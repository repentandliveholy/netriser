package updater

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestUpdaterCheck(t *testing.T) {
	manifest := Manifest{
		Version:   "1.1.0",
		Commit:    "abcdef12",
		BuildTime: "2026-11-10T12:00:00Z",
		Files: map[string]FileEntry{
			"linux/amd64": {
				Filename: "mesh-watchdog-linux-amd64",
				SHA256:   "aaaa",
				URL:      "bin/mesh-watchdog-linux-amd64",
			},
			"darwin/arm64": {
				Filename: "mesh-watchdog-darwin-arm64",
				SHA256:   "bbbb",
				URL:      "/bin/mesh-watchdog-darwin-arm64",
			},
		},
	}

	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}

	pub, priv := testKey(t)
	u := New("https://mesh-watchdog.test/")
	u.SetHTTPClient(manifestServer(manifestBytes, []byte(Sign(manifestBytes, priv))))
	u.setKeysForTest(pub)
	u.SetTargetPlatform("darwin", "arm64")

	// 1. Check with older version -> update available
	info, err := u.Check(context.Background(), "1.0.0", "oldcommit")
	if err != nil {
		t.Fatalf("unexpected check error: %v", err)
	}
	if !info.UpdateAvailable {
		t.Errorf("expected update to be available")
	}
	if info.LatestVersion != "1.1.0" {
		t.Errorf("expected latest version 1.1.0, got %s", info.LatestVersion)
	}
	if info.DownloadURL != "https://mesh-watchdog.test/bin/mesh-watchdog-darwin-arm64" {
		t.Errorf("unexpected download URL: %s", info.DownloadURL)
	}

	// 2. Check with identical version & commit -> no update
	info2, err := u.Check(context.Background(), "1.1.0", "abcdef12")
	if err != nil {
		t.Fatalf("unexpected check error: %v", err)
	}
	if info2.UpdateAvailable {
		t.Errorf("expected update to not be available for identical version")
	}

	// 3. Check for unsupported platform
	u.SetTargetPlatform("freebsd", "riscv64")
	_, err = u.Check(context.Background(), "1.0.0", "oldcommit")
	if err == nil {
		t.Fatalf("expected error for unsupported platform")
	}
}

func TestUpdaterApplySuccessAndSHA256Mismatch(t *testing.T) {
	newBinaryContent := []byte("#!/bin/sh\necho updated-version\n")
	hasher := sha256.New()
	hasher.Write(newBinaryContent)
	validHash := hex.EncodeToString(hasher.Sum(nil))

	fakeClient := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == "/bin/mesh-watchdog-test" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(newBinaryContent)),
					Header:     make(http.Header),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(bytes.NewReader([]byte("not found"))),
				Header:     make(http.Header),
			}, nil
		}),
	}

	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "mesh-watchdog")
	if err := os.WriteFile(targetPath, []byte("#!/bin/sh\necho old-version\n"), 0755); err != nil {
		t.Fatal(err)
	}

	u := New("https://mesh-watchdog.test/")
	u.SetHTTPClient(fakeClient)

	// 1. Test SHA256 mismatch failure
	badInfo := &UpdateInfo{
		CurrentVersion: "1.0.0",
		LatestVersion:  "1.1.0",
		DownloadURL:    "https://mesh-watchdog.test/bin/mesh-watchdog-test",
		TargetFile: FileEntry{
			Filename: "mesh-watchdog-test",
			SHA256:   "0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	err := u.Apply(context.Background(), targetPath, badInfo)
	if err == nil {
		t.Fatalf("expected checksum mismatch error, got nil")
	}

	// Verify original file unchanged
	oldContent, _ := os.ReadFile(targetPath)
	if string(oldContent) != "#!/bin/sh\necho old-version\n" {
		t.Fatalf("original file was unexpectedly modified on checksum failure")
	}

	// 2. Test successful update with correct SHA256
	goodInfo := &UpdateInfo{
		CurrentVersion: "1.0.0",
		LatestVersion:  "1.1.0",
		DownloadURL:    "https://mesh-watchdog.test/bin/mesh-watchdog-test",
		TargetFile: FileEntry{
			Filename: "mesh-watchdog-test",
			SHA256:   validHash,
		},
	}
	err = u.Apply(context.Background(), targetPath, goodInfo)
	if err != nil {
		t.Fatalf("expected update to succeed, got: %v", err)
	}

	// Verify target file was replaced with new binary content
	updatedContent, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(updatedContent) != string(newBinaryContent) {
		t.Fatalf("expected updated binary content, got %s", string(updatedContent))
	}
}

func TestUpdaterRejectsMissingOrMalformedChecksumBeforeDownload(t *testing.T) {
	u := New("https://example.test")
	u.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatal("download attempted without checksum")
		return nil, nil
	})})
	for _, hash := range []string{"", "abc", "zzzz", strings.Repeat("z", 64)} {
		path := filepath.Join(t.TempDir(), "binary")
		os.WriteFile(path, []byte("original"), 0755)
		err := u.Apply(context.Background(), path, &UpdateInfo{TargetFile: FileEntry{SHA256: hash}})
		if err == nil {
			t.Fatalf("accepted invalid checksum %q", hash)
		}
		content, _ := os.ReadFile(path)
		if string(content) != "original" {
			t.Fatal("original replaced")
		}
	}
}

func TestVersionComparisonDoesNotDowngradeNumberedReleases(t *testing.T) {
	for _, tc := range []struct {
		current, latest string
		want            bool
	}{
		{"1.1.0", "1.0.0", false}, {"1.9.0", "1.10.0", true}, {"2.0.0", "1.99.99", false},
		{"v1.1.0", "1.1.0", false}, {"dev", "1.1.0", true}, {"1.1.0", "broken", false},
	} {
		if got := isNewerVersion(tc.current, "abc", tc.latest, "def"); got != tc.want {
			t.Errorf("%s -> %s = %t", tc.current, tc.latest, got)
		}
	}
}

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// manifestServer serves version.json and, when sig is not nil, its signature.
func manifestServer(manifest, sig []byte) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, status := []byte("not found"), http.StatusNotFound
		switch req.URL.Path {
		case "/version.json":
			body, status = manifest, http.StatusOK
		case "/version.json.sig":
			if sig != nil {
				body, status = sig, http.StatusOK
			}
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
	})}
}

func signedTestManifest(t *testing.T, version string) []byte {
	t.Helper()
	data, err := json.Marshal(Manifest{Version: version, Commit: "c0ffee", Files: map[string]FileEntry{
		"linux/amd64": {Filename: "netriser-linux-amd64", SHA256: strings.Repeat("a", 64)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestUpdaterRejectsUnsignedForgedAndTamperedManifests(t *testing.T) {
	pub, priv := testKey(t)
	_, attacker := testKey(t)
	manifest := signedTestManifest(t, "9.0.0")
	tampered := bytes.Replace(manifest, []byte("9.0.0"), []byte("9.0.1"), 1)
	for name, client := range map[string]*http.Client{
		"missing signature":  manifestServer(manifest, nil),
		"garbage signature":  manifestServer(manifest, []byte("not base64!")),
		"attacker signature": manifestServer(manifest, []byte(Sign(manifest, attacker))),
		"tampered manifest":  manifestServer(tampered, []byte(Sign(manifest, priv))),
	} {
		u := New("https://dist.test")
		u.SetHTTPClient(client)
		u.setKeysForTest(pub)
		u.SetTargetPlatform("linux", "amd64")
		if _, err := u.Check(context.Background(), "1.0.0", "x"); err == nil || !strings.Contains(err.Error(), "not signed") {
			t.Errorf("%s: accepted or wrong error: %v", name, err)
		}
	}
}

func TestUpdaterAcceptsConfiguredMirrorKey(t *testing.T) {
	pub, priv := testKey(t)
	manifest := signedTestManifest(t, "9.0.0")
	u := New("https://mirror.test")
	u.SetHTTPClient(manifestServer(manifest, []byte(Sign(manifest, priv))))
	u.SetTargetPlatform("linux", "amd64")
	if _, err := u.Check(context.Background(), "1.0.0", "x"); err == nil {
		t.Fatal("mirror key trusted before configuration")
	}
	if err := u.SetTrustedKeys([]string{base64.StdEncoding.EncodeToString(pub)}); err != nil {
		t.Fatal(err)
	}
	info, err := u.Check(context.Background(), "1.0.0", "x")
	if err != nil || !info.UpdateAvailable {
		t.Fatalf("configured mirror key rejected: %v", err)
	}
	if err := u.SetTrustedKeys([]string{"short"}); err == nil {
		t.Fatal("invalid key accepted")
	}
}

func TestUpdaterNeverDowngrades(t *testing.T) {
	pub, priv := testKey(t)
	manifest := signedTestManifest(t, "1.2.0")
	u := New("https://dist.test")
	u.SetHTTPClient(manifestServer(manifest, []byte(Sign(manifest, priv))))
	u.setKeysForTest(pub)
	u.SetTargetPlatform("linux", "amd64")
	info, err := u.Check(context.Background(), "1.3.0", "x")
	if err != nil {
		t.Fatal(err)
	}
	if info.UpdateAvailable || !info.Downgrade {
		t.Fatalf("old release not flagged as downgrade: %+v", info)
	}
	path := filepath.Join(t.TempDir(), "binary")
	os.WriteFile(path, []byte("current"), 0755)
	if err := u.Apply(context.Background(), path, info); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("downgrade applied: %v", err)
	}
}

func TestBuiltinReleaseKeyIsValid(t *testing.T) {
	keys, err := TrustedKeys(nil)
	if err != nil || len(keys) == 0 {
		t.Fatalf("built-in release key invalid: %v", err)
	}
}
