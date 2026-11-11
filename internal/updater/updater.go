package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Manifest represents the published version.json metadata file.
type Manifest struct {
	Version      string               `json:"version"`
	Commit       string               `json:"commit"`
	BuildTime    string               `json:"build_time"`
	MinVersion   string               `json:"min_version,omitempty"`
	ReleaseNotes string               `json:"release_notes,omitempty"`
	Files        map[string]FileEntry `json:"files"`
}

// FileEntry describes an executable artifact for a specific OS/Arch.
type FileEntry struct {
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	URL      string `json:"url"`
}

// UpdateInfo holds details about an update evaluation.
type UpdateInfo struct {
	CurrentVersion  string    `json:"current_version"`
	CurrentCommit   string    `json:"current_commit"`
	LatestVersion   string    `json:"latest_version"`
	LatestCommit    string    `json:"latest_commit"`
	UpdateAvailable bool      `json:"update_available"`
	PlatformKey     string    `json:"platform_key"`
	TargetFile      FileEntry `json:"target_file"`
	DownloadURL     string    `json:"download_url"`
}

// Updater handles checking and applying self-updates.
type Updater struct {
	baseURL    string
	httpClient *http.Client
	targetOS   string
	targetArch string
}

// New creates a new Updater instance with the specified base distribution URL.
func New(baseURL string) *Updater {
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	return &Updater{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		targetOS:   runtime.GOOS,
		targetArch: runtime.GOARCH,
	}
}

// SetTargetPlatform overrides target OS/Arch (primarily for testing).
func (u *Updater) SetTargetPlatform(osName, archName string) {
	u.targetOS = osName
	u.targetArch = archName
}

// SetHTTPClient sets custom HTTP client (for mock servers in tests).
func (u *Updater) SetHTTPClient(client *http.Client) {
	u.httpClient = client
}

// Check queries the update manifest and determines whether an update is available.
func (u *Updater) Check(ctx context.Context, currentVersion, currentCommit string) (*UpdateInfo, error) {
	manifestURL := u.resolveURL("version.json")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to construct manifest request: %w", err)
	}
	req.Header.Set("User-Agent", fmt.Sprintf("netriser/%s (%s/%s)", currentVersion, u.targetOS, u.targetArch))

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch update manifest from %s: %w", manifestURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update server returned HTTP %d for %s", resp.StatusCode, manifestURL)
	}

	var m Manifest
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, fmt.Errorf("failed to parse update manifest JSON: %w", err)
	}

	platformKey := fmt.Sprintf("%s/%s", u.targetOS, u.targetArch)
	fileEntry, ok := m.Files[platformKey]
	if !ok {
		return nil, fmt.Errorf("platform %s not supported in release manifest v%s", platformKey, m.Version)
	}

	downloadURL := u.resolveURL(fileEntry.URL)
	if fileEntry.URL == "" {
		downloadURL = u.resolveURL(fmt.Sprintf("bin/%s", fileEntry.Filename))
	}

	updateAvailable := isNewerVersion(currentVersion, currentCommit, m.Version, m.Commit)

	return &UpdateInfo{
		CurrentVersion:  currentVersion,
		CurrentCommit:   currentCommit,
		LatestVersion:   m.Version,
		LatestCommit:    m.Commit,
		UpdateAvailable: updateAvailable,
		PlatformKey:     platformKey,
		TargetFile:      fileEntry,
		DownloadURL:     downloadURL,
	}, nil
}

// Apply downloads the new binary, validates its SHA256 checksum, and safely replaces the current executable.
func (u *Updater) Apply(ctx context.Context, targetExecPath string, info *UpdateInfo) error {
	if info == nil {
		return fmt.Errorf("missing update metadata")
	}
	expectedHash := strings.ToLower(strings.TrimSpace(info.TargetFile.SHA256))
	hashBytes, err := hex.DecodeString(expectedHash)
	if err != nil || len(hashBytes) != sha256.Size {
		return fmt.Errorf("release must provide a valid SHA256 checksum")
	}
	if targetExecPath == "" {
		var err error
		targetExecPath, err = CurrentExecutablePath()
		if err != nil {
			return fmt.Errorf("failed to determine executable path: %w", err)
		}
	}

	targetDir := filepath.Dir(targetExecPath)
	tempFile, err := os.CreateTemp(targetDir, fmt.Sprintf(".netriser-update-%d-*", time.Now().UnixNano()))
	if err != nil {
		return fmt.Errorf("failed to create temporary update file in %s: %w", targetDir, err)
	}
	tempPath := tempFile.Name()
	defer func() {
		// Cleanup temp file if left behind
		if _, err := os.Stat(tempPath); err == nil {
			_ = os.Remove(tempPath)
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, info.DownloadURL, nil)
	if err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("failed to create download request: %w", err)
	}
	req.Header.Set("User-Agent", fmt.Sprintf("netriser/%s (%s/%s)", info.CurrentVersion, u.targetOS, u.targetArch))

	resp, err := u.httpClient.Do(req)
	if err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("failed to download new binary from %s: %w", info.DownloadURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_ = tempFile.Close()
		return fmt.Errorf("download server returned HTTP %d for %s", resp.StatusCode, info.DownloadURL)
	}

	hasher := sha256.New()
	writer := io.MultiWriter(tempFile, hasher)

	if _, err := io.Copy(writer, resp.Body); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("failed while saving downloaded binary: %w", err)
	}
	if err := tempFile.Sync(); err != nil {
		tempFile.Close()
		return fmt.Errorf("sync temporary binary: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close temporary binary: %w", err)
	}

	calculatedHash := hex.EncodeToString(hasher.Sum(nil))
	if calculatedHash != expectedHash {
		return fmt.Errorf("sha256 checksum mismatch: expected %s, got %s", expectedHash, calculatedHash)
	}

	return replaceExecutable(targetExecPath, tempPath)
}

// CurrentExecutablePath returns the resolved absolute path of the currently executing binary.
func CurrentExecutablePath() (string, error) {
	execPath, err := os.Executable()
	if err != nil {
		return "", err
	}
	evalPath, err := filepath.EvalSymlinks(execPath)
	if err != nil {
		return filepath.Abs(execPath)
	}
	return filepath.Abs(evalPath)
}

func (u *Updater) resolveURL(ref string) string {
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}
	parsedBase, err := url.Parse(u.baseURL)
	if err != nil {
		return u.baseURL + ref
	}
	parsedRef, err := url.Parse(ref)
	if err != nil {
		return u.baseURL + ref
	}
	return parsedBase.ResolveReference(parsedRef).String()
}

func isNewerVersion(currVer, currCommit, latestVer, latestCommit string) bool {
	if currVer != latestVer {
		current, cOK := numericVersion(currVer)
		latest, lOK := numericVersion(latestVer)
		if cOK && lOK {
			for i := range current {
				if latest[i] != current[i] {
					return latest[i] > current[i]
				}
			}
			return false
		}
		// Development builds can move to a numbered release. Unknown release
		// formats must not trigger an automatic downgrade or an endless update loop.
		return (currVer == "dev" || currVer == "unknown") && lOK
	}
	return currCommit != "" && latestCommit != "" && currCommit != "unknown" && latestCommit != "unknown" &&
		!strings.HasPrefix(currCommit, latestCommit) && !strings.HasPrefix(latestCommit, currCommit)
}

func numericVersion(value string) ([3]uint64, bool) {
	var result [3]uint64
	parts := strings.Split(strings.TrimPrefix(value, "v"), ".")
	if len(parts) != 3 {
		return result, false
	}
	for i, part := range parts {
		n, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return result, false
		}
		result[i] = n
	}
	return result, true
}
