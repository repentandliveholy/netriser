package updater

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// ManifestSignatureName is the detached signature published next to
// version.json: the base64 Ed25519 signature of the exact manifest bytes.
const ManifestSignatureName = "version.json.sig"

// builtinPublicKeys are the release-signing keys trusted by this build
// (base64, raw 32-byte Ed25519 public keys). Several keys allow rotation: a new
// key is added one release before the old one is retired.
var builtinPublicKeys = []string{
	releasePublicKey,
}

// ErrUnsigned reports a manifest without a valid signature from a trusted key.
var ErrUnsigned = errors.New("release manifest is not signed by a trusted key")

// ParsePublicKey decodes a base64 raw Ed25519 public key.
func ParsePublicKey(value string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, fmt.Errorf("invalid public key encoding: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length %d, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// TrustedKeys returns the built-in keys plus additional configured keys, for
// example the key of a self-hosted or corporate distribution mirror.
func TrustedKeys(extra []string) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for _, k := range append(append([]string{}, builtinPublicKeys...), extra...) {
		if strings.TrimSpace(k) == "" {
			continue
		}
		pub, err := ParsePublicKey(k)
		if err != nil {
			return nil, err
		}
		keys = append(keys, pub)
	}
	if len(keys) == 0 {
		return nil, errors.New("no trusted release keys configured")
	}
	return keys, nil
}

// VerifySignature checks a detached base64 signature of data against keys.
func VerifySignature(data, signature []byte, keys []ed25519.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signature)))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: malformed signature", ErrUnsigned)
	}
	for _, key := range keys {
		if ed25519.Verify(key, data, sig) {
			return nil
		}
	}
	return ErrUnsigned
}

// Sign returns the base64 detached signature used for release files.
func Sign(data []byte, key ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, data))
}
