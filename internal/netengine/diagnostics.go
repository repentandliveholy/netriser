package netengine

import (
	"regexp"
)

const MaxDiagnosticBytes = 512 * 1024 // 512 KB

var (
	// Matches WireGuard / NetBird private or preshared base64 keys
	reWgKey = regexp.MustCompile(`(?i)(PrivateKey|PresharedKey)\s*=\s*[A-Za-z0-9+/=]{40,48}`)
	// Matches Tailscale auth keys
	reTsKey = regexp.MustCompile(`tskey-[a-zA-Z0-9_\-]+`)
	// Matches Bearer tokens
	reBearer = regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*`)
	// Matches token/secret/password key-value pairs
	reSecrets = regexp.MustCompile(`(?i)(password|passwd|secret|token|api_key|auth_key)\s*[:=]\s*["']?([^\s"']+)["']?`)
)

// SanitizeDiagnostics redacts credentials, private keys, and tokens from diagnostic dumps.
func SanitizeDiagnostics(text string) string {
	out := reWgKey.ReplaceAllString(text, "$1 = [REDACTED]")
	out = reTsKey.ReplaceAllString(out, "tskey-[REDACTED]")
	out = reBearer.ReplaceAllString(out, "Bearer [REDACTED]")
	out = reSecrets.ReplaceAllString(out, "$1: [REDACTED]")
	return out
}

// TruncateDiagnostics caps diagnostic output to prevent runaway memory or dump sizes.
func TruncateDiagnostics(text string, maxBytes int) string {
	if maxBytes <= 0 {
		maxBytes = MaxDiagnosticBytes
	}
	if len(text) > maxBytes {
		return text[:maxBytes] + "\n\n[... DIAGNOSTIC OUTPUT TRUNCATED: exceeded size limit ...]\n"
	}
	return text
}
