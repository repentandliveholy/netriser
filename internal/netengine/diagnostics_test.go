package netengine

import (
	"strings"
	"testing"
)

func TestSanitizeDiagnostics(t *testing.T) {
	raw := `
Interface: utun3
PrivateKey = aW5pdGlhbGl6ZW1lc2h3YXRjaGRvZ3Rlc3RrZXkxMjM0NTY3OA=
PresharedKey = dGVzdHByZXNoYXJlZGtleWZvcm1lc2h3YXRjaGRvZzEyMzQ=
AuthToken: tskey-auth-k1234567890abcdef-unlimited
Authorization: Bearer ya29.a0AfH6SMCxyz123456789
password = supersecretpassword
api_key: "abc12345secret"
NormalConfig: mtu=1420
`
	sanitized := SanitizeDiagnostics(raw)

	if strings.Contains(sanitized, "aW5pdGlhbGl6ZW1lc2h3YXRjaGRvZ3Rlc3RrZXkxMjM0NTY3OA=") {
		t.Errorf("PrivateKey was not sanitized: %s", sanitized)
	}
	if strings.Contains(sanitized, "dGVzdHByZXNoYXJlZGtleWZvcm1lc2h3YXRjaGRvZzEyMzQ=") {
		t.Errorf("PresharedKey was not sanitized: %s", sanitized)
	}
	if strings.Contains(sanitized, "tskey-auth-k1234567890abcdef-unlimited") {
		t.Errorf("tskey was not sanitized: %s", sanitized)
	}
	if strings.Contains(sanitized, "supersecretpassword") {
		t.Errorf("password was not sanitized: %s", sanitized)
	}
	if !strings.Contains(sanitized, "PrivateKey = [REDACTED]") {
		t.Errorf("expected redacted PrivateKey placeholder: %s", sanitized)
	}
	if !strings.Contains(sanitized, "NormalConfig: mtu=1420") {
		t.Errorf("normal config altered: %s", sanitized)
	}
}

func TestTruncateDiagnostics(t *testing.T) {
	longStr := strings.Repeat("A", 1000)
	truncated := TruncateDiagnostics(longStr, 500)

	if len(truncated) <= 500 {
		t.Errorf("expected truncated string with notice, got length %d", len(truncated))
	}
	if !strings.Contains(truncated, "[... DIAGNOSTIC OUTPUT TRUNCATED") {
		t.Errorf("missing truncation notice: %s", truncated)
	}
	if !strings.HasPrefix(truncated, strings.Repeat("A", 500)) {
		t.Errorf("prefix doesn't match original")
	}

	shortStr := "hello"
	if TruncateDiagnostics(shortStr, 500) != "hello" {
		t.Errorf("short string should not be truncated")
	}
}
