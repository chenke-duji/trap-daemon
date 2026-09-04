package main

import (
	"testing"

	"trap-daemon/internal/config"
)

// TestParseV3AuthProtocolConsistency verifies that every auth protocol accepted
// by config validation is correctly parsed by parseV3AuthProtocol, and that
// the parse result is never a security downgrade (NoAuth) for a valid non-none
// protocol. This guards against drift between the validation map and the parse
// switch when new protocols are added.
func TestParseV3AuthProtocolConsistency(t *testing.T) {
	validAuth := []string{"none", "md5", "sha", "sha224", "sha256", "sha384", "sha512"}
	for _, p := range validAuth {
		v3 := config.V3Config{
			User:         "u",
			AuthProtocol: p,
			PrivProtocol: "none",
		}
		if p != "none" {
			v3.AuthPassphrase = "passphrase123"
		}
		if err := config.ValidateV3(&v3); err != nil {
			t.Fatalf("validation rejected valid authProtocol %q: %v", p, err)
		}
		got := parseV3AuthProtocol(p)
		// For non-none protocols, ensure we don't get NoAuth (security downgrade)
		if p != "none" {
			if got == parseV3AuthProtocol("none") {
				t.Errorf("parseV3AuthProtocol(%q) returned NoAuth — security downgrade!", p)
			}
		}
	}
}

// TestParseV3PrivProtocolConsistency verifies that every priv protocol accepted
// by config validation is correctly parsed by parseV3PrivProtocol, and that
// the parse result is never a security downgrade (NoPriv) for a valid non-none
// protocol.
func TestParseV3PrivProtocolConsistency(t *testing.T) {
	validPriv := []string{"none", "des", "aes", "aes192", "aes256", "aes192c", "aes256c"}
	for _, p := range validPriv {
		v3 := config.V3Config{
			User:           "u",
			AuthProtocol:   "sha",
			AuthPassphrase: "passphrase123",
			PrivProtocol:   p,
		}
		if p != "none" {
			v3.PrivPassphrase = "passphrase456"
		}
		if err := config.ValidateV3(&v3); err != nil {
			t.Fatalf("validation rejected valid privProtocol %q: %v", p, err)
		}
		got := parseV3PrivProtocol(p)
		// For non-none protocols, ensure we don't get NoPriv (security downgrade)
		if p != "none" {
			if got == parseV3PrivProtocol("none") {
				t.Errorf("parseV3PrivProtocol(%q) returned NoPriv — security downgrade!", p)
			}
		}
	}
}

func TestV3SecurityLevel(t *testing.T) {
	cases := []struct {
		auth string
		priv string
		want string
	}{
		{"none", "none", "NoAuthNoPriv"},
		{"MD5", "none", "AuthNoPriv"},
		{"SHA256", "AES256", "AuthPriv"},
		{"", "", "NoAuthNoPriv"},
	}
	for _, c := range cases {
		v3 := config.V3Config{AuthProtocol: c.auth, PrivProtocol: c.priv}
		got := v3SecurityLevel(&v3)
		if got != c.want {
			t.Errorf("v3SecurityLevel(auth=%q, priv=%q) = %q, want %q", c.auth, c.priv, got, c.want)
		}
	}
}
