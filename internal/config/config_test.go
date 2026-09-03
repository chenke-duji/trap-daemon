package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadDefaultsAndOverrides(t *testing.T) {
	content := `
snmp:
  listenAddr: "0.0.0.0:1162"
oidMap:
  path: "/opt/oid-database.db"
cepEngine:
  baseUrl: "http://127.0.0.1:8080"
forward:
  batchSize: 20
`
	cfg, err := Load(writeTempConfig(t, content))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SNMP.ListenAddr != "0.0.0.0:1162" {
		t.Fatalf("listenAddr not applied: %s", cfg.SNMP.ListenAddr)
	}
	if cfg.SNMP.Protocol != "v1v2c" {
		t.Fatalf("expected default protocol v1v2c, got %s", cfg.SNMP.Protocol)
	}
	if cfg.OIDMap.Path != "/opt/oid-database.db" {
		t.Fatalf("oidMap path not applied: %s", cfg.OIDMap.Path)
	}
	if cfg.CEPEngine.BaseURL != "http://127.0.0.1:8080" {
		t.Fatalf("baseUrl not applied")
	}
	// default batch path from defaults
	if cfg.CEPEngine.BatchPath != "/api/v1/events/batch" {
		t.Fatalf("expected default batch path, got %s", cfg.CEPEngine.BatchPath)
	}
	// forward override
	if cfg.Forward.BatchSize != 20 {
		t.Fatalf("expected forward.batchSize 20, got %d", cfg.Forward.BatchSize)
	}
	// default policy
	if cfg.Forward.QueueFullPolicy != "drop" {
		t.Fatalf("expected default queueFullPolicy drop, got %s", cfg.Forward.QueueFullPolicy)
	}
}

func TestLoadRequiredFields(t *testing.T) {
	// Missing oidMap.path and cepEngine.baseUrl must fail.
	cfg := defaultConfig()
	cfg.OIDMap.Path = ""
	cfg.CEPEngine.BaseURL = ""
	if err := validate(cfg); err == nil {
		t.Fatal("expected validation error for missing required fields")
	}
}

func TestEnvOverride(t *testing.T) {
	t.Setenv("TRAPD_SNMP_LISTENADDR", "0.0.0.0:9999")
	t.Setenv("TRAPD_CEPENGINE_BASEURL", "http://example:8080")
	t.Setenv("TRAPD_METRICS_ENABLED", "true")

	cfg := defaultConfig()
	applyEnv(cfg)

	if cfg.SNMP.ListenAddr != "0.0.0.0:9999" {
		t.Fatalf("env listenAddr not applied: %s", cfg.SNMP.ListenAddr)
	}
	if cfg.CEPEngine.BaseURL != "http://example:8080" {
		t.Fatalf("env baseUrl not applied")
	}
	if !cfg.Metrics.Enabled {
		t.Fatal("env metrics enabled not applied")
	}
}

func TestInvalidProtocol(t *testing.T) {
	cfg := defaultConfig()
	cfg.SNMP.Protocol = "snmpx"
	cfg.OIDMap.Path = "/x"
	cfg.CEPEngine.BaseURL = "http://x"
	if err := validate(cfg); err == nil {
		t.Fatal("expected error for unsupported protocol")
	}
}

func TestProtocolBothAccepted(t *testing.T) {
	cfg := defaultConfig()
	cfg.SNMP.Protocol = "both"
	cfg.SNMP.V3.User = "trapUser"
	cfg.SNMP.V3.AuthProtocol = "SHA256"
	cfg.SNMP.V3.AuthPassphrase = "passphrase123"
	cfg.SNMP.V3.PrivProtocol = "AES256"
	cfg.SNMP.V3.PrivPassphrase = "passphrase456"
	cfg.OIDMap.Path = "/x"
	cfg.CEPEngine.BaseURL = "http://x"
	if err := validate(cfg); err != nil {
		t.Fatalf("expected both protocol to be valid: %v", err)
	}
}

func TestV3ValidationMissingUser(t *testing.T) {
	cfg := defaultConfig()
	cfg.SNMP.Protocol = "v3"
	cfg.SNMP.V3.AuthProtocol = "SHA"
	cfg.SNMP.V3.AuthPassphrase = "passphrase"
	cfg.OIDMap.Path = "/x"
	cfg.CEPEngine.BaseURL = "http://x"
	if err := validate(cfg); err == nil {
		t.Fatal("expected error for missing v3 user")
	}
}

func TestV3ValidationPrivWithoutAuth(t *testing.T) {
	cfg := defaultConfig()
	cfg.SNMP.Protocol = "v3"
	cfg.SNMP.V3.User = "trapUser"
	cfg.SNMP.V3.AuthProtocol = "none"
	cfg.SNMP.V3.PrivProtocol = "AES"
	cfg.SNMP.V3.PrivPassphrase = "passphrase"
	cfg.OIDMap.Path = "/x"
	cfg.CEPEngine.BaseURL = "http://x"
	if err := validate(cfg); err == nil {
		t.Fatal("expected error for priv without auth")
	}
}

func TestV3ValidationShortPassphrase(t *testing.T) {
	cfg := defaultConfig()
	cfg.SNMP.Protocol = "v3"
	cfg.SNMP.V3.User = "trapUser"
	cfg.SNMP.V3.AuthProtocol = "SHA"
	cfg.SNMP.V3.AuthPassphrase = "short"
	cfg.OIDMap.Path = "/x"
	cfg.CEPEngine.BaseURL = "http://x"
	if err := validate(cfg); err == nil {
		t.Fatal("expected error for passphrase < 8 chars")
	}
}

func TestV3ValidationNoAuthNoPriv(t *testing.T) {
	cfg := defaultConfig()
	cfg.SNMP.Protocol = "v3"
	cfg.SNMP.V3.User = "trapUser"
	cfg.SNMP.V3.AuthProtocol = "none"
	cfg.SNMP.V3.PrivProtocol = "none"
	cfg.OIDMap.Path = "/x"
	cfg.CEPEngine.BaseURL = "http://x"
	if err := validate(cfg); err != nil {
		t.Fatalf("expected NoAuthNoPriv to be valid: %v", err)
	}
}

func TestV3ValidationAuthNoPriv(t *testing.T) {
	cfg := defaultConfig()
	cfg.SNMP.Protocol = "v3"
	cfg.SNMP.V3.User = "trapUser"
	cfg.SNMP.V3.AuthProtocol = "MD5"
	cfg.SNMP.V3.AuthPassphrase = "passphrase"
	cfg.SNMP.V3.PrivProtocol = "none"
	cfg.OIDMap.Path = "/x"
	cfg.CEPEngine.BaseURL = "http://x"
	if err := validate(cfg); err != nil {
		t.Fatalf("expected AuthNoPriv to be valid: %v", err)
	}
}

func TestV3EnvOverride(t *testing.T) {
	t.Setenv("TRAPD_SNMP_V3_ENABLED", "true")
	t.Setenv("TRAPD_SNMP_V3_USER", "envUser")
	t.Setenv("TRAPD_SNMP_V3_AUTHPROTOCOL", "SHA512")
	t.Setenv("TRAPD_SNMP_V3_AUTHPASSPHRASE", "envPass123")

	cfg := defaultConfig()
	applyEnv(cfg)

	if !cfg.SNMP.V3.Enabled {
		t.Fatal("env v3 enabled not applied")
	}
	if cfg.SNMP.V3.User != "envUser" {
		t.Fatalf("env v3 user not applied: %s", cfg.SNMP.V3.User)
	}
	if cfg.SNMP.V3.AuthProtocol != "SHA512" {
		t.Fatalf("env v3 authProtocol not applied: %s", cfg.SNMP.V3.AuthProtocol)
	}
	if cfg.SNMP.V3.AuthPassphrase != "envPass123" {
		t.Fatalf("env v3 authPassphrase not applied")
	}
}
