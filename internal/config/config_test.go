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
  path: "/opt/oid-database.properties"
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
	if cfg.OIDMap.Path != "/opt/oid-database.properties" {
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
