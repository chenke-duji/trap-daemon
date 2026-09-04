// Package config loads and validates trap-daemon configuration from a YAML
// file with optional environment-variable overrides.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"trap-daemon/internal/forward"
)

// SNMPConfig holds the UDP trap listener settings.
type SNMPConfig struct {
	ListenAddr  string   `yaml:"listenAddr"`  // e.g. "0.0.0.0:162"
	Protocol    string   `yaml:"protocol"`    // "v1v2c" (default), "v3", or "both"
	Communities []string `yaml:"communities"` // optional allowlist for v1/v2c; empty accepts all (with warning)
	V3          V3Config `yaml:"v3"`          // SNMPv3 USM credentials
}

// V3Config holds SNMPv3 USM (User Security Model) credentials.
// Env overrides: TRAPD_SNMP_V3_ENABLED, TRAPD_SNMP_V3_USER, etc.
type V3Config struct {
	Enabled        bool   `yaml:"enabled"`
	User           string `yaml:"user"`
	AuthProtocol   string `yaml:"authProtocol"`   // none|MD5|SHA|SHA224|SHA256|SHA384|SHA512
	AuthPassphrase string `yaml:"authPassphrase"` // required when authProtocol != none
	PrivProtocol   string `yaml:"privProtocol"`   // none|DES|AES|AES192|AES256|AES192C|AES256C
	PrivPassphrase string `yaml:"privPassphrase"` // required when privProtocol != none
}

// OIDMapConfig points at the mib-parser generated OID database (a config item,
// never bundled with this project).
type OIDMapConfig struct {
	Path           string `yaml:"path"`
	LoadFailPolicy string `yaml:"loadFailPolicy"` // "exit" (default) | "warn"
}

// CEPEngineConfig describes the downstream cep-engine REST endpoint.
type CEPEngineConfig struct {
	BaseURL    string `yaml:"baseUrl"`
	BatchPath  string `yaml:"batchPath"`
	SinglePath string `yaml:"singlePath"`
	AuthToken  string `yaml:"authToken"`
	Timeout    int    `yaml:"timeoutMs"`
	RetryMax   int    `yaml:"retryMax"`
	RetryBase  int    `yaml:"retryBaseMs"`
}

// LoggingConfig controls log level and output file rotation settings.
type LoggingConfig struct {
	Level      string `yaml:"level"` // debug | info | warn | error
	File       string `yaml:"file"`  // empty -> stdout
	MaxSizeMB  int    `yaml:"maxSizeMB"`
	MaxBackups int    `yaml:"maxBackups"`
}

// MetricsConfig controls the Prometheus self-monitoring endpoint.
type MetricsConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listenAddr"`
	Path       string `yaml:"path"`
}

// Config is the root configuration.
type Config struct {
	SNMP      SNMPConfig            `yaml:"snmp"`
	OIDMap    OIDMapConfig          `yaml:"oidMap"`
	CEPEngine CEPEngineConfig       `yaml:"cepEngine"`
	Forward   forward.ForwardConfig `yaml:"forward"`
	Logging   LoggingConfig         `yaml:"logging"`
	Metrics   MetricsConfig         `yaml:"metrics"`
}

// Load reads a YAML config file and applies defaults and env overrides.
func Load(path string) (*Config, error) {
	cfg := defaultConfig()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("config: read %s: %w", path, err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("config: parse %s: %w", path, err)
		}
	}
	applyEnv(cfg)
	if err := validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// defaultConfig returns a Config populated with sensible defaults.
func defaultConfig() *Config {
	return &Config{
		SNMP: SNMPConfig{
			ListenAddr: "0.0.0.0:162",
			Protocol:   "v1v2c",
		},
		OIDMap: OIDMapConfig{LoadFailPolicy: "exit"},
		CEPEngine: CEPEngineConfig{
			BatchPath:  "/api/v1/events/batch",
			SinglePath: "/api/v1/events",
			Timeout:    5000,
			RetryMax:   3,
			RetryBase:  200,
		},
		Forward: forward.DefaultForwardConfig,
		Logging: LoggingConfig{
			Level:      "info",
			MaxSizeMB:  100,
			MaxBackups: 5,
		},
		Metrics: MetricsConfig{
			ListenAddr: "127.0.0.1:9091",
			Path:       "/metrics",
		},
	}
}

// applyEnv applies simple TRAPD_* environment overrides. Format:
//
//	TRAPD_SNMP_LISTENADDR, TRAPD_SNMP_COMMUNITIES, TRAPD_CEPENGINE_BASEURL,
//	TRAPD_OIDMAP_PATH, TRAPD_LOGGING_LEVEL, TRAPD_METRICS_ENABLED, ...
func applyEnv(cfg *Config) {
	setStr := func(env string, dst *string) {
		if v := os.Getenv(env); v != "" {
			*dst = v
		}
	}
	setStr("TRAPD_SNMP_LISTENADDR", &cfg.SNMP.ListenAddr)
	setStr("TRAPD_SNMP_PROTOCOL", &cfg.SNMP.Protocol)
	// Communities: support comma-separated list or backward-compatible single value.
	if v := os.Getenv("TRAPD_SNMP_COMMUNITIES"); v != "" {
		cfg.SNMP.Communities = splitCommaList(v)
	}
	if v := os.Getenv("TRAPD_SNMP_COMMUNITY"); v != "" {
		if len(cfg.SNMP.Communities) == 0 {
			cfg.SNMP.Communities = []string{v}
		}
	}
	setStr("TRAPD_OIDMAP_PATH", &cfg.OIDMap.Path)
	setStr("TRAPD_OIDMAP_LOADFAILPOLICY", &cfg.OIDMap.LoadFailPolicy)
	setStr("TRAPD_CEPENGINE_BASEURL", &cfg.CEPEngine.BaseURL)
	setStr("TRAPD_CEPENGINE_AUTHTOKEN", &cfg.CEPEngine.AuthToken)
	setStr("TRAPD_LOGGING_LEVEL", &cfg.Logging.Level)
	setStr("TRAPD_LOGGING_FILE", &cfg.Logging.File)
	setStr("TRAPD_METRICS_LISTENADDR", &cfg.Metrics.ListenAddr)
	setStr("TRAPD_METRICS_PATH", &cfg.Metrics.Path)
	if v := os.Getenv("TRAPD_METRICS_ENABLED"); v != "" {
		cfg.Metrics.Enabled = strings.EqualFold(v, "true") || v == "1"
	}
	// SNMPv3 credential overrides.
	setStr("TRAPD_SNMP_V3_USER", &cfg.SNMP.V3.User)
	setStr("TRAPD_SNMP_V3_AUTHPROTOCOL", &cfg.SNMP.V3.AuthProtocol)
	setStr("TRAPD_SNMP_V3_AUTHPASSPHRASE", &cfg.SNMP.V3.AuthPassphrase)
	setStr("TRAPD_SNMP_V3_PRIVPROTOCOL", &cfg.SNMP.V3.PrivProtocol)
	setStr("TRAPD_SNMP_V3_PRIVPASSPHRASE", &cfg.SNMP.V3.PrivPassphrase)
	if v := os.Getenv("TRAPD_SNMP_V3_ENABLED"); v != "" {
		cfg.SNMP.V3.Enabled = strings.EqualFold(v, "true") || v == "1"
	}
}

// splitCommaList splits a comma-separated string, trimming whitespace and
// dropping empty entries.
func splitCommaList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// validate checks required settings and normalizes values.
func validate(cfg *Config) error {
	if cfg.SNMP.ListenAddr == "" {
		return fmt.Errorf("config: snmp.listenAddr is required")
	}
	if cfg.SNMP.Protocol == "" {
		cfg.SNMP.Protocol = "v1v2c"
	}
	switch cfg.SNMP.Protocol {
	case "v1v2c", "v3", "both":
	default:
		return fmt.Errorf("config: unsupported snmp.protocol %q (want v1v2c, v3, or both)", cfg.SNMP.Protocol)
	}
	// Validate V3 settings when V3 is enabled.
	if cfg.SNMP.Protocol == "v3" || cfg.SNMP.Protocol == "both" {
		if err := ValidateV3(&cfg.SNMP.V3); err != nil {
			return err
		}
	}
	if cfg.OIDMap.Path == "" {
		return fmt.Errorf("config: oidMap.path is required (point to mib-parser oid-database.db)")
	}
	if cfg.OIDMap.LoadFailPolicy == "" {
		cfg.OIDMap.LoadFailPolicy = "exit"
	}
	switch cfg.OIDMap.LoadFailPolicy {
	case "exit", "warn":
	default:
		return fmt.Errorf("config: unsupported oidMap.loadFailPolicy %q", cfg.OIDMap.LoadFailPolicy)
	}
	if cfg.CEPEngine.BaseURL == "" {
		return fmt.Errorf("config: cepEngine.baseUrl is required")
	}
	if cfg.Forward.QueueFullPolicy == "" {
		cfg.Forward.QueueFullPolicy = string(forward.PolicyDrop)
	}
	switch forward.QueueFullPolicy(cfg.Forward.QueueFullPolicy) {
	case forward.PolicyDrop, forward.PolicyBlock, forward.PolicySingle:
	default:
		return fmt.Errorf("config: unsupported forward.queueFullPolicy %q", cfg.Forward.QueueFullPolicy)
	}
	return nil
}

// validAuthProtocols and validPrivProtocols enumerate the accepted SNMPv3
// security protocol identifiers (case-insensitive in config).
var (
	validAuthProtocols = map[string]struct{}{
		"none": {}, "md5": {}, "sha": {}, "sha224": {},
		"sha256": {}, "sha384": {}, "sha512": {},
	}
	validPrivProtocols = map[string]struct{}{
		"none": {}, "des": {}, "aes": {}, "aes192": {},
		"aes256": {}, "aes192c": {}, "aes256c": {},
	}
)

// ValidateV3 checks SNMPv3 USM credential consistency.
func ValidateV3(v3 *V3Config) error {
	if v3.User == "" {
		return fmt.Errorf("config: snmp.v3.user is required when protocol is v3 or both")
	}
	auth := strings.ToLower(v3.AuthProtocol)
	if auth == "" {
		auth = "none"
	}
	if _, ok := validAuthProtocols[auth]; !ok {
		return fmt.Errorf("config: unsupported snmp.v3.authProtocol %q", v3.AuthProtocol)
	}
	priv := strings.ToLower(v3.PrivProtocol)
	if priv == "" {
		priv = "none"
	}
	if _, ok := validPrivProtocols[priv]; !ok {
		return fmt.Errorf("config: unsupported snmp.v3.privProtocol %q", v3.PrivProtocol)
	}
	// Privacy requires authentication (RFC 3414: privLevel implies authLevel).
	if auth == "none" && priv != "none" {
		return fmt.Errorf("config: snmp.v3.privProtocol requires a non-none authProtocol")
	}
	if auth != "none" && v3.AuthPassphrase == "" {
		return fmt.Errorf("config: snmp.v3.authPassphrase is required when authProtocol is %q", v3.AuthProtocol)
	}
	if priv != "none" && v3.PrivPassphrase == "" {
		return fmt.Errorf("config: snmp.v3.privPassphrase is required when privProtocol is %q", v3.PrivProtocol)
	}
	// USM passphrase length: 8..255 per RFC 3414.
	if auth != "none" && len(v3.AuthPassphrase) < 8 {
		return fmt.Errorf("config: snmp.v3.authPassphrase must be at least 8 characters")
	}
	if priv != "none" && len(v3.PrivPassphrase) < 8 {
		return fmt.Errorf("config: snmp.v3.privPassphrase must be at least 8 characters")
	}
	return nil
}
