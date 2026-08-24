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
	ListenAddr string `yaml:"listenAddr"` // e.g. "0.0.0.0:162"
	Protocol   string `yaml:"protocol"`   // "v1v2c" (default) or "v3"
	Community  string `yaml:"community"`  // optional; empty accepts all
	V3         V3Config `yaml:"v3"`       // reserved
}

// V3Config reserves SNMPv3 credentials (not implemented yet).
type V3Config struct {
	Enabled       bool   `yaml:"enabled"`
	User          string `yaml:"user"`
	AuthProtocol  string `yaml:"authProtocol"`
	AuthPassphrase string `yaml:"authPassphrase"`
	PrivProtocol  string `yaml:"privProtocol"`
	PrivPassphrase string `yaml:"privPassphrase"`
}

// OIDMapConfig points at the mib-parser generated OID database (a config item,
// never bundled with this project).
type OIDMapConfig struct {
	Path          string `yaml:"path"`
	LoadFailPolicy string `yaml:"loadFailPolicy"` // "exit" (default) | "warn"
}

// CEPEngineConfig describes the downstream cep-engine REST endpoint.
type CEPEngineConfig struct {
	BaseURL   string `yaml:"baseUrl"`
	BatchPath string `yaml:"batchPath"`
	SinglePath string `yaml:"singlePath"`
	AuthToken string `yaml:"authToken"`
	Timeout   int    `yaml:"timeoutMs"`
	RetryMax  int    `yaml:"retryMax"`
	RetryBase int    `yaml:"retryBaseMs"`
}

// LoggingConfig controls log level and output file rotation settings.
type LoggingConfig struct {
	Level     string `yaml:"level"` // debug | info | warn | error
	File      string `yaml:"file"`  // empty -> stdout
	MaxSizeMB int    `yaml:"maxSizeMB"`
	MaxBackups int   `yaml:"maxBackups"`
}

// MetricsConfig controls the Prometheus self-monitoring endpoint.
type MetricsConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listenAddr"`
	Path       string `yaml:"path"`
}

// Config is the root configuration.
type Config struct {
	SNMP      SNMPConfig          `yaml:"snmp"`
	OIDMap    OIDMapConfig        `yaml:"oidMap"`
	CEPEngine CEPEngineConfig     `yaml:"cepEngine"`
	Forward   forward.ForwardConfig `yaml:"forward"`
	Logging   LoggingConfig       `yaml:"logging"`
	Metrics   MetricsConfig       `yaml:"metrics"`
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
			ListenAddr: ":9091",
			Path:       "/metrics",
		},
	}
}

// applyEnv applies simple TRAPD_* environment overrides. Format:
//
//	TRAPD_SNMP_LISTENADDR, TRAPD_CEPGINE_BASEURL, TRAPD_OIDMAP_PATH,
//	TRAPD_LOGGING_LEVEL, TRAPD_METRICS_ENABLED, ...
func applyEnv(cfg *Config) {
	setStr := func(env string, dst *string) {
		if v := os.Getenv(env); v != "" {
			*dst = v
		}
	}
	setStr("TRAPD_SNMP_LISTENADDR", &cfg.SNMP.ListenAddr)
	setStr("TRAPD_SNMP_PROTOCOL", &cfg.SNMP.Protocol)
	setStr("TRAPD_SNMP_COMMUNITY", &cfg.SNMP.Community)
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
	case "v1v2c", "v3":
	default:
		return fmt.Errorf("config: unsupported snmp.protocol %q (want v1v2c or v3)", cfg.SNMP.Protocol)
	}
	if cfg.OIDMap.Path == "" {
		return fmt.Errorf("config: oidMap.path is required (point to mib-parser oid-database.properties)")
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
