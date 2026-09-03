// Command trapd is the SNMP Trap Daemon: it listens for v1/v2c/v3 traps on
// UDP, maps varbind OIDs to field names using the mib-parser OID database,
// builds cep-engine RawEvents, and forwards them in batches over REST HTTP.
// It is designed to run Active-Active (dedup happens in cep-engine).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gosnmp/gosnmp"

	"trap-daemon/internal/config"
	"trap-daemon/internal/forward"
	"trap-daemon/internal/metrics"
	"trap-daemon/internal/model"
	"trap-daemon/internal/oidmap"
	"trap-daemon/internal/snmp"
)

// snmpV3Params builds a gosnmp.GoSNMP configured for V3 USM trap reception.
// UnmarshalTrap auto-detects the packet version from the header, so this
// listener can also decode v1/v2c traps when protocol is "both".
func snmpV3Params(v3 config.V3Config, logger *slog.Logger) *gosnmp.GoSNMP {
	authProto := parseV3AuthProtocol(v3.AuthProtocol)
	privProto := parseV3PrivProtocol(v3.PrivProtocol)

	msgFlags := gosnmp.NoAuthNoPriv
	if authProto != gosnmp.NoAuth {
		msgFlags = gosnmp.AuthNoPriv
	}
	if privProto != gosnmp.NoPriv {
		msgFlags = gosnmp.AuthPriv
	}

	gosnmpLogger := gosnmp.NewLogger(slog.NewLogLogger(logger.Handler(), slog.LevelDebug))

	return &gosnmp.GoSNMP{
		Version:       gosnmp.Version3,
		SecurityModel: gosnmp.UserSecurityModel,
		MsgFlags:      msgFlags,
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 v3.User,
			AuthenticationProtocol:   authProto,
			AuthenticationPassphrase: v3.AuthPassphrase,
			PrivacyProtocol:          privProto,
			PrivacyPassphrase:        v3.PrivPassphrase,
			Logger:                   gosnmpLogger,
		},
		Logger: gosnmpLogger,
	}
}

// parseV3AuthProtocol maps a config string to a gosnmp SnmpV3AuthProtocol.
// Empty or "none" maps to NoAuth. Config validation ensures only valid
// values reach this function; the default case is unreachable in production.
func parseV3AuthProtocol(s string) gosnmp.SnmpV3AuthProtocol {
	switch strings.ToLower(s) {
	case "", "none":
		return gosnmp.NoAuth
	case "md5":
		return gosnmp.MD5
	case "sha":
		return gosnmp.SHA
	case "sha224":
		return gosnmp.SHA224
	case "sha256":
		return gosnmp.SHA256
	case "sha384":
		return gosnmp.SHA384
	case "sha512":
		return gosnmp.SHA512
	default:
		return gosnmp.NoAuth
	}
}

// parseV3PrivProtocol maps a config string to a gosnmp SnmpV3PrivProtocol.
// Empty or "none" maps to NoPriv. Config validation ensures only valid
// values reach this function; the default case is unreachable in production.
func parseV3PrivProtocol(s string) gosnmp.SnmpV3PrivProtocol {
	switch strings.ToLower(s) {
	case "", "none":
		return gosnmp.NoPriv
	case "des":
		return gosnmp.DES
	case "aes":
		return gosnmp.AES
	case "aes192":
		return gosnmp.AES192
	case "aes256":
		return gosnmp.AES256
	case "aes192c":
		return gosnmp.AES192C
	case "aes256c":
		return gosnmp.AES256C
	default:
		return gosnmp.NoPriv
	}
}

// v3SecurityLevel returns the SNMPv3 security level label for logging.
func v3SecurityLevel(v3 config.V3Config) string {
	auth := parseV3AuthProtocol(v3.AuthProtocol)
	priv := parseV3PrivProtocol(v3.PrivProtocol)
	switch {
	case auth == gosnmp.NoAuth && priv == gosnmp.NoPriv:
		return "NoAuthNoPriv"
	case auth != gosnmp.NoAuth && priv == gosnmp.NoPriv:
		return "AuthNoPriv"
	case auth != gosnmp.NoAuth && priv != gosnmp.NoPriv:
		return "AuthPriv"
	default:
		return "Unknown"
	}
}

var (
	configPath = flag.String("config", "config.yaml", "path to YAML config file")
	v          = flag.Bool("v", false, "print build/version info and exit")
	version    = flag.Bool("version", false, "print build/version info and exit (alias of -v)")
)

// build info (overridable at link time via -ldflags "-X main.buildVersion=... -X main.buildDate=...").
var (
	buildVersion = "dev"
	buildDate    = "unknown"
)

func main() {
	flag.Parse()
	if *v || *version {
		fmt.Printf("trap-daemon %s (%s)\n", buildVersion, buildDate)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trap-daemon: %v\n", err)
		os.Exit(1)
	}

	logger := setupLogger(cfg.Logging)
	slog.SetDefault(logger)
	logger.Info("trap-daemon starting",
		"version", buildVersion, "listen", cfg.SNMP.ListenAddr, "protocol", cfg.SNMP.Protocol)

	// OID database (config item pointing at mib-parser output).
	om, err := oidmap.Load(cfg.OIDMap.Path)
	if err != nil {
		if cfg.OIDMap.LoadFailPolicy == "warn" {
			logger.Warn("oidmap load failed; continuing without field-name mapping", "err", err)
			om = nil
		} else {
			logger.Error("oidmap load failed", "path", cfg.OIDMap.Path, "err", err)
			os.Exit(1)
		}
	} else {
		logger.Info("oidmap loaded", "path", cfg.OIDMap.Path, "entries", om.Len())
	}

	// Assemble pipeline: metrics -> batch queue -> http forwarder.
	var q *forward.BatchQueue
	metric := metrics.New(func() int {
		if q != nil {
			return q.QueueDepth()
		}
		return 0
	})

	fwd, err := forward.NewHTTPForwarder(forward.HTTPConfig{
		BaseURL:    cfg.CEPEngine.BaseURL,
		BatchPath:  cfg.CEPEngine.BatchPath,
		SinglePath: cfg.CEPEngine.SinglePath,
		AuthToken:  cfg.CEPEngine.AuthToken,
		Timeout:    cfg.CEPEngine.Timeout,
		RetryMax:   cfg.CEPEngine.RetryMax,
		RetryBase:  cfg.CEPEngine.RetryBase,
	}, logger)
	if err != nil {
		logger.Error("forwarder init failed", "err", err)
		os.Exit(1)
	}

	q = forward.NewBatchQueue(cfg.Forward, fwd, metric, logger)
	q.Start()
	logger.Info("forward pipeline started",
		"workers", cfg.Forward.Workers, "batchSize", cfg.Forward.BatchSize,
		"queueCapacity", cfg.Forward.QueueCapacity, "policy", cfg.Forward.QueueFullPolicy)

	// Optional Prometheus self-monitoring endpoint.
	var metricsSrv *http.Server
	if cfg.Metrics.Enabled {
		metricsSrv = startMetrics(cfg.Metrics, metric, logger)
	}

	// SNMP trap receiver.
	v1v2cDecoder := snmp.NewV1V2cDecoder()
	var v3Decoder snmp.TrapDecoder
	v3Enabled := cfg.SNMP.Protocol == "v3" || cfg.SNMP.Protocol == "both"
	if v3Enabled {
		v3Decoder = snmp.NewV3Decoder()
	}
	cc := newCommunityChecker(cfg.SNMP.Communities, logger)
	tl := gosnmp.NewTrapListener()
	if v3Enabled {
		// V3 params also handle v1/v2c: UnmarshalTrap auto-detects version
		// from the packet header, so a single listener covers "both".
		tl.Params = snmpV3Params(cfg.SNMP.V3, logger)
		secLevel := v3SecurityLevel(cfg.SNMP.V3)
		logger.Info("SNMPv3 trap reception enabled",
			"user", cfg.SNMP.V3.User,
			"authProtocol", cfg.SNMP.V3.AuthProtocol,
			"privProtocol", cfg.SNMP.V3.PrivProtocol,
			"securityLevel", secLevel,
		)
		if secLevel == "NoAuthNoPriv" {
			logger.Warn("SNMPv3 configured with NoAuthNoPriv: traps will be accepted without authentication or encryption (insecure)")
		}
	} else {
		tl.Params = gosnmp.Default
	}
	tl.Params.Logger = gosnmp.NewLogger(slog.NewLogLogger(logger.Handler(), slog.LevelDebug))
	tl.OnNewTrap = func(pkt *gosnmp.SnmpPacket, src *net.UDPAddr) {
		// V3 packets use USM authentication, not community strings.
		if pkt.Version != gosnmp.Version3 {
			if !cc.accept(pkt, src) {
				return
			}
		}
		var dec snmp.TrapDecoder
		switch pkt.Version {
		case gosnmp.Version3:
			dec = v3Decoder
		default:
			dec = v1v2cDecoder
		}
		handleTrap(pkt, src, dec, om, q, logger)
	}

	listenErr := make(chan error, 1)
	go func() {
		logger.Info("SNMP trap listener starting", "addr", cfg.SNMP.ListenAddr)
		if err := tl.Listen(cfg.SNMP.ListenAddr); err != nil {
			listenErr <- err
		}
	}()
	// Wait until the listener socket is actually bound.
	select {
	case <-tl.Listening():
		logger.Info("SNMP trap listener ready", "addr", cfg.SNMP.ListenAddr)
	case err := <-listenErr:
		logger.Error("SNMP trap listener failed", "err", err)
		os.Exit(1)
	case <-time.After(10 * time.Second):
		logger.Warn("timed out waiting for trap listener readiness")
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Info("shutdown signal received", "signal", sig.String())

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	tl.Close()
	q.Close()
	_ = fwd.Close()
	if metricsSrv != nil {
		_ = metricsSrv.Shutdown(shutdownCtx)
	}
	logger.Info("trap-daemon stopped")
}

// handleTrap decodes a packet, maps varbind OIDs to field names, builds a
// RawEvent, and enqueues it for forwarding.
func handleTrap(pkt *gosnmp.SnmpPacket, src *net.UDPAddr, decoder snmp.TrapDecoder, om *oidmap.Map, q *forward.BatchQueue, logger *slog.Logger) {
	td, err := decoder.Decode(pkt, src)
	if err != nil {
		logger.Warn("trap decode failed", "err", err)
		return
	}

	// fieldName closure consults the OID map (nil-safe).
	var fieldName func(string) (string, bool)
	trapName := td.TrapOID
	if om != nil {
		fieldName = om.Lookup
		if n, ok := om.Lookup(td.TrapOID); ok {
			trapName = n
		}
	}
	ev := model.NewFromTrapData(td, fieldName)
	logger.Info("received trap",
		"sourceIp", td.SourceIP,
		"trapName", trapName,
		"trapOid", td.TrapOID,
	)
	q.Enqueue(ev)
}

// communityChecker validates incoming trap communities against a configured
// allowlist. If the allowlist is empty, all communities are accepted but a
// startup warning is logged.
type communityChecker struct {
	allowed map[string]struct{}
	log     *slog.Logger
}

func newCommunityChecker(communities []string, log *slog.Logger) *communityChecker {
	cc := &communityChecker{
		allowed: make(map[string]struct{}, len(communities)),
		log:     log,
	}
	for _, c := range communities {
		cc.allowed[c] = struct{}{}
	}
	if len(cc.allowed) == 0 {
		log.Warn("no SNMP communities configured; all traps will be accepted (insecure)")
	}
	return cc
}

func (cc *communityChecker) accept(pkt *gosnmp.SnmpPacket, src *net.UDPAddr) bool {
	if len(cc.allowed) == 0 {
		return true
	}
	_, ok := cc.allowed[pkt.Community]
	if !ok {
		srcIP := ""
		if src != nil {
			srcIP = src.IP.String()
		}
		cc.log.Warn("trap rejected: community not in allowlist",
			"sourceIp", srcIP,
			"community", pkt.Community,
		)
		return false
	}
	return true
}

// startMetrics launches the Prometheus endpoint in a goroutine and returns the
// *http.Server so the caller can gracefully shut it down.
func startMetrics(cfg config.MetricsConfig, m *metrics.Metrics, logger *slog.Logger) *http.Server {
	mux := http.NewServeMux()
	mux.Handle(cfg.Path, m.Handler())
	srv := &http.Server{Addr: cfg.ListenAddr, Handler: mux}
	go func() {
		logger.Info("metrics endpoint listening", "addr", cfg.ListenAddr, "path", cfg.Path)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics server failed", "err", err)
		}
	}()
	return srv
}

// setupLogger configures slog level and output (stdout or rotating file).
func setupLogger(cfg config.LoggingConfig) *slog.Logger {
	level := parseLevel(cfg.Level)
	opts := &slog.HandlerOptions{Level: level}

	var w ioWriter
	if cfg.File != "" {
		rw := newRotatingWriter(cfg.File, cfg.MaxSizeMB, cfg.MaxBackups)
		w = rw
	} else {
		w = os.Stdout
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

type ioWriter interface {
	Write(p []byte) (int, error)
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// rotatingWriter appends to a file and rolls it over when it exceeds a size
// limit, keeping up to maxBackups rotated files.
type rotatingWriter struct {
	mu         sync.Mutex
	path       string
	maxSize    int64
	maxBackups int
	file       *os.File
}

func newRotatingWriter(path string, maxSizeMB, maxBackups int) *rotatingWriter {
	return &rotatingWriter{
		path:       path,
		maxSize:    int64(maxSizeMB) * 1024 * 1024,
		maxBackups: maxBackups,
	}
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Ensure file is open.
	if w.file == nil {
		f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return 0, err
		}
		w.file = f
	}

	// Rotate if this write would exceed the size limit.
	if info, err := w.file.Stat(); err == nil && info.Size()+int64(len(p)) > w.maxSize {
		w.rotate()
		// rotate closes and nulls w.file; reopen for the new write.
		if w.file == nil {
			f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
			if err != nil {
				return 0, err
			}
			w.file = f
		}
	}

	return w.file.Write(p)
}

func (w *rotatingWriter) rotate() {
	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}
	ts := time.Now().Format("20060102-150405")
	rotated := fmt.Sprintf("%s.%s", w.path, ts)
	_ = os.Rename(w.path, rotated)
	// Prune old backups beyond maxBackups.
	if w.maxBackups > 0 {
		matches, _ := filepath.Glob(w.path + ".*")
		for len(matches) > w.maxBackups {
			// Rough pruning by filename timestamp (oldest first).
			oldest := matches[0]
			for _, m := range matches {
				if m < oldest {
					oldest = m
				}
			}
			_ = os.Remove(oldest)
			matches = removeStr(matches, oldest)
		}
	}
}

func removeStr(s []string, v string) []string {
	for i, x := range s {
		if x == v {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}
