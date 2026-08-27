// Command trapd is the SNMP Trap Daemon: it listens for v1/v2c traps on UDP,
// maps varbind OIDs to field names using the mib-parser OID database, builds
// cep-engine RawEvents, and forwards them in batches over REST HTTP. It is
// designed to run Active-Active (dedup happens in cep-engine).
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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

var (
	configPath = flag.String("config", "config.yaml", "path to YAML config file")
	version    = flag.Bool("version", false, "print version and exit")
)

// build info (overridable at link time).
var (
	buildVersion = "dev"
	buildDate    = "unknown"
)

func main() {
	flag.Parse()
	if *version {
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
	if cfg.Metrics.Enabled {
		go serveMetrics(cfg.Metrics, metric, logger)
	}

	// SNMP trap receiver.
	decoder := snmp.NewV1V2cDecoder()
	tl := gosnmp.NewTrapListener()
	tl.Params = gosnmp.Default // v2c default; UnmarshalTrap detects v1/v2c from the packet
	tl.Params.Logger = gosnmp.NewLogger(slog.NewLogLogger(logger.Handler(), slog.LevelDebug))
	tl.OnNewTrap = func(pkt *gosnmp.SnmpPacket, src *net.UDPAddr) {
		handleTrap(pkt, src, decoder, om, q, logger)
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

	tl.Close()
	q.Close()
	_ = fwd.Close()
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

// serveMetrics exposes the Prometheus endpoint until the process exits.
func serveMetrics(cfg config.MetricsConfig, m *metrics.Metrics, logger *slog.Logger) {
	mux := http.NewServeMux()
	mux.Handle(cfg.Path, m.Handler())
	srv := &http.Server{Addr: cfg.ListenAddr, Handler: mux}
	logger.Info("metrics endpoint listening", "addr", cfg.ListenAddr, "path", cfg.Path)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("metrics server failed", "err", err)
	}
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
	mu          sync.Mutex
	path        string
	maxSize     int64
	maxBackups  int
	file        *os.File
	writeErr    error
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
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	if w.file == nil {
		f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			w.writeErr = err
			return 0, err
		}
		w.file = f
	}
	if info, err := w.file.Stat(); err == nil && info.Size()+int64(len(p)) > w.maxSize {
		w.rotate()
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
