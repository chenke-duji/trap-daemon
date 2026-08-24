// Package integration exercises the full trap-daemon pipeline with real
// gosnmp packets: UDP listener -> decoder -> oidmap field-name mapping ->
// RawEvent -> batch queue -> HTTP POST to a mock cep-engine. This validates
// the end-to-end RawEvent JSON contract against cep-engine.
package integration

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"trap-daemon/internal/forward"
	"trap-daemon/internal/metrics"
	"trap-daemon/internal/model"
	"trap-daemon/internal/oidmap"
	"trap-daemon/internal/snmp"
)

// testdataPath resolves the repo testdata oid-database.properties.
func testdataPath() string {
	wd, _ := os.Getwd() // <repo>/internal/integration
	return filepath.Join(wd, "..", "..", "testdata", "oid-database.properties")
}

type mockCEPServer struct {
	t       *testing.T
	gotPath string
	gotAuth string
	bodies  chan []byte
}

func newMockCEPServer(t *testing.T) *mockCEPServer {
	m := &mockCEPServer{t: t, bodies: make(chan []byte, 16)}
	return m
}

func (m *mockCEPServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.gotPath = r.URL.Path
		m.gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		select {
		case m.bodies <- body:
		default:
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"accepted"}`))
	})
}

func setupPipeline(t *testing.T, mock *mockCEPServer) (*gosnmp.TrapListener, int) {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Load OID map from testdata.
	om, err := oidmap.Load(testdataPath())
	if err != nil {
		t.Fatalf("oidmap load: %v", err)
	}

	// Forwarder -> mock cep-engine.
	srv := httptest.NewServer(mock.handler())
	t.Cleanup(srv.Close)

	fwd, err := forward.NewHTTPForwarder(forward.HTTPConfig{
		BaseURL:   srv.URL,
		BatchPath: "/api/v1/events/batch",
		Timeout:   2000,
		RetryMax:  1,
		RetryBase: 5,
	}, logger)
	if err != nil {
		t.Fatalf("forwarder: %v", err)
	}

	// Metrics + batch queue.
	var q *forward.BatchQueue
	m := metrics.New(func() int {
		if q != nil {
			return q.QueueDepth()
		}
		return 0
	})
	q = forward.NewBatchQueue(forward.ForwardConfig{
		BatchSize:          10,
		BatchFlushInterval: 50,
		Workers:            2,
		QueueCapacity:      100,
		QueueFullPolicy:    "drop",
		DropLogEnabled:     true,
	}, fwd, m, logger)
	q.Start()
	t.Cleanup(q.Close)

	// Trap listener on a random high port.
	decoder := snmp.NewV1V2cDecoder()
	tl := gosnmp.NewTrapListener()
	tl.Params = gosnmp.Default
	tl.Params.Logger = gosnmp.NewLogger(slog.NewLogLogger(logger.Handler(), slog.LevelDebug))
	tl.OnNewTrap = func(pkt *gosnmp.SnmpPacket, src *net.UDPAddr) {
		td, err := decoder.Decode(pkt, src)
		if err != nil {
			t.Errorf("decode: %v", err)
			return
		}
		ev := model.NewFromTrapData(td, om.Lookup)
		q.Enqueue(ev)
	}

	addr := "127.0.0.1:" + freePort(t)
	go func() {
		if err := tl.Listen(addr); err != nil {
			t.Errorf("listen: %v", err)
		}
	}()
	select {
	case <-tl.Listening():
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not become ready")
	}
	t.Cleanup(tl.Close)

	return tl, portNumber(t, addr)
}

func freePort(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, portStr, _ := net.SplitHostPort(conn.LocalAddr().String())
	return portStr
}

func portNumber(t *testing.T, addr string) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func sendV2cTrap(t *testing.T, port int) {
	t.Helper()
	// Build a raw SNMPv2c trap packet and send it directly over UDP to avoid
	// gosnmp.SendTrap waiting for a response (traps are unconfirmed).
	packet := &gosnmp.SnmpPacket{
		Version:   gosnmp.Version2c,
		PDUType:   gosnmp.SNMPv2Trap,
		Community: "public",
		Variables: []gosnmp.SnmpPDU{
			{Name: "1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(360000)},
			{Name: "1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: "1.3.6.1.6.3.1.1.5.3"},
			{Name: "1.3.6.1.2.1.2.2.1.1.3", Type: gosnmp.Integer, Value: 3},
			{Name: "1.3.6.1.2.1.2.2.1.2.3", Type: gosnmp.OctetString, Value: []byte("eth0")},
		},
	}
	data, err := packet.MarshalMsg()
	if err != nil {
		t.Fatalf("marshal trap: %v", err)
	}

	conn, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(data); err != nil {
		t.Fatalf("write trap: %v", err)
	}
}

func sendV1Trap(t *testing.T, port int) {
	t.Helper()
	packet := &gosnmp.SnmpPacket{
		Version: gosnmp.Version1,
		PDUType: gosnmp.Trap,
		SnmpTrap: gosnmp.SnmpTrap{
			Enterprise:   "1.3.6.1.4.1.9",
			AgentAddress: "192.0.2.11",
			GenericTrap:  6,
			SpecificTrap: 55,
			Timestamp:    300,
		},
		Variables: []gosnmp.SnmpPDU{
			{Name: "1.3.6.1.4.1.9.9.43.1.1.6.1.22", Type: gosnmp.OctetString, Value: []byte("interface-1")},
		},
	}
	data, err := packet.MarshalMsg()
	if err != nil {
		t.Fatalf("marshal v1 trap: %v", err)
	}
	conn, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(data); err != nil {
		t.Fatalf("write v1 trap: %v", err)
	}
}

func TestEndToEndV1(t *testing.T) {
	mock := newMockCEPServer(t)
	_, port := setupPipeline(t, mock)

	sendV1Trap(t, port)

	var body []byte
	select {
	case body = <-mock.bodies:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for v1 trap")
	}

	var events []map[string]any
	if err := json.Unmarshal(body, &events); err != nil {
		t.Fatalf("invalid batch JSON: %v", err)
	}
	ev := events[0]
	md, _ := ev["metadata"].(map[string]any)
	if md == nil {
		t.Fatal("metadata missing")
	}
	// v1 enterpriseSpecific trap OID = enterprise + specificTrap.
	if md["trapOid"] != "1.3.6.1.4.1.9.55" {
		t.Fatalf("expected enterpriseSpecific trapOid, got %v", md["trapOid"])
	}
	// OID map maps 1.3.6.1.4.1.9.9.43.1.1.6.1.* -> hwEntityDescr.
	vb, _ := md["varbinds"].(map[string]any)
	if vb == nil || vb["hwEntityDescr"] != "interface-1" {
		t.Fatalf("expected varbinds[hwEntityDescr]=interface-1, got %v", vb)
	}
}

func TestEndToEndV2c(t *testing.T) {
	mock := newMockCEPServer(t)
	_, port := setupPipeline(t, mock)

	sendV2cTrap(t, port)

	var body []byte
	select {
	case body = <-mock.bodies:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for cep-engine to receive the trap")
	}

	if mock.gotPath != "/api/v1/events/batch" {
		t.Fatalf("expected batch path, got %s", mock.gotPath)
	}

	var events []map[string]any
	if err := json.Unmarshal(body, &events); err != nil {
		t.Fatalf("invalid batch JSON: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("empty batch")
	}
	ev := events[0]

	// Contract fields.
	for _, key := range []string{"source", "sourceIp", "receivedAt", "originTimestamp", "rawEvent", "metadata"} {
		if _, ok := ev[key]; !ok {
			t.Fatalf("missing contract field %q", key)
		}
	}
	if ev["source"] != "snmp_trap" {
		t.Fatalf("expected source snmp_trap, got %v", ev["source"])
	}

	md, _ := ev["metadata"].(map[string]any)
	if md == nil {
		t.Fatal("metadata missing")
	}
	if md["trapOid"] != "1.3.6.1.6.3.1.1.5.3" {
		t.Fatalf("expected linkDown trapOid, got %v", md["trapOid"])
	}
	// Varbinds must be keyed by field name (from oidmap), not raw OID.
	vb, _ := md["varbinds"].(map[string]any)
	if vb == nil {
		t.Fatalf("varbinds missing: %v", md)
	}
	if vb["ifIndex"] != "3" {
		t.Fatalf("expected varbinds[ifIndex]=3, got %v", vb)
	}
	if vb["ifDescr"] != "eth0" {
		t.Fatalf("expected varbinds[ifDescr]=eth0, got %v", vb)
	}
}
