package model

import (
	"encoding/json"
	"strings"
	"testing"

	"trap-daemon/internal/snmp"
)

func testTrapData() *snmp.TrapData {
	return &snmp.TrapData{
		Version:    "2c",
		SourceIP:   "192.0.2.10",
		TrapOID:    "1.3.6.1.6.3.1.1.5.3",
		SysUpTime:  360000,
		ReceivedAt: 1724400000000,
		Varbinds: []snmp.Varbind{
			{OID: "1.3.6.1.2.1.2.2.1.1.3", Type: "Integer", Value: "3"},
			{OID: "1.3.6.1.2.1.2.2.1.2.3", Type: "OctetString", Value: "eth0"},
		},
	}
}

func TestNewFromTrapDataWithFieldNames(t *testing.T) {
	// Simulate oidmap: map known instance OIDs to field names.
	fieldName := func(oid string) (string, bool) {
		switch oid {
		case "1.3.6.1.2.1.2.2.1.1.3":
			return "ifIndex", true
		case "1.3.6.1.2.1.2.2.1.2.3":
			return "ifDescr", true
		default:
			return "", false
		}
	}
	ev := NewFromTrapData(testTrapData(), fieldName)

	if ev.Source != "snmp_trap" {
		t.Fatalf("expected source snmp_trap, got %s", ev.Source)
	}
	if ev.SourceIP != "192.0.2.10" {
		t.Fatalf("unexpected sourceIp %s", ev.SourceIP)
	}
	if ev.Metadata.TrapOID != "1.3.6.1.6.3.1.1.5.3" {
		t.Fatalf("unexpected trapOid %s", ev.Metadata.TrapOID)
	}
	// varbinds keyed by field name
	if ev.Metadata.Varbinds["ifIndex"] != "3" {
		t.Fatalf("expected varbinds[ifIndex]=3, got %v", ev.Metadata.Varbinds)
	}
	if ev.Metadata.Varbinds["ifDescr"] != "eth0" {
		t.Fatalf("expected varbinds[ifDescr]=eth0, got %v", ev.Metadata.Varbinds)
	}
	// deterministic originTimestamp from sysUpTime (360000 hundredths -> 3,600,000 ms)
	if ev.OriginTimestamp != 3600000 {
		t.Fatalf("expected originTimestamp 3600000, got %d", ev.OriginTimestamp)
	}
	// rawEvent deterministic and non-empty
	if ev.RawEvent == "" {
		t.Fatal("rawEvent empty")
	}
}

func TestNewFromTrapDataFallbackOIDKey(t *testing.T) {
	// No mapping -> varbind key falls back to raw instance OID.
	ev := NewFromTrapData(testTrapData(), func(string) (string, bool) { return "", false })
	if ev.Metadata.Varbinds["1.3.6.1.2.1.2.2.1.1.3"] != "3" {
		t.Fatalf("expected raw OID fallback key, got %v", ev.Metadata.Varbinds)
	}
}

func TestOriginTimestampDeterministicFallback(t *testing.T) {
	td := testTrapData()
	td.SysUpTime = 0 // force hash fallback

	ev1 := NewFromTrapData(td, nil)
	ev2 := NewFromTrapData(td, nil)
	if ev1.OriginTimestamp != ev2.OriginTimestamp {
		t.Fatalf("expected deterministic originTimestamp, got %d vs %d", ev1.OriginTimestamp, ev2.OriginTimestamp)
	}
	// Deterministic across time: same td -> same value.
	if ev1.OriginTimestamp == 0 {
		t.Fatal("expected non-zero hash-derived originTimestamp")
	}
}

func TestRawEventJSONContract(t *testing.T) {
	ev := NewFromTrapData(testTrapData(), func(string) (string, bool) { return "", false })
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	// JSON keys must match the Java Gson field names exactly.
	want := []string{
		`"source":"snmp_trap"`,
		`"sourceIp":"192.0.2.10"`,
		`"receivedAt"`,
		`"originTimestamp"`,
		`"rawEvent"`,
		`"metadata"`,
		`"trapOid":"1.3.6.1.6.3.1.1.5.3"`,
	}
	s := string(b)
	for _, w := range want {
		if !strings.Contains(s, w) {
			t.Fatalf("JSON missing %q in %s", w, s)
		}
	}
}
