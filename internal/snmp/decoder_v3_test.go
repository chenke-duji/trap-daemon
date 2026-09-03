package snmp

import (
	"net"
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestDecodeV3(t *testing.T) {
	pkt := &gosnmp.SnmpPacket{
		Version: gosnmp.Version3,
		PDUType: gosnmp.SNMPv2Trap,
		Variables: []gosnmp.SnmpPDU{
			{Name: "1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(720000)},
			{Name: "1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: "1.3.6.1.6.3.1.1.5.4"},
			{Name: "1.3.6.1.2.1.2.2.1.1.5", Type: gosnmp.Integer, Value: 5},
			{Name: "1.3.6.1.2.1.2.2.1.2.5", Type: gosnmp.OctetString, Value: []byte("eth1")},
		},
	}

	d := NewV3Decoder()
	if d.Version() != "v3" {
		t.Fatalf("unexpected version label %q", d.Version())
	}
	td, err := d.Decode(pkt, testUDPAddr())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if td.Version != "3" {
		t.Fatalf("expected version 3, got %s", td.Version)
	}
	if td.TrapOID != "1.3.6.1.6.3.1.1.5.4" {
		t.Fatalf("expected linkUp trapOID, got %s", td.TrapOID)
	}
	if td.SysUpTime != 720000 {
		t.Fatalf("expected sysUpTime 720000, got %d", td.SysUpTime)
	}
	if td.SourceIP != "192.0.2.10" {
		t.Fatalf("expected source ip 192.0.2.10, got %s", td.SourceIP)
	}
	if len(td.Varbinds) != 2 {
		t.Fatalf("expected 2 data varbinds (envelope dropped), got %d: %+v", len(td.Varbinds), td.Varbinds)
	}
	if td.Varbinds[0].OID != "1.3.6.1.2.1.2.2.1.1.5" || td.Varbinds[0].Value != "5" {
		t.Fatalf("unexpected varbind0: %+v", td.Varbinds[0])
	}
	if td.Varbinds[1].Value != "eth1" {
		t.Fatalf("expected eth1, got %q", td.Varbinds[1].Value)
	}
}

func TestDecodeV3NilPacket(t *testing.T) {
	d := NewV3Decoder()
	if _, err := d.Decode(nil, testUDPAddr()); err == nil {
		t.Fatal("expected error for nil packet")
	}
}

func TestDecodeV3WrongVersion(t *testing.T) {
	pkt := &gosnmp.SnmpPacket{Version: gosnmp.Version2c}
	d := NewV3Decoder()
	if _, err := d.Decode(pkt, testUDPAddr()); err == nil {
		t.Fatal("expected error for v2c packet in v3 decoder")
	}
}

func TestDecodeV3TrapOIDFromBytes(t *testing.T) {
	// Some agents send snmpTrapOID as []byte instead of string.
	pkt := &gosnmp.SnmpPacket{
		Version: gosnmp.Version3,
		PDUType: gosnmp.SNMPv2Trap,
		Variables: []gosnmp.SnmpPDU{
			{Name: "1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(100)},
			{Name: "1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.OctetString, Value: []byte("1.3.6.1.4.1.9.9.43.1")},
		},
	}
	d := NewV3Decoder()
	td, err := d.Decode(pkt, testUDPAddr())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if td.TrapOID != "1.3.6.1.4.1.9.9.43.1" {
		t.Fatalf("expected trapOID from bytes, got %s", td.TrapOID)
	}
}

func TestDecodeV3NilSource(t *testing.T) {
	pkt := &gosnmp.SnmpPacket{
		Version: gosnmp.Version3,
		PDUType: gosnmp.SNMPv2Trap,
		Variables: []gosnmp.SnmpPDU{
			{Name: "1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: "1.3.6.1.6.3.1.1.5.1"},
		},
	}
	d := NewV3Decoder()
	td, err := d.Decode(pkt, nil)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if td.SourceIP != "" {
		t.Fatalf("expected empty source IP for nil src, got %s", td.SourceIP)
	}
}

// Ensure the shared decodeV2cFormatPDU still works via V1V2cDecoder
// (regression guard after extracting the shared function).
func TestDecodeV2cAfterRefactor(t *testing.T) {
	pkt := &gosnmp.SnmpPacket{
		Version: gosnmp.Version2c,
		PDUType: gosnmp.SNMPv2Trap,
		Variables: []gosnmp.SnmpPDU{
			{Name: "1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(500)},
			{Name: "1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: "1.3.6.1.6.3.1.1.5.5"},
		},
	}
	d := NewV1V2cDecoder()
	td, err := d.Decode(pkt, &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if td.Version != "2c" {
		t.Fatalf("expected 2c, got %s", td.Version)
	}
	if td.TrapOID != "1.3.6.1.6.3.1.1.5.5" {
		t.Fatalf("expected authenticationFailure, got %s", td.TrapOID)
	}
	if td.SysUpTime != 500 {
		t.Fatalf("expected sysUpTime 500, got %d", td.SysUpTime)
	}
}
