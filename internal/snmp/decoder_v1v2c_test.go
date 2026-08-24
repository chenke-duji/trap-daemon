package snmp

import (
	"net"
	"testing"

	"github.com/gosnmp/gosnmp"
)

func testUDPAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 54310}
}

func TestDecodeV2c(t *testing.T) {
	pkt := &gosnmp.SnmpPacket{
		Version: gosnmp.Version2c,
		PDUType: gosnmp.SNMPv2Trap,
		Variables: []gosnmp.SnmpPDU{
			{Name: "1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(360000)},
			{Name: "1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: "1.3.6.1.6.3.1.1.5.3"},
			{Name: "1.3.6.1.2.1.2.2.1.1.3", Type: gosnmp.Integer, Value: 3},
			{Name: "1.3.6.1.2.1.2.2.1.2.3", Type: gosnmp.OctetString, Value: []byte("eth0")},
		},
	}

	d := NewV1V2cDecoder()
	if d.Version() != "v1/v2c" {
		t.Fatalf("unexpected version label %q", d.Version())
	}
	td, err := d.Decode(pkt, testUDPAddr())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if td.Version != "2c" {
		t.Fatalf("expected 2c, got %s", td.Version)
	}
	if td.TrapOID != "1.3.6.1.6.3.1.1.5.3" {
		t.Fatalf("expected linkDown trapOID, got %s", td.TrapOID)
	}
	if td.SysUpTime != 360000 {
		t.Fatalf("expected sysUpTime 360000, got %d", td.SysUpTime)
	}
	if td.SourceIP != "192.0.2.10" {
		t.Fatalf("expected source ip, got %s", td.SourceIP)
	}
	if len(td.Varbinds) != 2 {
		t.Fatalf("expected 2 data varbinds (envelope dropped), got %d: %+v", len(td.Varbinds), td.Varbinds)
	}
	if td.Varbinds[0].OID != "1.3.6.1.2.1.2.2.1.1.3" || td.Varbinds[0].Value != "3" {
		t.Fatalf("unexpected varbind0: %+v", td.Varbinds[0])
	}
	if td.Varbinds[1].Value != "eth0" {
		t.Fatalf("expected eth0, got %q", td.Varbinds[1].Value)
	}
}

func TestDecodeV1EnterpriseSpecific(t *testing.T) {
	pkt := &gosnmp.SnmpPacket{
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
	d := NewV1V2cDecoder()
	td, err := d.Decode(pkt, testUDPAddr())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if td.Version != "1" {
		t.Fatalf("expected 1, got %s", td.Version)
	}
	if td.TrapOID != "1.3.6.1.4.1.9.55" {
		t.Fatalf("expected enterpriseSpecific trapOID, got %s", td.TrapOID)
	}
	if td.GenericTrap != 6 || td.SpecificTrap != 55 {
		t.Fatalf("unexpected v1 trap header: %+v", td)
	}
	if td.AgentAddress != "192.0.2.11" {
		t.Fatalf("expected agent address, got %s", td.AgentAddress)
	}
}

func TestDecodeV1GenericLinkDown(t *testing.T) {
	pkt := &gosnmp.SnmpPacket{
		Version: gosnmp.Version1,
		PDUType: gosnmp.Trap,
		SnmpTrap: gosnmp.SnmpTrap{
			Enterprise:  "1.3.6.1.6.3.1.1.5",
			GenericTrap: 2, // linkDown
			Timestamp:   100,
		},
		Variables: []gosnmp.SnmpPDU{
			{Name: "1.3.6.1.2.1.2.2.1.1.3", Type: gosnmp.Integer, Value: 3},
		},
	}
	d := NewV1V2cDecoder()
	td, err := d.Decode(pkt, testUDPAddr())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if td.TrapOID != "1.3.6.1.6.3.1.1.5.3" {
		t.Fatalf("expected linkDown trapOID, got %s", td.TrapOID)
	}
}

func TestDecodeNilPacket(t *testing.T) {
	d := NewV1V2cDecoder()
	if _, err := d.Decode(nil, testUDPAddr()); err == nil {
		t.Fatal("expected error for nil packet")
	}
}

func TestDecodeUnsupportedVersion(t *testing.T) {
	pkt := &gosnmp.SnmpPacket{Version: gosnmp.Version3}
	d := NewV1V2cDecoder()
	if _, err := d.Decode(pkt, testUDPAddr()); err == nil {
		t.Fatal("expected error for v3 in v1/v2c decoder")
	}
}

func TestValueToString(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{[]byte("eth0"), "eth0"},
		{int(3), "3"},
		{uint32(360000), "360000"},
		{nil, ""},
		{"abc", "abc"},
	}
	for _, c := range cases {
		if got := valueToString(c.in); got != c.want {
			t.Fatalf("valueToString(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
