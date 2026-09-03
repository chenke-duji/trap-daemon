// Package snmp decodes SNMP Trap packets into a normalized TrapData used by
// the rest of trap-daemon. The decoder consumes a parsed gosnmp.SnmpPacket
// (which already carries v1/v2c/v3 information) and produces a standardized
// structure. v1, v2c, and v3 are all implemented.
package snmp

import (
	"net"

	"github.com/gosnmp/gosnmp"
)

// Varbind is a single variable binding extracted from a trap PDU.
// OID is the full instance OID (leading dot stripped). Value is the
// string rendering of the original typed value.
type Varbind struct {
	OID   string
	Type  string // SNMP type name, e.g. "Integer", "OctetString"
	Value string
}

// TrapData is the normalized representation of an incoming SNMP trap,
// independent of protocol version. Fields shared by v1/v2c are filled in;
// version-specific ones (Enterprise/GenericTrap/SpecificTrap) are only set
// for v1.
type TrapData struct {
	Version      string    // "1", "2c", or "3"
	SourceIP     string    // UDP source address
	TrapOID      string    // trap OID (v2c: snmpTrapOID value; v1: synthesized)
	Enterprise   string    // v1 only
	GenericTrap  int       // v1 only
	SpecificTrap int       // v1 only
	SysUpTime    uint32    // device uptime in hundredths of a second
	ReceivedAt   int64     // unix millis when the daemon received the trap
	AgentAddress string    // v1 only (may be empty)
	Varbinds     []Varbind // all varbinds except the trapOID/sysUpTime envelope vars
}

// TrapDecoder decodes a parsed gosnmp packet into a TrapData.
// Implementations are version-specific.
type TrapDecoder interface {
	// Version reports which SNMP version this decoder handles.
	Version() string
	// Decode converts a parsed packet plus its UDP source into TrapData.
	Decode(pkt *gosnmp.SnmpPacket, src *net.UDPAddr) (*TrapData, error)
}
