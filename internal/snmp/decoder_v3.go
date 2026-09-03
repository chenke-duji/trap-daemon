package snmp

import (
	"fmt"
	"net"
	"time"

	"github.com/gosnmp/gosnmp"
)

// V3Decoder decodes SNMPv3 traps. V3 trap PDUs use the same SNMPv2-Trap-PDU
// format as v2c (snmpTrapOID and sysUpTime carried as varbinds), so the PDU
// body is parsed identically. V3 authentication and decryption are handled
// by gosnmp's UnmarshalTrap before the packet reaches the decoder.
type V3Decoder struct{}

// NewV3Decoder returns a decoder for v3 traps.
func NewV3Decoder() *V3Decoder {
	return &V3Decoder{}
}

// Version reports "v3".
func (d *V3Decoder) Version() string { return "v3" }

// Decode converts a parsed v3 packet into a normalized TrapData.
// The packet must have already been authenticated and decrypted by gosnmp's
// UnmarshalTrap; this method only extracts the PDU fields.
func (d *V3Decoder) Decode(pkt *gosnmp.SnmpPacket, src *net.UDPAddr) (*TrapData, error) {
	if pkt == nil {
		return nil, fmt.Errorf("snmp: nil packet")
	}
	if pkt.Version != gosnmp.Version3 {
		return nil, fmt.Errorf("snmp: v3 decoder received non-v3 packet (version %d)", pkt.Version)
	}

	sourceIP := ""
	if src != nil {
		sourceIP = src.IP.String()
	}

	td := &TrapData{
		Version:    "3",
		SourceIP:   sourceIP,
		ReceivedAt: time.Now().UnixMilli(),
	}

	// V3 trap PDU format is identical to V2c: snmpTrapOID and sysUpTime
	// are carried as varbinds in the SNMPv2-Trap-PDU.
	return decodeV2cFormatPDU(pkt, td)
}
