package snmp

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"
)

// Well-known OIDs used to locate envelope variables inside a trap PDU.
const (
	oidSysUpTime   = "1.3.6.1.2.1.1.3.0"
	oidSnmpTrapOID = "1.3.6.1.6.3.1.1.4.1.0"
)

// Standard SNMPv2 trap OIDs, used to synthesize a v1 generic trap OID.
// Index i corresponds to GenericTrap value i (0..5).
var v1GenericTrapOIDs = [...]string{
	"1.3.6.1.6.3.1.1.5.1", // coldStart
	"1.3.6.1.6.3.1.1.5.2", // warmStart
	"1.3.6.1.6.3.1.1.5.3", // linkDown
	"1.3.6.1.6.3.1.1.5.4", // linkUp
	"1.3.6.1.6.3.1.1.5.5", // authenticationFailure
	"1.3.6.1.6.3.1.1.5.6", // egpNeighborLoss
}

// V1V2cDecoder decodes SNMPv1 and v2c traps. v3 is not handled here; a future
// V3Decoder can implement TrapDecoder independently.
type V1V2cDecoder struct{}

// NewV1V2cDecoder returns a decoder for v1/v2c traps.
func NewV1V2cDecoder() *V1V2cDecoder {
	return &V1V2cDecoder{}
}

// Version reports "1/2c" (both handled by this decoder).
func (d *V1V2cDecoder) Version() string { return "v1/v2c" }

// Decode converts a parsed gosnmp packet into a normalized TrapData.
func (d *V1V2cDecoder) Decode(pkt *gosnmp.SnmpPacket, src *net.UDPAddr) (*TrapData, error) {
	if pkt == nil {
		return nil, fmt.Errorf("snmp: nil packet")
	}
	sourceIP := ""
	if src != nil {
		sourceIP = src.IP.String()
	}

	td := &TrapData{
		Version:    versionString(pkt.Version),
		SourceIP:   sourceIP,
		ReceivedAt: time.Now().UnixMilli(),
	}

	switch pkt.Version {
	case gosnmp.Version1:
		return d.decodeV1(pkt, td)
	case gosnmp.Version2c:
		return d.decodeV2c(pkt, td)
	default:
		return nil, fmt.Errorf("snmp: unsupported version %d for v1/v2c decoder", pkt.Version)
	}
}

// decodeV1 handles the SNMPv1 trap format (enterprise/generic/specific header).
func (d *V1V2cDecoder) decodeV1(pkt *gosnmp.SnmpPacket, td *TrapData) (*TrapData, error) {
	td.Enterprise = trimDot(pkt.Enterprise)
	td.GenericTrap = pkt.GenericTrap
	td.SpecificTrap = pkt.SpecificTrap
	td.AgentAddress = pkt.AgentAddress
	td.SysUpTime = uint32(pkt.Timestamp) //#nosec G115 -- TimeTicks is a 32-bit protocol field

	switch {
	case pkt.GenericTrap >= 0 && pkt.GenericTrap <= 5:
		td.TrapOID = v1GenericTrapOIDs[pkt.GenericTrap]
	case pkt.GenericTrap == 6:
		// enterpriseSpecific: <enterprise>.<specificTrap>
		if td.Enterprise == "" {
			return nil, fmt.Errorf("snmp: enterpriseSpecific trap (generic=6) missing enterprise OID")
		}
		td.TrapOID = td.Enterprise + "." + strconv.Itoa(pkt.SpecificTrap)
	default:
		return nil, fmt.Errorf("snmp: invalid generic trap %d (must be 0-6)", pkt.GenericTrap)
	}

	td.Varbinds = extractVarbinds(pkt.Variables)
	return td, nil
}

// decodeV2c handles the v2c format; the trap OID comes from the snmpTrapOID
// varbind and sysUpTime from the sysUpTime.0 varbind.
func (d *V1V2cDecoder) decodeV2c(pkt *gosnmp.SnmpPacket, td *TrapData) (*TrapData, error) {
	return decodeV2cFormatPDU(pkt, td)
}

// decodeV2cFormatPDU parses the PDU body common to v2c and v3 traps:
// snmpTrapOID from the snmpTrapOID.0 varbind and sysUpTime from
// sysUpTime.0, then extracts the remaining data varbinds.
// V3 trap PDUs use the identical SNMPv2-Trap-PDU format as v2c.
func decodeV2cFormatPDU(pkt *gosnmp.SnmpPacket, td *TrapData) (*TrapData, error) {
	for _, v := range pkt.Variables {
		oid := trimDot(v.Name)
		switch oid {
		case oidSysUpTime:
			if u, ok := toUint64(v.Value); ok {
				td.SysUpTime = uint32(u) //#nosec G115 -- TimeTicks is a 32-bit protocol field
			}
		case oidSnmpTrapOID:
			switch val := v.Value.(type) {
			case string:
				td.TrapOID = trimDot(val)
			case []byte:
				if utf8.Valid(val) {
					td.TrapOID = trimDot(string(val))
				}
			}
		}
	}

	td.Varbinds = extractVarbinds(pkt.Variables)
	return td, nil
}

// extractVarbinds converts the PDU variables into Varbind list, dropping the
// envelope variables (sysUpTime.0 and snmpTrapOID.0) which are not field data.
func extractVarbinds(pdus []gosnmp.SnmpPDU) []Varbind {
	out := make([]Varbind, 0, len(pdus))
	for _, p := range pdus {
		oid := trimDot(p.Name)
		if oid == oidSysUpTime || oid == oidSnmpTrapOID {
			continue
		}
		out = append(out, Varbind{
			OID:   oid,
			Type:  p.Type.String(),
			Value: valueToString(p.Value),
		})
	}
	return out
}

// valueToString renders a decoded SNMP value to a stable string form.
// Binary (non-UTF-8) OctetString values are hex-encoded to avoid producing
// unprintable characters in logs and downstream JSON payloads.
func valueToString(v any) string {
	switch t := v.(type) {
	case []byte:
		if utf8.Valid(t) {
			return string(t)
		}
		return "0x" + hex.EncodeToString(t)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

// toUint64 extracts a uint64 from common SNMP numeric value types.
// Signed integer types are accepted only when non-negative (SNMP counters and
// TimeTicks are unsigned by definition), avoiding G115 overflow concerns.
func toUint64(v any) (uint64, bool) {
	switch t := v.(type) {
	case int:
		if t < 0 {
			return 0, false
		}
		return uint64(t), true
	case uint:
		return uint64(t), true
	case uint32:
		return uint64(t), true
	case uint64:
		return t, true
	case int32:
		if t < 0 {
			return 0, false
		}
		return uint64(t), true
	case int64:
		if t < 0 {
			return 0, false
		}
		return uint64(t), true
	default:
		return 0, false
	}
}

// trimDot removes a single leading dot from an OID string.
func trimDot(oid string) string {
	return strings.TrimPrefix(oid, ".")
}

// versionString maps a gosnmp SnmpVersion to a stable label.
func versionString(v gosnmp.SnmpVersion) string {
	switch v {
	case gosnmp.Version1:
		return "1"
	case gosnmp.Version2c:
		return "2c"
	case gosnmp.Version3:
		return "3"
	default:
		return fmt.Sprintf("unknown(%d)", v)
	}
}
