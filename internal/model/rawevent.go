// Package model defines the RawEvent JSON structure that trap-daemon builds
// and forwards to cep-engine. Field names and structure are strictly aligned
// with cep-engine's com.raysdata.cep.model.RawEvent (deserialized with Gson,
// so JSON keys must match the Java field names exactly).
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"trap-daemon/internal/snmp"
)

// RawEvent is the payload posted to cep-engine.
type RawEvent struct {
	Source          string   `json:"source"`
	SourceIP        string   `json:"sourceIp"`
	ReceivedAt      int64    `json:"receivedAt"`
	OriginTimestamp int64    `json:"originTimestamp"`
	RawEvent        string   `json:"rawEvent"`
	Metadata        Metadata `json:"metadata"`
}

// Metadata holds protocol-specific data consumed by the Groovy parser.
type Metadata struct {
	TrapOID  string            `json:"trapOid"`
	Varbinds map[string]string `json:"varbinds"`
}

// Source value used for SNMP traps.
const SourceSNMPTrap = "snmp_trap"

// sysUpTime is measured in hundredths of a second; convert to millis.
const sysUpTimeToMillis = 10

// NewFromTrapData builds a RawEvent from a decoded trap and a field-name map.
//
// fieldName maps a full instance varbind OID to a field name (from oidmap).
// varbinds in metadata use the field name as the key, falling back to the raw
// OID when no field name is known (cep-engine's resolveInstanceOid handles the
// full instance OID as a final fallback).
//
// OriginTimestamp is derived deterministically from the trap's sysUpTime so
// that multiple Active-Active daemon instances produce an identical value for
// the same device event (required by cep-engine transport dedup). SNMP v1/v2c
// traps carry no device absolute timestamp, so sysUpTime-based derivation is
// the only stable cross-instance source.
func NewFromTrapData(td *snmp.TrapData, fieldName func(oid string) (string, bool)) *RawEvent {
	if fieldName == nil {
		fieldName = func(string) (string, bool) { return "", false }
	}
	varbinds := make(map[string]string, len(td.Varbinds))
	for _, vb := range td.Varbinds {
		key := vb.OID
		if name, ok := fieldName(vb.OID); ok {
			key = name
		}
		varbinds[key] = vb.Value
	}

	rawText := renderRawText(td)

	return &RawEvent{
		Source:          SourceSNMPTrap,
		SourceIP:        td.SourceIP,
		ReceivedAt:      td.ReceivedAt,
		OriginTimestamp: deriveOriginTimestamp(td, rawText),
		RawEvent:        rawText,
		Metadata: Metadata{
			TrapOID:  td.TrapOID,
			Varbinds: varbinds,
		},
	}
}

// deriveOriginTimestamp computes a deterministic cross-instance timestamp.
// Preferred: sysUpTime converted to millis (identical for all instances of the
// same trap). Fallback: a deterministic hash of the raw trap text when
// sysUpTime is zero/absent, still identical across instances.
func deriveOriginTimestamp(td *snmp.TrapData, rawText string) int64 {
	if td.SysUpTime > 0 {
		return int64(td.SysUpTime) * sysUpTimeToMillis
	}
	return deterministicHash(rawText)
}

// deterministicHash returns a stable int64 derived from the raw text.
func deterministicHash(s string) int64 {
	sum := sha256.Sum256([]byte(s))
	// Use the first 8 bytes as an int64 (deterministic, not used as crypto).
	var v int64
	for i := 0; i < 8; i++ {
		v = v<<8 | int64(sum[i])
	}
	if v < 0 {
		v = -v
	}
	return v
}

// renderRawText produces a stable, human-readable text of the trap. It must be
// deterministic (no receivedAt) so it can be used in the dedup fingerprint.
func renderRawText(td *snmp.TrapData) string {
	var b strings.Builder
	fmt.Fprintf(&b, "SNMP trap v%s from %s\n", td.Version, td.SourceIP)
	fmt.Fprintf(&b, "trap-oid: %s\n", td.TrapOID)
	fmt.Fprintf(&b, "sysUpTime: %d\n", td.SysUpTime)
	for _, vb := range td.Varbinds {
		fmt.Fprintf(&b, "varbind %s=%s\n", vb.OID, vb.Value)
	}
	return b.String()
}

// checksum returns the hex SHA-256 of a byte payload (used by tests/forwarder).
func checksum(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
