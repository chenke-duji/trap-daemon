// Package oidmap loads the OID -> symbol-name database produced by
// mib-parser (oid-database.properties) and performs longest-prefix matching
// of a full instance OID (from a trap varbind) to a known field/object name.
//
// The database file is NOT bundled with this project; its path is a config
// item supplied by the user (see config oidMap.path). The file format is the
// standard Java properties style emitted by mib-parser:
//
//	# comment
//	1.3.6.1.2.1.2.2.1.1=ifIndex
//	1.3.6.1.2.1.2.2.1.2=ifDescr
//
package oidmap

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// node is a single OID entry with its parsed numeric form.
type node struct {
	segments []int // numeric OID, e.g. [1 3 6 1 2 1 2 2 1 1]
	name     string
	oid      string
}

// Map holds a sorted list of OID nodes for longest-prefix matching.
// It is immutable after Load; safe for concurrent reads.
type Map struct {
	nodes []node // sorted lexicographically by segments
}

// Load reads an oid-database.properties file and builds the prefix Map.
// It returns an error if the file cannot be read or no valid entry is parsed.
func Load(path string) (*Map, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("oidmap: open %s: %w", path, err)
	}
	defer f.Close()

	var nodes []node
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue // ignore malformed lines, keep loader lenient
		}
		oid := strings.TrimSpace(line[:eq])
		name := strings.TrimSpace(line[eq+1:])
		if oid == "" || name == "" {
			continue
		}
		segs, err := parseOID(oid)
		if err != nil {
			// Skip unparsable OIDs (e.g. symbol names used as keys in rare cases).
			continue
		}
		nodes = append(nodes, node{segments: segs, name: name, oid: oid})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("oidmap: read %s: %w", path, err)
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("oidmap: no valid entries in %s", path)
	}

	sort.Slice(nodes, func(i, j int) bool {
		return compareSegs(nodes[i].segments, nodes[j].segments) < 0
	})

	return &Map{nodes: nodes}, nil
}

// Len returns the number of loaded OID entries.
func (m *Map) Len() int {
	if m == nil {
		return 0
	}
	return len(m.nodes)
}

// Lookup performs longest-prefix matching of a full instance OID against the
// loaded object nodes. It returns the matched symbol name (field name) and
// true on success. If the OID cannot be parsed or no node is a prefix of it,
// it returns ("", false) so the caller can fall back to the raw OID as key.
func (m *Map) Lookup(fullInstanceOid string) (string, bool) {
	if m == nil {
		return "", false
	}
	segs, err := parseOID(fullInstanceOid)
	if err != nil {
		return "", false
	}

	// Upper bound: index of first node with segments > target.
	i := sort.Search(len(m.nodes), func(i int) bool {
		return compareSegs(m.nodes[i].segments, segs) > 0
	})

	// Walk backwards from i-1 to find the longest node that is a prefix.
	for k := i - 1; k >= 0; k-- {
		if isPrefix(m.nodes[k].segments, segs) {
			return m.nodes[k].name, true
		}
	}
	return "", false
}

// compareSegs compares two numeric OID slices lexicographically.
// Returns -1, 0, or 1.
func compareSegs(a, b []int) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}

// isPrefix reports whether p is a prefix of s.
func isPrefix(p, s []int) bool {
	if len(p) > len(s) {
		return false
	}
	for i := range p {
		if p[i] != s[i] {
			return false
		}
	}
	return true
}

// parseOID parses a dot-separated numeric OID string into a slice of ints.
func parseOID(oid string) ([]int, error) {
	parts := strings.Split(oid, ".")
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty oid")
	}
	segs := make([]int, 0, len(parts))
	for _, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 {
			return nil, fmt.Errorf("invalid oid segment %q", p)
		}
		segs = append(segs, v)
	}
	return segs, nil
}
