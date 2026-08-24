package oidmap

import (
	"os"
	"path/filepath"
	"testing"
)

func testDataPath(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// wd is <repo>/internal/oidmap; testdata lives at repo/testdata
	path := filepath.Join(wd, "..", "..", "testdata", "oid-database.db")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("testdata missing at %s: %v", path, err)
	}
	return path
}

func TestLoadAndLen(t *testing.T) {
	m, err := Load(testDataPath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if m.Len() != 10 {
		t.Fatalf("expected 10 entries, got %d", m.Len())
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(os.TempDir(), "does-not-exist-oidmap.properties")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadEmptyFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "empty.properties")
	if err := os.WriteFile(p, []byte("# only a comment\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for file with no valid entries")
	}
}

func TestLookupExactInstance(t *testing.T) {
	m, err := Load(testDataPath(t))
	if err != nil {
		t.Fatal(err)
	}
	// varbind with instance suffix appended to an object node
	name, ok := m.Lookup("1.3.6.1.2.1.2.2.1.1.3")
	if !ok {
		t.Fatal("expected match")
	}
	if name != "ifIndex" {
		t.Fatalf("expected ifIndex, got %s", name)
	}
}

func TestLookupDeepestPrefix(t *testing.T) {
	m, err := Load(testDataPath(t))
	if err != nil {
		t.Fatal(err)
	}
	// Both 1.3.6.1.2.1.2.2.1.1 (ifIndex) and ...1.2 (ifDescr) share prefixes;
	// 1.3.6.1.2.1.2.2.1.2.1 must map to ifDescr (longest prefix).
	name, ok := m.Lookup("1.3.6.1.2.1.2.2.1.2.1")
	if !ok {
		t.Fatal("expected match")
	}
	if name != "ifDescr" {
		t.Fatalf("expected ifDescr, got %s", name)
	}
}

func TestLookupEnterprisePrefix(t *testing.T) {
	m, err := Load(testDataPath(t))
	if err != nil {
		t.Fatal(err)
	}
	// Enterprise trap field with deep instance
	name, ok := m.Lookup("1.3.6.1.4.1.9.9.43.1.1.6.1.22")
	if !ok {
		t.Fatal("expected match")
	}
	if name != "hwEntityDescr" {
		t.Fatalf("expected hwEntityDescr, got %s", name)
	}
}

func TestLookupNoMatch(t *testing.T) {
	m, err := Load(testDataPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Lookup("1.3.6.1.2.1.999.1.1"); ok {
		t.Fatal("expected no match")
	}
}

func TestLookupInvalidOID(t *testing.T) {
	m, err := Load(testDataPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Lookup("not-an-oid"); ok {
		t.Fatal("expected no match for invalid oid")
	}
}

func TestLookupNilMap(t *testing.T) {
	var m *Map
	if _, ok := m.Lookup("1.3.6.1"); ok {
		t.Fatal("expected no match on nil map")
	}
	if m.Len() != 0 {
		t.Fatal("expected len 0 on nil map")
	}
}

func TestParseOID(t *testing.T) {
	segs, err := parseOID("1.3.6.1.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 6 || segs[0] != 1 || segs[5] != 1 {
		t.Fatalf("unexpected parse: %v", segs)
	}
	if _, err := parseOID("1.a.3"); err == nil {
		t.Fatal("expected error for non-numeric segment")
	}
}
