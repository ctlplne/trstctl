package ctlog_test

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto/ctlog"
	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
)

func TestParseSTH(t *testing.T) {
	sth, err := ctlog.ParseSTH(ctlogtest.GetSTHBody(42))
	if err != nil {
		t.Fatalf("ParseSTH: %v", err)
	}
	if sth.TreeSize != 42 {
		t.Errorf("TreeSize = %d, want 42", sth.TreeSize)
	}
}

func TestParseSTHRejectsGarbage(t *testing.T) {
	if _, err := ctlog.ParseSTH([]byte("not json")); err == nil {
		t.Error("ParseSTH(garbage) = nil error, want an error")
	}
}

func TestParseEntriesX509(t *testing.T) {
	der, _, err := ctlogtest.IssueCert("payments", "payments.example.com", "www.payments.example.com")
	if err != nil {
		t.Fatal(err)
	}
	body := ctlogtest.GetEntriesBody(ctlogtest.X509Entry(der))

	entries, err := ctlog.ParseEntries(7, body)
	if err != nil {
		t.Fatalf("ParseEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Index != 7 {
		t.Errorf("Index = %d, want 7 (start offset)", e.Index)
	}
	if e.Precert {
		t.Error("x509_entry must not be flagged a precert")
	}
	if !equalStr(e.DNSNames, []string{"payments.example.com", "www.payments.example.com"}) {
		t.Errorf("DNSNames = %v", e.DNSNames)
	}
	if e.FingerprintSHA256 == "" || e.SerialHex == "" {
		t.Errorf("missing fingerprint/serial: %+v", e)
	}
	if e.NotAfter.IsZero() {
		t.Error("NotAfter is zero")
	}
}

func TestParseEntriesPrecert(t *testing.T) {
	der, tbs, err := ctlogtest.IssueCert("api", "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	body := ctlogtest.GetEntriesBody(ctlogtest.PrecertEntry(der, tbs))

	entries, err := ctlog.ParseEntries(0, body)
	if err != nil {
		t.Fatalf("ParseEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	e := entries[0]
	if !e.Precert {
		t.Error("precert_entry must be flagged a precert")
	}
	if !equalStr(e.DNSNames, []string{"api.example.com"}) {
		t.Errorf("DNSNames = %v, want [api.example.com]", e.DNSNames)
	}
}

func TestParseEntriesMixedBatch(t *testing.T) {
	d1, _, _ := ctlogtest.IssueCert("one", "one.example.com")
	d2, tbs2, _ := ctlogtest.IssueCert("two", "two.example.com")
	body := ctlogtest.GetEntriesBody(ctlogtest.X509Entry(d1), ctlogtest.PrecertEntry(d2, tbs2))

	entries, err := ctlog.ParseEntries(100, body)
	if err != nil {
		t.Fatalf("ParseEntries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Index != 100 || entries[1].Index != 101 {
		t.Errorf("indices = %d,%d, want 100,101", entries[0].Index, entries[1].Index)
	}
	if entries[0].Precert || !entries[1].Precert {
		t.Errorf("precert flags = %v,%v, want false,true", entries[0].Precert, entries[1].Precert)
	}
}

func TestParseEntriesRejectsTruncatedLeaf(t *testing.T) {
	// A leaf_input that is too short to hold the framing must error, not panic.
	bad := ctlogtest.LogEntry{LeafInput: []byte{0, 0, 1, 2}, ExtraData: nil}
	if _, err := ctlog.ParseEntries(0, ctlogtest.GetEntriesBody(bad)); err == nil {
		t.Error("ParseEntries(truncated leaf) = nil error, want an error")
	}
}

func equalStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
