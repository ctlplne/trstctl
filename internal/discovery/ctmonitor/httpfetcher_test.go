package ctmonitor_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/discovery/ctmonitor"
)

// The HTTP fetcher talks RFC 6962 to a faithful CT log and returns parsed,
// crypto-free entries — without the monitor ever importing crypto.
func TestHTTPFetcher(t *testing.T) {
	d1, _, err := ctlogtest.IssueCert("one", "one.example.com")
	if err != nil {
		t.Fatal(err)
	}
	d2, tbs2, err := ctlogtest.IssueCert("two", "two.example.com")
	if err != nil {
		t.Fatal(err)
	}
	srv := ctlogtest.NewServer(ctlogtest.X509Entry(d1), ctlogtest.PrecertEntry(d2, tbs2))
	defer srv.Close()

	f := ctmonitor.NewHTTPFetcher()
	ctx := context.Background()

	size, err := f.TreeSize(ctx, srv.URL())
	if err != nil {
		t.Fatalf("TreeSize: %v", err)
	}
	if size != 2 {
		t.Fatalf("TreeSize = %d, want 2", size)
	}

	entries, err := f.Entries(ctx, srv.URL(), 0, size)
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].DNSNames[0] != "one.example.com" || entries[1].DNSNames[0] != "two.example.com" {
		t.Errorf("entries = %q, %q", entries[0].DNSNames, entries[1].DNSNames)
	}
	if entries[0].Precert || !entries[1].Precert {
		t.Errorf("precert flags = %v, %v, want false, true", entries[0].Precert, entries[1].Precert)
	}
	if entries[1].Index != 1 {
		t.Errorf("entries[1].Index = %d, want 1", entries[1].Index)
	}
}
