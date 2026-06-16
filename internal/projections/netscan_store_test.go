package projections_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/discovery/netscan"
	"trstctl.com/trstctl/internal/store"
)

// TestNetscanMergesDiscoveryIntoInventory is the S6.1 acceptance: the scanner
// discovers a certificate over the network and merges it into the inventory
// (S4.1) via the StoreSink, idempotently.
func TestNetscanMergesDiscoveryIntoInventory(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	fingerprint := crypto.SHA256Hex(srv.Certificate().Raw)

	sc := netscan.New(netscan.NewStoreSink(s, tenantA))
	defer sc.Close()

	if rep := sc.Scan(ctx, []string{addr}); rep.Discovered != 1 {
		t.Fatalf("scan report = %+v, want 1 discovered", rep)
	}

	cert := certByFingerprint(t, ctx, s, fingerprint)
	if cert.DeploymentLocation != addr {
		t.Errorf("deployment location = %q, want %q", cert.DeploymentLocation, addr)
	}
	if cert.Source != "network-scan" {
		t.Errorf("source = %q, want network-scan", cert.Source)
	}
	if cert.NotAfter == nil {
		t.Error("inventory row is missing validity metadata")
	}

	// Re-scanning the same endpoint refreshes the row rather than duplicating it.
	if rep := sc.Scan(ctx, []string{addr}); rep.Discovered != 1 {
		t.Fatalf("re-scan report = %+v", rep)
	}
	if n := countByFingerprint(t, ctx, s, fingerprint); n != 1 {
		t.Errorf("re-scan duplicated the inventory row: %d rows with the same fingerprint", n)
	}
}

func listCerts(t *testing.T, ctx context.Context, s *store.Store) []store.Certificate {
	t.Helper()
	certs, err := s.ListCertificatesPage(ctx, tenantA, store.ZeroUUID, nil, 1000, nil)
	if err != nil {
		t.Fatalf("list certificates: %v", err)
	}
	return certs
}

func certByFingerprint(t *testing.T, ctx context.Context, s *store.Store, fp string) store.Certificate {
	t.Helper()
	for _, c := range listCerts(t, ctx, s) {
		if c.Fingerprint == fp {
			return c
		}
	}
	t.Fatalf("no inventory row with fingerprint %s", fp)
	return store.Certificate{}
}

func countByFingerprint(t *testing.T, ctx context.Context, s *store.Store, fp string) int {
	t.Helper()
	n := 0
	for _, c := range listCerts(t, ctx, s) {
		if c.Fingerprint == fp {
			n++
		}
	}
	return n
}
