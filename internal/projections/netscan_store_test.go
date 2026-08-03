// SPDX-License-Identifier: MPL-2.0

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

	sc := netscan.New(&testNetscanStoreSink{store: s, tenantID: tenantA}, netscan.WithAllowLoopbackTargets(true))
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

// testNetscanStoreSink upserts network-scan discoveries into the inventory. It
// lives HERE, in a control-plane test, and not in internal/discovery/netscan,
// because C2 re-homes network scanning onto network-role agents — and the agent
// binary must not link internal/store (docs/agent_binary_import_boundary_test.go).
// The direct upsert is a test harness for store idempotency; the production
// ingestion path is event-sourced through the dispatcher's run sinks (AN-2).
type testNetscanStoreSink struct {
	store    *store.Store
	tenantID string
}

func (ss *testNetscanStoreSink) Record(ctx context.Context, f netscan.Found) error {
	info := f.Cert
	notBefore, notAfter := info.NotBefore, info.NotAfter
	sans := make([]string, 0, len(info.DNSNames)+len(info.IPAddresses)+len(info.URIs)+len(info.EmailAddresses))
	sans = append(sans, info.DNSNames...)
	sans = append(sans, info.IPAddresses...)
	sans = append(sans, info.URIs...)
	sans = append(sans, info.EmailAddresses...)
	_, err := ss.store.UpsertCertificate(ctx, store.Certificate{
		TenantID:           ss.tenantID,
		Subject:            info.Subject,
		SANs:               sans,
		Issuer:             info.Issuer,
		Serial:             info.SerialNumber,
		Fingerprint:        info.SHA256Fingerprint,
		KeyAlgorithm:       info.KeyAlgorithm,
		NotBefore:          &notBefore,
		NotAfter:           &notAfter,
		DeploymentLocation: f.Address,
		Source:             "network-scan",
	})
	return err
}
