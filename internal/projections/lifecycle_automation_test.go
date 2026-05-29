package projections_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"certctl.io/certctl/internal/ca"
	"certctl.io/certctl/internal/crypto"
	"certctl.io/certctl/internal/crypto/certinfo"
	"certctl.io/certctl/internal/lifecycle"
	"certctl.io/certctl/internal/notify"
	"certctl.io/certctl/internal/orchestrator"
	"certctl.io/certctl/internal/store"
)

// lifecycleCSR builds a CSR for cn via the crypto boundary (no crypto/* here).
func lifecycleCSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: cn, DNSNames: []string{cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// newLifecycleManager wires a Manager over the built-in CA and the real spine.
func newLifecycleManager(t *testing.T, s *store.Store, cfg lifecycle.Config) (*lifecycle.Manager, *ca.IssuanceService) {
	t.Helper()
	builtin, err := ca.NewBuiltin("certctl Built-in CA")
	if err != nil {
		t.Fatal(err)
	}
	idem := orchestrator.NewIdempotency(s)
	ob := orchestrator.NewOutbox(s)
	svc := ca.NewIssuanceService(builtin, idem, ob, s)
	log := openLog(t)
	return lifecycle.NewManager(s, svc, ob, idem, log, cfg), svc
}

// seedInventoryCert issues a real certificate with the given lifetime and
// inventories it, returning the stored row (with id, serial, not_after).
func seedInventoryCert(t *testing.T, s *store.Store, svc *ca.IssuanceService, tenantID, cn string, ttl time.Duration) store.Certificate {
	t.Helper()
	ctx := context.Background()
	issued, err := svc.Issue(ctx, ca.IssueRequest{TenantID: tenantID, CSR: lifecycleCSR(t, cn), DNSNames: []string{cn}, TTL: ttl}, "seed:"+tenantID+":"+cn)
	if err != nil {
		t.Fatalf("seed Issue: %v", err)
	}
	info, err := certinfo.Inspect(issued.CertificatePEM)
	if err != nil {
		t.Fatalf("seed inspect: %v", err)
	}
	nb, na := info.NotBefore, info.NotAfter
	c, err := s.UpsertCertificate(ctx, store.Certificate{
		TenantID: tenantID, Subject: info.Subject, SANs: info.DNSNames, Issuer: info.Issuer,
		Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint, KeyAlgorithm: info.KeyAlgorithm,
		NotBefore: &nb, NotAfter: &na, Source: "seed",
	})
	if err != nil {
		t.Fatalf("seed Upsert: %v", err)
	}
	return c
}

func countOutbox(t *testing.T, s *store.Store, tenantID, destination string) int {
	t.Helper()
	pending, err := orchestrator.NewOutbox(s).Pending(context.Background(), tenantID)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range pending {
		if e.Destination == destination {
			n++
		}
	}
	return n
}

// TestCertificateAutoRenewsAtThreshold is the acceptance "a cert auto-renews at
// threshold": a certificate inside the renewal window is renewed — a new
// credential is issued and linked, and the old one is retired.
func TestCertificateAutoRenewsAtThreshold(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	m, svc := newLifecycleManager(t, s, lifecycle.Config{RenewBefore: 24 * time.Hour, AlertBefore: 7 * 24 * time.Hour, TTL: 90 * 24 * time.Hour})

	old := seedInventoryCert(t, s, svc, tenantA, "renew.acme.test", 1*time.Hour) // within 24h window

	n, err := m.RenewExpiring(ctx, tenantA)
	if err != nil {
		t.Fatalf("RenewExpiring: %v", err)
	}
	if n != 1 {
		t.Fatalf("renewed %d certs, want 1", n)
	}

	// The old certificate is retired (superseded) and stamped.
	got, err := s.GetCertificate(ctx, tenantA, old.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "superseded" || got.RenewedAt == nil {
		t.Errorf("old cert status=%q renewed_at=%v, want superseded + stamped", got.Status, got.RenewedAt)
	}

	// A successor exists: active, links back to the old cert, distinct serial,
	// far-future expiry.
	all, err := s.ListCertificatesPage(ctx, tenantA, store.ZeroUUID, 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	var succ *store.Certificate
	for i := range all {
		if all[i].ReplacesID != nil && *all[i].ReplacesID == old.ID {
			succ = &all[i]
		}
	}
	if succ == nil {
		t.Fatal("no successor certificate links to the old one")
	}
	if succ.Status != "active" {
		t.Errorf("successor status = %q, want active", succ.Status)
	}
	if succ.Serial == old.Serial {
		t.Errorf("successor reused the old serial %s", succ.Serial)
	}
	if succ.NotAfter == nil || !succ.NotAfter.After(time.Now().Add(30*24*time.Hour)) {
		t.Errorf("successor not_after = %v, want far future", succ.NotAfter)
	}
}

// TestRevocationPropagates is the acceptance "revocation propagates": a revoked
// certificate is marked revoked and a revocation.publish intent is enqueued on
// the outbox (AN-6), idempotently.
func TestRevocationPropagates(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	m, svc := newLifecycleManager(t, s, lifecycle.Config{RenewBefore: 24 * time.Hour, AlertBefore: 7 * 24 * time.Hour, TTL: 90 * 24 * time.Hour})

	old := seedInventoryCert(t, s, svc, tenantA, "revoke.acme.test", 720*time.Hour)

	if err := m.Revoke(ctx, tenantA, old.ID, "keyCompromise", "rev-1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	got, err := s.GetCertificate(ctx, tenantA, old.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "revoked" || got.RevokedAt == nil || got.RevocationReason != "keyCompromise" {
		t.Errorf("revoked cert = {status:%q revoked_at:%v reason:%q}", got.Status, got.RevokedAt, got.RevocationReason)
	}
	if c := countOutbox(t, s, tenantA, "revocation.publish"); c != 1 {
		t.Errorf("revocation.publish outbox entries = %d, want 1", c)
	}

	// A retried revoke under the same key does not enqueue a second propagation.
	if err := m.Revoke(ctx, tenantA, old.ID, "keyCompromise", "rev-1"); err != nil {
		t.Fatalf("replay Revoke: %v", err)
	}
	if c := countOutbox(t, s, tenantA, "revocation.publish"); c != 1 {
		t.Errorf("after replay, revocation.publish entries = %d, want 1", c)
	}
}

// TestRotationProducesNewCredentialAndRetiresOld is the acceptance "rotation
// produces a new credential and retires the old".
func TestRotationProducesNewCredentialAndRetiresOld(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	m, svc := newLifecycleManager(t, s, lifecycle.Config{RenewBefore: 24 * time.Hour, AlertBefore: 7 * 24 * time.Hour, TTL: 90 * 24 * time.Hour})

	old := seedInventoryCert(t, s, svc, tenantA, "rotate.acme.test", 720*time.Hour) // not near expiry

	fresh, err := m.Rotate(ctx, tenantA, old.ID, "rot-1")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if fresh.ID == "" || len(fresh.SANs) == 0 {
		t.Fatalf("rotated cert = %+v", fresh)
	}
	if fresh.Status != "active" {
		t.Errorf("new credential status = %q, want active", fresh.Status)
	}
	if fresh.ReplacesID == nil || *fresh.ReplacesID != old.ID {
		t.Errorf("new credential replaces_id = %v, want %s", fresh.ReplacesID, old.ID)
	}
	if fresh.Serial == old.Serial {
		t.Errorf("rotation reused the old serial %s", fresh.Serial)
	}

	got, err := s.GetCertificate(ctx, tenantA, old.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "superseded" || got.RenewedAt == nil {
		t.Errorf("old cert after rotation = {status:%q renewed_at:%v}, want superseded + stamped", got.Status, got.RenewedAt)
	}
}

// TestExpiryAlertsFireBeforeExpiry is the acceptance "alerts fire before expiry":
// a cert inside the alert window raises an alert on the notification surface; a
// cert outside the window does not; re-running does not re-alert.
func TestExpiryAlertsFireBeforeExpiry(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	m, svc := newLifecycleManager(t, s, lifecycle.Config{RenewBefore: 1 * time.Hour, AlertBefore: 7 * 24 * time.Hour, TTL: 90 * 24 * time.Hour})

	soon := seedInventoryCert(t, s, svc, tenantA, "soon.acme.test", 72*time.Hour)      // 3d: inside 7d window
	later := seedInventoryCert(t, s, svc, tenantA, "later.acme.test", 60*24*time.Hour) // 60d: outside

	n, err := m.AlertExpiring(ctx, tenantA)
	if err != nil {
		t.Fatalf("AlertExpiring: %v", err)
	}
	if n != 1 {
		t.Fatalf("alerted %d certs, want 1", n)
	}
	if c := countOutbox(t, s, tenantA, notify.DestinationExpiry); c != 1 {
		t.Fatalf("%s outbox entries = %d, want 1", notify.DestinationExpiry, c)
	}

	// The alert is for the soon-expiring cert, and the cert is stamped.
	pending, _ := orchestrator.NewOutbox(s).Pending(ctx, tenantA)
	var alerted notify.Alert
	for _, e := range pending {
		if e.Destination == notify.DestinationExpiry {
			if err := json.Unmarshal(e.Payload, &alerted); err != nil {
				t.Fatalf("decode alert: %v", err)
			}
		}
	}
	if alerted.CertificateID != soon.ID {
		t.Errorf("alert is for %s, want soon cert %s", alerted.CertificateID, soon.ID)
	}
	gotSoon, _ := s.GetCertificate(ctx, tenantA, soon.ID)
	if gotSoon.AlertedAt == nil {
		t.Error("soon cert was not stamped alerted_at")
	}
	gotLater, _ := s.GetCertificate(ctx, tenantA, later.ID)
	if gotLater.AlertedAt != nil {
		t.Error("later cert (outside window) should not be alerted")
	}

	// Re-running does not re-alert (idempotent surface).
	n2, err := m.AlertExpiring(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 0 {
		t.Errorf("second AlertExpiring alerted %d, want 0", n2)
	}
	if c := countOutbox(t, s, tenantA, notify.DestinationExpiry); c != 1 {
		t.Errorf("after re-run, %s entries = %d, want 1", notify.DestinationExpiry, c)
	}
}
