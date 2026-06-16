package projections_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/lifecycle"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
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
	m, svc, _ := newLifecycleManagerWithLog(t, s, cfg)
	return m, svc
}

// newLifecycleManagerWithLog is newLifecycleManager but also returns the shared
// event log, so an event-sourcing test can Rebuild the read model from the very
// log the Manager appended to (CORRECT-002).
func newLifecycleManagerWithLog(t *testing.T, s *store.Store, cfg lifecycle.Config) (*lifecycle.Manager, *ca.IssuanceService, *events.Log) {
	t.Helper()
	builtin, err := ca.NewBuiltin("trstctl Built-in CA")
	if err != nil {
		t.Fatal(err)
	}
	idem := orchestrator.NewIdempotency(s)
	ob := orchestrator.NewOutbox(s)
	svc := ca.NewIssuanceService(builtin, idem, ob, s)
	log := openLog(t)
	return lifecycle.NewManager(s, svc, ob, idem, log, cfg), svc, log
}

// seedInventoryCertEventSourced issues a real certificate and inventories it
// through the event-sourced command path (orchestrator.RecordCertificate emits a
// certificate.recorded event and projects it), so the row is reconstructable from
// the log on a Rebuild() — unlike seedInventoryCert, which writes the read table
// directly. CORRECT-002 tests that Rebuild from this log preserves later status
// transitions, so the seed itself must be event-sourced too.
func seedInventoryCertEventSourced(t *testing.T, s *store.Store, svc *ca.IssuanceService, log *events.Log, tenantID, cn string, ttl time.Duration) store.Certificate {
	t.Helper()
	ctx := context.Background()
	issued, err := svc.Issue(ctx, ca.IssueRequest{TenantID: tenantID, CSR: lifecycleCSR(t, cn), DNSNames: []string{cn}, TTL: ttl}, "seed-es:"+tenantID+":"+cn)
	if err != nil {
		t.Fatalf("seed Issue: %v", err)
	}
	info, err := certinfo.Inspect(issued.CertificatePEM)
	if err != nil {
		t.Fatalf("seed inspect: %v", err)
	}
	orch := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))
	nb, na := info.NotBefore, info.NotAfter
	c, err := orch.RecordCertificate(ctx, tenantID, store.Certificate{
		Subject: info.Subject, SANs: info.DNSNames, Issuer: info.Issuer,
		Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint, KeyAlgorithm: info.KeyAlgorithm,
		NotBefore: &nb, NotAfter: &na, Source: "seed",
	})
	if err != nil {
		t.Fatalf("seed RecordCertificate: %v", err)
	}
	return c
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
	all, err := s.ListCertificatesPage(ctx, tenantA, store.ZeroUUID, nil, 100, nil)
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

// TestRevokedStatusSurvivesRebuild is the CORRECT-002 acceptance: a revoked
// certificate's status must be event-sourced, so re-deriving the read model from
// the log (Projector.Rebuild) leaves it revoked. Before the fix the lifecycle
// Manager UPDATE-d the read table directly and emitted a certificate.revoked event
// the projector ignored, so Rebuild() reverted the status to active — this test
// FAILS on the pre-fix tree.
func TestRevokedStatusSurvivesRebuild(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	m, svc, log := newLifecycleManagerWithLog(t, s, lifecycle.Config{RenewBefore: 24 * time.Hour, AlertBefore: 7 * 24 * time.Hour, TTL: 90 * 24 * time.Hour})

	cert := seedInventoryCertEventSourced(t, s, svc, log, tenantA, "revoke-rebuild.acme.test", 720*time.Hour)

	if err := m.Revoke(ctx, tenantA, cert.ID, "keyCompromise", "rev-rb-1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	got, err := s.GetCertificate(ctx, tenantA, cert.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "revoked" || got.RevokedAt == nil || got.RevocationReason != "keyCompromise" {
		t.Fatalf("after Revoke = {status:%q revoked_at:%v reason:%q}, want revoked+stamped", got.Status, got.RevokedAt, got.RevocationReason)
	}

	// Re-derive the read model from the log. If revocation were a direct read-table
	// UPDATE (the pre-fix behavior), this would erase it; an event-sourced
	// revocation is replayed from the log.
	if err := projections.New(s).Rebuild(ctx, log); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	after, err := s.GetCertificateByFingerprint(ctx, tenantA, cert.Fingerprint)
	if err != nil {
		t.Fatalf("GetCertificateByFingerprint after rebuild: %v", err)
	}
	if after.Status != "revoked" {
		t.Errorf("after Rebuild status = %q, want revoked (revocation is not event-sourced)", after.Status)
	}
	if after.RevocationReason != "keyCompromise" {
		t.Errorf("after Rebuild reason = %q, want keyCompromise", after.RevocationReason)
	}
	if after.RevokedAt == nil {
		t.Error("after Rebuild revoked_at is nil; the revoked timestamp was lost")
	}
}

// TestSupersededStatusAndSuccessorLinkSurviveRebuild is the CORRECT-002 acceptance
// for rotation/renewal: after a rotation, the predecessor is superseded and the
// successor links back via replaces_id; both facts must be event-sourced and so
// survive a Projector.Rebuild(). Pre-fix the predecessor's superseded status came
// from a direct UPDATE and the certificate.rotated event had no projector case,
// so Rebuild() reverted the predecessor to active and dropped the successor row
// (it had been a direct insert) — this test FAILS on the pre-fix tree.
func TestSupersededStatusAndSuccessorLinkSurviveRebuild(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	m, svc, log := newLifecycleManagerWithLog(t, s, lifecycle.Config{RenewBefore: 24 * time.Hour, AlertBefore: 7 * 24 * time.Hour, TTL: 90 * 24 * time.Hour})

	old := seedInventoryCertEventSourced(t, s, svc, log, tenantA, "rotate-rebuild.acme.test", 720*time.Hour)

	fresh, err := m.Rotate(ctx, tenantA, old.ID, "rot-rb-1")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if fresh.ReplacesID == nil || *fresh.ReplacesID != old.ID {
		t.Fatalf("successor replaces_id = %v, want %s", fresh.ReplacesID, old.ID)
	}

	// Rebuild the read model purely from the log.
	if err := projections.New(s).Rebuild(ctx, log); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}

	// The predecessor must still be superseded.
	gotOld, err := s.GetCertificateByFingerprint(ctx, tenantA, old.Fingerprint)
	if err != nil {
		t.Fatalf("get predecessor after rebuild: %v", err)
	}
	if gotOld.Status != "superseded" {
		t.Errorf("after Rebuild predecessor status = %q, want superseded", gotOld.Status)
	}
	if gotOld.RenewedAt == nil {
		t.Error("after Rebuild predecessor renewed_at is nil; the supersession stamp was lost")
	}

	// The successor must still exist and still link to the predecessor.
	gotNew, err := s.GetCertificateByFingerprint(ctx, tenantA, fresh.Fingerprint)
	if err != nil {
		t.Fatalf("successor missing after rebuild (not event-sourced): %v", err)
	}
	if gotNew.Status != "active" {
		t.Errorf("after Rebuild successor status = %q, want active", gotNew.Status)
	}
	if gotNew.ReplacesID == nil || *gotNew.ReplacesID != old.ID {
		t.Errorf("after Rebuild successor replaces_id = %v, want %s (link lost)", gotNew.ReplacesID, old.ID)
	}
}
