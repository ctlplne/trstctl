package pkisecret_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca/revocation"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/pkisecret"
)

// recordingSink is an in-process RevocationSink double that records issuance and
// revocation, modeling the event-sourced revocation pipeline (revocation.Service)
// without standing up Postgres/NATS. revoked() captures whether a serial was
// recorded revoked and the reason code, which is what a real CRL/OCSP responder
// then reflects.
type recordingSink struct {
	mu      sync.Mutex
	issued  map[string]bool
	revoked map[string]int // serial -> reason code
}

func newRecordingSink() *recordingSink {
	return &recordingSink{issued: map[string]bool{}, revoked: map[string]int{}}
}

func (s *recordingSink) RecordIssued(_ context.Context, _, _, serial string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issued[serial] = true
	return nil
}

func (s *recordingSink) Revoke(_ context.Context, _, _, serial string, reason int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[serial] = reason
	return nil
}

func (s *recordingSink) isRevoked(serial string) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.revoked[serial]
	return r, ok
}

func (s *recordingSink) wasIssued(serial string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.issued[serial]
}

func caFixture(t *testing.T) ([]byte, crypto.DigestSigner) {
	t.Helper()
	k, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Destroy)
	der, _ := crypto.SelfSignedCACert(k, "PKI Secrets CA", time.Hour)
	return der, k
}

// TestRevokeIsRecordedOnPipeline is the GAP-005 acceptance: when a revocation sink
// is wired, revoking a leased certificate records its real serial on the
// event-sourced revocation pipeline (the serial a CRL/OCSP responder reflects),
// rather than only deleting an in-memory map entry. Pre-fix Revoke was a bare
// `delete(p.live, serial)` that recorded nothing, so this fails; post-fix the
// serial is recorded revoked with a real reason code.
func TestRevokeIsRecordedOnPipeline(t *testing.T) {
	caDER, caKey := caFixture(t)
	sink := newRecordingSink()
	prof := pkisecret.Profile{Name: "web", MaxTTL: time.Hour}
	p := pkisecret.NewPKIProvider(caDER, caKey, prof, nil,
		pkisecret.WithRevocationSink("t1", "ca-1", sink))

	ctx := context.Background()
	cred, err := p.Generate(ctx, dynsecret.GenerateRequest{Role: "web.example", TTL: time.Hour})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	serial := cred.BackendRef
	if !sink.wasIssued(serial) {
		t.Fatalf("issued serial %q was not recorded on the revocation pipeline", serial)
	}
	if _, ok := sink.isRevoked(serial); ok {
		t.Fatal("serial recorded revoked before Revoke was called")
	}

	if err := p.Revoke(ctx, serial); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	reason, ok := sink.isRevoked(serial)
	if !ok {
		t.Fatalf("after Revoke the serial %q was NOT recorded on the revocation pipeline (GAP-005)", serial)
	}
	if reason == 0 {
		t.Errorf("revocation recorded with reason 0; want a real CRLReason")
	}
	// And it is no longer live locally.
	if p.IsLive(serial) {
		t.Error("serial still live after Revoke")
	}
}

// TestRevokeViaLeaseEngineRecordsOnPipeline proves the end-to-end path the secrets
// API actually drives: a lease expiry → engine RunRevocations → provider.Revoke
// places the certificate serial on the revocation pipeline (event-sourced), so a
// revoked dynamic-secret certificate is genuinely invalidated, not just dropped
// from memory.
func TestRevokeViaLeaseEngineRecordsOnPipeline(t *testing.T) {
	caDER, caKey := caFixture(t)
	sink := newRecordingSink()
	p := pkisecret.NewPKIProvider(caDER, caKey, pkisecret.Profile{Name: "web", MaxTTL: time.Hour}, nil,
		pkisecret.WithRevocationSink("t1", "ca-1", sink))
	eng, err := dynsecret.New(dynsecret.Config{TenantID: "t1", Providers: []dynsecret.Provider{p}, Queue: dynsecret.NewMemoryQueue()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	lease, _, err := eng.Issue(ctx, "pki", "web.example", time.Minute, "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	serial := lease.BackendRef

	// Expire the lease and drain the revocation queue (the durable AN-6 path).
	if _, err := eng.ExpireDue(ctx, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.RunRevocations(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := sink.isRevoked(serial); !ok {
		t.Fatalf("lease-expiry revocation did not reach the revocation pipeline for serial %q (GAP-005)", serial)
	}
}

// TestRevocationServiceSatisfiesSink binds the library seam to the REAL served
// revocation pipeline: revocation.Service (which writes the store-backed CRL/OCSP
// and emits a ca.certificate.revoked event, AN-2) satisfies pkisecret.RevocationSink.
// So WithRevocationSink wires the genuine served revocation path, not just a
// test double — a revoked dynamic-secret certificate stops validating exactly as a
// directly-issued one does (CORRECT-001 at the library level). If the signatures
// drift, this fails to compile.
func TestRevocationServiceSatisfiesSink(t *testing.T) {
	var _ pkisecret.RevocationSink = (*revocation.Service)(nil)
}

// TestRevokeWithoutSinkStillIdempotent: a bare embed with no sink falls back to the
// in-memory liveness set; Revoke must remain idempotent and not error (the
// conformance suite relies on a safe double-revoke).
func TestRevokeWithoutSinkStillIdempotent(t *testing.T) {
	caDER, caKey := caFixture(t)
	p := pkisecret.NewPKIProvider(caDER, caKey, pkisecret.Profile{Name: "any", MaxTTL: time.Hour}, nil)
	ctx := context.Background()
	cred, err := p.Generate(ctx, dynsecret.GenerateRequest{Role: "x.example", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Revoke(ctx, cred.BackendRef); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := p.Revoke(ctx, cred.BackendRef); err != nil {
		t.Fatalf("double Revoke not idempotent: %v", err)
	}
}
