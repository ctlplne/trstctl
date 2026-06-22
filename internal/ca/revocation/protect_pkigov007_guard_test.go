package revocation

import (
	"os"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/projections"
)

// PKIGOV-007 (19-PKIGOV) PROTECT regression guard.
//
// Confirmed strength: the revocation governance machinery is intact — Revoke emits an
// immutable ca.certificate.revoked event (AN-2), the OCSP responder answers on a
// BOUNDED bulkhead pool (AN-7, so an OCSP flood cannot starve the API), and
// GenerateCRL publishes a CRL (recorded as a ca.crl.published event). Anchor:
// internal/ca/revocation/revocation.go.
//
// Part 1 is BEHAVIORAL on the real wiring with NO Postgres/NATS/network: the package's
// default pool sizing is bounded (positive workers + queue), an injected bulkhead pool
// is the one the Service runs OCSP on, and the event-type constants the Service emits
// are the governance events expected. Part 2 is an ANCHOR-LOCK over revocation.go for
// the revoked-event emit, the pool-submit OCSP path, and the CRL publish. If the OCSP
// path stops being bounded, or the revoked/CRL events stop being emitted, this guard
// goes RED.
func TestProtectPKIGOV007_BoundedPoolAndGovernanceEvents(t *testing.T) {
	// The default OCSP pool is bounded: a positive worker count and a finite, positive
	// queue mean a flood fast-rejects instead of growing unbounded (AN-7).
	if defaultWorkers <= 0 {
		t.Errorf("PKIGOV-007: defaultWorkers = %d, want > 0; the OCSP responder must run on a bounded worker pool", defaultWorkers)
	}
	if defaultQueue <= 0 {
		t.Errorf("PKIGOV-007: defaultQueue = %d, want > 0 (finite); an unbounded OCSP queue defeats the bulkhead", defaultQueue)
	}

	// An injected pool is the one the Service uses (so OCSP submission is bounded by the
	// caller's bulkhead). Build a real pool — pure in-memory, no external deps.
	pool := bulkhead.New(bulkhead.Config{Name: "ocsp-guard", Workers: 1, Queue: 1})
	defer pool.Close()
	svc := New(nil, nil, nil, WithPool(pool))
	if svc.pool != pool {
		t.Fatal("PKIGOV-007: WithPool did not bind the injected bulkhead pool; the OCSP responder may not run bounded")
	}
	if svc.ownPool {
		t.Error("PKIGOV-007: Service marked an injected pool as owned; it must not close a caller-provided pool")
	}

	// The governance event types the Service emits must be the immutable
	// revoked/published facts (AN-2). Lock their wire values.
	if projections.EventCACertificateRevoked != "ca.certificate.revoked" {
		t.Errorf("PKIGOV-007: EventCACertificateRevoked = %q, want \"ca.certificate.revoked\"; the revoked governance event changed", projections.EventCACertificateRevoked)
	}
	if projections.EventCRLPublished != "ca.crl.published" {
		t.Errorf("PKIGOV-007: EventCRLPublished = %q, want \"ca.crl.published\"; the CRL-published governance event changed", projections.EventCRLPublished)
	}
}

func TestProtectPKIGOV007_RevocationMachineryAnchor(t *testing.T) {
	src, err := os.ReadFile("revocation.go")
	if err != nil {
		t.Fatalf("PKIGOV-007 anchor: cannot read revocation.go: %v", err)
	}
	body := string(src)
	for _, needle := range []string{
		"func (s *Service) Revoke(",                   // the revoke entrypoint
		"projections.EventCACertificateRevoked",       // emits the immutable revoked event (AN-2)
		"func (s *Service) OCSP(",                     // the OCSP responder
		"s.pool.Submit(func() {",                      // OCSP runs on the bounded bulkhead (AN-7)
		"func (s *Service) GenerateCRL(",              // CRL generation
		"projections.EventCRLPublished",               // CRL publish recorded as an event (AN-2)
		"ca.SignOCSP(",                                // OCSP responses are signed through the CA boundary (AN-3)
		"ca.CreateCRL(",                               // CRL signed through the CA boundary
		"bulkhead.New(bulkhead.Config{Name: \"ocsp\"", // the default bounded pool when none injected
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("PKIGOV-007: revocation.go no longer contains %q; the revoked-event / bounded-OCSP / CRL-publish governance machinery may have regressed", needle)
		}
	}

	// Lock that OCSP submission goes through the pool BEFORE awaiting a result — i.e.
	// the bounded submit is the gate, not an afterthought. The Submit call must precede
	// the result receive.
	ocspIdx := strings.Index(body, "func (s *Service) OCSP(")
	if ocspIdx < 0 {
		t.Fatalf("PKIGOV-007: OCSP method missing; re-point this guard")
	}
	ocspBody := body[ocspIdx:]
	submitIdx := strings.Index(ocspBody, "s.pool.Submit(")
	recvIdx := strings.Index(ocspBody, "case r := <-ch:")
	if submitIdx < 0 || recvIdx < 0 || !(submitIdx < recvIdx) {
		t.Error("PKIGOV-007: OCSP no longer submits to the bounded pool before awaiting the response; the AN-7 backpressure gate on OCSP is broken")
	}
}
