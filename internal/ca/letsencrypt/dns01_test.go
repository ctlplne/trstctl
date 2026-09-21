// SPDX-License-Identifier: BUSL-1.1

package letsencrypt_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/letsencrypt"
	"trstctl.com/trstctl/internal/ca/letsencrypt/acmefake"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/acmekey"
)

// Unattended domain validation on the UPSTREAM client (epic B7).
//
// Every issuance test before this one ran against a pre-authorized order, so a
// solver that did nothing passed them all — which is exactly how the upstream
// path shipped unable to validate at all. These run against an authority that
// issues PENDING orders with a real dns-01 challenge, so an order only
// completes if a record was actually published.

// recordingSolver stands in for the served DNS-01 automation. It records what
// it was asked to publish and whether the record was retracted.
type recordingSolver struct {
	mu        sync.Mutex
	solved    []acmekey.ChallengeRequest
	retracted int
	failWith  error
	types     []string
}

func (s *recordingSolver) SolvableChallenges() []string {
	if len(s.types) > 0 {
		return s.types
	}
	return []string{acmekey.ChallengeDNS01}
}

func (s *recordingSolver) Solve(_ context.Context, req acmekey.ChallengeRequest) (func(context.Context) error, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failWith != nil {
		return nil, s.failWith
	}
	s.solved = append(s.solved, req)
	return func(context.Context) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.retracted++
		return nil
	}, nil
}

func (s *recordingSolver) snapshot() ([]acmekey.ChallengeRequest, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]acmekey.ChallengeRequest(nil), s.solved...), s.retracted
}

// The whole loop: a pending order, a dns-01 challenge, a solver that publishes,
// and a certificate that only exists because validation happened.
func TestUpstreamIssuanceSolvesDNS01Unattended(t *testing.T) {
	srv, err := acmefake.NewServer()
	if err != nil {
		t.Fatalf("start ACME double: %v", err)
	}
	t.Cleanup(srv.Close)
	srv.RequireDomainValidation("dv.example.test", false)

	solver := &recordingSolver{}
	plugin := newSolvingPlugin(t, srv.DirectoryURL(), solver)

	issued, err := plugin.Issue(context.Background(), ca.IssueRequest{
		TenantID: "tenant-a",
		CSR:      buildCSR(t, "dv.example.test", []string{"dv.example.test"}),
		DNSNames: []string{"dv.example.test"},
	})
	if err != nil {
		t.Fatalf("issue with DV required: %v", err)
	}
	if len(issued.CertificatePEM) == 0 {
		t.Fatal("no certificate issued")
	}

	solved, retracted := solver.snapshot()
	if len(solved) != 1 {
		t.Fatalf("the solver was asked to publish %d records, want 1 — an order that completed "+
			"without one did not validate anything", len(solved))
	}
	if solved[0].Type != acmekey.ChallengeDNS01 {
		t.Errorf("solved challenge type = %q, want dns-01", solved[0].Type)
	}
	if solved[0].TenantID != "tenant-a" {
		t.Errorf("solver received tenant %q; without the tenant it cannot select a provider "+
			"config under RLS", solved[0].TenantID)
	}
	if solved[0].KeyAuth == "" {
		t.Error("solver received no key authorization, so it has nothing to publish")
	}
	if srv.ChallengeAccepts() != 1 {
		t.Errorf("the authority saw %d challenge accepts, want 1", srv.ChallengeAccepts())
	}
	// The record is retracted afterward. A validation token left live in
	// public DNS is a real leak of estate structure.
	if retracted != 1 {
		t.Errorf("the published record was retracted %d times, want 1 — a TXT record left "+
			"behind stays in public DNS indefinitely", retracted)
	}
}

// Wildcards are the case that CANNOT work over http-01. The identifier reaches
// the solver with its "*." intact, because a solver enforcing a wildcard policy
// has to be able to see the wildcard.
func TestUpstreamWildcardIssuanceReachesTheSolverAsAWildcard(t *testing.T) {
	srv, err := acmefake.NewServer()
	if err != nil {
		t.Fatalf("start ACME double: %v", err)
	}
	t.Cleanup(srv.Close)
	srv.RequireDomainValidation("wild.example.test", true)

	solver := &recordingSolver{}
	plugin := newSolvingPlugin(t, srv.DirectoryURL(), solver)

	if _, err := plugin.Issue(context.Background(), ca.IssueRequest{
		TenantID: "tenant-a",
		CSR:      buildCSR(t, "*.wild.example.test", []string{"*.wild.example.test"}),
		DNSNames: []string{"*.wild.example.test"},
	}); err != nil {
		t.Fatalf("wildcard issue: %v", err)
	}
	solved, _ := solver.snapshot()
	if len(solved) != 1 {
		t.Fatalf("solver saw %d challenges, want 1", len(solved))
	}
	if !strings.HasPrefix(solved[0].Identifier, "*.") {
		t.Errorf("solver received identifier %q; the wildcard was stripped before it could apply "+
			"a wildcard policy", solved[0].Identifier)
	}
}

// An authority that requires validation, with no solver configured, must FAIL
// with a reason — not quietly issue nothing, and not appear to succeed.
func TestUpstreamWithoutASolverFailsWithAReason(t *testing.T) {
	srv, err := acmefake.NewServer()
	if err != nil {
		t.Fatalf("start ACME double: %v", err)
	}
	t.Cleanup(srv.Close)
	srv.RequireDomainValidation("nosolver.example.test", false)

	plugin := newRemoteAccountPlugin(t, "letsencrypt", srv.DirectoryURL())
	_, err = plugin.Issue(context.Background(), ca.IssueRequest{
		TenantID: "tenant-a",
		CSR:      buildCSR(t, "nosolver.example.test", []string{"nosolver.example.test"}),
		DNSNames: []string{"nosolver.example.test"},
	})
	if err == nil {
		t.Fatal("issuance succeeded against an authority requiring validation, with no solver")
	}
	if !strings.Contains(err.Error(), "no domain-validation solver") {
		t.Errorf("error = %v; an operator needs to know the cause is a missing solver rather "+
			"than a transient upstream failure", err)
	}
	if srv.ChallengeAccepts() != 0 {
		t.Error("a challenge was accepted with no solver configured")
	}
}

// A solver that cannot publish must not leave the order half-done, and the
// record must be retracted on the failure path too.
func TestUpstreamPublishFailureIsReportedAndNothingIsAccepted(t *testing.T) {
	srv, err := acmefake.NewServer()
	if err != nil {
		t.Fatalf("start ACME double: %v", err)
	}
	t.Cleanup(srv.Close)
	srv.RequireDomainValidation("fail.example.test", false)

	solver := &recordingSolver{failWith: errors.New("provider refused")}
	plugin := newSolvingPlugin(t, srv.DirectoryURL(), solver)

	if _, err := plugin.Issue(context.Background(), ca.IssueRequest{
		TenantID: "tenant-a",
		CSR:      buildCSR(t, "fail.example.test", []string{"fail.example.test"}),
		DNSNames: []string{"fail.example.test"},
	}); err == nil {
		t.Fatal("issuance succeeded although the record could not be published")
	}
	if srv.ChallengeAccepts() != 0 {
		t.Error("a challenge was accepted although nothing was published — the authority would " +
			"have validated against a record that does not exist")
	}
}

// An authority offering only a challenge type this deployment cannot solve is
// refused with both lists, so an operator can see the mismatch.
func TestUpstreamRefusesWhenNoOfferedChallengeIsSolvable(t *testing.T) {
	srv, err := acmefake.NewServer()
	if err != nil {
		t.Fatalf("start ACME double: %v", err)
	}
	t.Cleanup(srv.Close)
	srv.RequireDomainValidation("mismatch.example.test", false)

	// The double offers dns-01; this solver only does http-01.
	solver := &recordingSolver{types: []string{acmekey.ChallengeHTTP01}}
	plugin := newSolvingPlugin(t, srv.DirectoryURL(), solver)

	_, err = plugin.Issue(context.Background(), ca.IssueRequest{
		TenantID: "tenant-a",
		CSR:      buildCSR(t, "mismatch.example.test", []string{"mismatch.example.test"}),
		DNSNames: []string{"mismatch.example.test"},
	})
	if err == nil {
		t.Fatal("issuance succeeded with no solvable challenge")
	}
	if !strings.Contains(err.Error(), "no challenge this deployment can solve") {
		t.Errorf("error = %v, want the no-solvable-challenge classification", err)
	}
}

func newSolvingPlugin(t *testing.T, directoryURL string, solver acmekey.ChallengeSolver, extra ...letsencrypt.Option) *letsencrypt.Plugin {
	t.Helper()
	account, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(account.Destroy)
	opts := append([]letsencrypt.Option{letsencrypt.WithChallengeSolver(solver)}, extra...)
	plugin, err := letsencrypt.NewPluginWithRemoteAccountSigner(
		"letsencrypt", directoryURL, http.DefaultClient, account, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(plugin.Destroy)
	return plugin
}

// A revalidation cycle shorter than the certificate lifetime runs with no
// operator step (epic B7 acceptance).
//
// This is the criterion the compressing CA/Browser Forum reuse window actually
// imposes. Issuing once unattended is not the same as staying issued: the
// second issuance is the one that fails when the solver depends on state left
// over from the first — a retracted record it assumed was still live, a token
// it cached, an authorization it expected to be reused. So the authority here
// requires validation EVERY time, which is the shape a compressed window takes,
// and both cycles must publish and retract on their own.
func TestUpstreamRevalidationCycleNeedsNoOperatorStep(t *testing.T) {
	srv, err := acmefake.NewServer()
	if err != nil {
		t.Fatalf("start ACME double: %v", err)
	}
	t.Cleanup(srv.Close)
	srv.RequireDomainValidation("renew.example.test", false)

	solver := &recordingSolver{}
	plugin := newSolvingPlugin(t, srv.DirectoryURL(), solver)

	for cycle := 1; cycle <= 2; cycle++ {
		issued, err := plugin.Issue(context.Background(), ca.IssueRequest{
			TenantID: "tenant-a",
			CSR:      buildCSR(t, "renew.example.test", []string{"renew.example.test"}),
			DNSNames: []string{"renew.example.test"},
		})
		if err != nil {
			t.Fatalf("revalidation cycle %d: %v — the second cycle failing is the failure mode "+
				"this test exists for: it is the one an operator meets in production, weeks "+
				"after the first success made the feature look done", cycle, err)
		}
		if len(issued.CertificatePEM) == 0 {
			t.Fatalf("revalidation cycle %d issued no certificate", cycle)
		}
	}

	solved, retracted := solver.snapshot()
	if len(solved) != 2 {
		t.Fatalf("the solver published %d records across two revalidation cycles, want 2 — a "+
			"second cycle that published nothing rode an authorization it will not always have",
			len(solved))
	}
	// Each cycle cleans up after itself. A solver that retracts only once has
	// left a live validation token in public DNS for every cycle but the last.
	if retracted != 2 {
		t.Errorf("records retracted = %d across two cycles, want 2; a token left live in public "+
			"DNS after validation discloses estate structure and never expires on its own",
			retracted)
	}
	if srv.ChallengeAccepts() != 2 {
		t.Errorf("the authority saw %d challenge accepts across two cycles, want 2",
			srv.ChallengeAccepts())
	}
}

// recordingObserver captures every authorization outcome the driver reports.
type recordingObserver struct {
	mu  sync.Mutex
	out []acmekey.DVOutcome
}

func (o *recordingObserver) ObserveAuthorization(_ context.Context, _ string, out acmekey.DVOutcome) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.out = append(o.out, out)
}

func (o *recordingObserver) snapshot() []acmekey.DVOutcome {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]acmekey.DVOutcome(nil), o.out...)
}

// A fully-reused order must still be OBSERVED (epic B7).
//
// This is the case the staleness surface exists for, and it was the one case
// that recorded nothing. When the authority already considers every identifier
// authorized it returns the order ready, so no challenge is solved and the
// solve path — where reuse was reported — never runs.
//
// The install this describes is the dangerous one: its validation path may have
// been broken for months, and nothing fails until the reuse window closes, at
// which point every identifier authorized in the same original burst fails on
// the same day. Recording nothing for it left the console panel empty, which an
// operator reads as "no problems" — the exact inversion of the truth.
func TestFullyReusedOrderIsStillObserved(t *testing.T) {
	srv, err := acmefake.NewServer()
	if err != nil {
		t.Fatalf("start ACME double: %v", err)
	}
	t.Cleanup(srv.Close)
	// No RequireDomainValidation: the authority hands back a ready order, which
	// is what a reused authorization looks like from the client side.

	solver := &recordingSolver{}
	observer := &recordingObserver{}
	plugin := newSolvingPlugin(t, srv.DirectoryURL(), solver, letsencrypt.WithDVObserver(observer))

	if _, err := plugin.Issue(context.Background(), ca.IssueRequest{
		TenantID: "tenant-a",
		CSR:      buildCSR(t, "reused.example.test", []string{"reused.example.test"}),
		DNSNames: []string{"reused.example.test"},
	}); err != nil {
		t.Fatalf("issue against a ready order: %v", err)
	}

	solved, _ := solver.snapshot()
	if len(solved) != 0 {
		t.Fatalf("the solver published %d records for a ready order; nothing should have been "+
			"asked to validate", len(solved))
	}

	observed := observer.snapshot()
	if len(observed) == 0 {
		t.Fatal("a fully-reused order reported no authorization outcome at all, so the staleness " +
			"surface stays empty for the install that most needs it — and an empty panel reads " +
			"as 'nothing is stale'")
	}
	for _, out := range observed {
		if !out.Reused {
			t.Errorf("outcome for %q reports Reused=false, but no challenge was solved",
				out.Identifier)
		}
		if out.Identifier == "" {
			t.Error("an observed outcome names no identifier, so it cannot become a row")
		}
	}
}
