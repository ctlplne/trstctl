// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	acme "trstctl.com/trstctl/internal/protocols/acme"
	"trstctl.com/trstctl/internal/store"
)

// Upstream DV consent is ENFORCED, not merely recorded (epic B7).
//
// The column exists because credentials an operator supplied so trstctl could
// VERIFY a challenge are not consent for trstctl to PUBLISH into that zone
// whenever a public CA asks. A flag that is stored and never checked would be
// worse than none: it would read as a control on the configuration page while
// every zone stayed open.
func TestUpstreamSolverRefusesAConfigThatHasNotConsented(t *testing.T) {
	ctx := context.Background()
	h := newServedHarness(t, config.Protocols{})

	// A provider config created for the SERVER direction: dns-01 is an allowed
	// method, but nobody enabled upstream DV on it.
	seedDNS01Config(t, ctx, h, store.ACMEDNS01ProviderConfig{
		Name: "server-side-only", Provider: "manual", Zone: "example.test",
		AllowedMethods: []string{"dns-01"}, AllowWildcards: true,
		AllowUpstreamDV: false,
	})

	solver := &upstreamACMEDNS01Solver{
		automation:      h.srv.acmeDNS01,
		log:             h.log,
		caaIssuerDomain: "letsencrypt.org",
	}
	_, err := solver.Solve(ctx, acmekey.ChallengeRequest{
		TenantID: h.tenant, Type: acmekey.ChallengeDNS01,
		Identifier: "app.example.test", Token: "tok", KeyAuth: "tok.thumb",
	})
	if err == nil {
		t.Fatal("the solver published a record using a config that never consented to upstream " +
			"domain validation; the consent flag is decoration")
	}
	if !strings.Contains(err.Error(), "allow_upstream_dv") {
		t.Errorf("error = %v; it must name the flag an operator has to set, or they cannot act on it", err)
	}
}

// The solver refuses to run at all without the external CA's CAA identifier.
//
// A CAA check against an empty issuer authorizes every issuer while appearing
// to check — the exact shape of control that reads as protection and provides
// none. Refusing is the only honest option, because the alternative is a check
// that always passes.
func TestUpstreamSolverRefusesWithoutTheExternalCAAIssuer(t *testing.T) {
	ctx := context.Background()
	h := newServedHarness(t, config.Protocols{})
	seedDNS01Config(t, ctx, h, store.ACMEDNS01ProviderConfig{
		Name: "consented", Provider: "manual", Zone: "example.test",
		AllowedMethods: []string{"dns-01"}, AllowUpstreamDV: true,
	})

	solver := &upstreamACMEDNS01Solver{automation: h.srv.acmeDNS01, log: h.log}
	_, err := solver.Solve(ctx, acmekey.ChallengeRequest{
		TenantID: h.tenant, Type: acmekey.ChallengeDNS01,
		Identifier: "app.example.test", Token: "tok", KeyAuth: "tok.thumb",
	})
	if err == nil {
		t.Fatal("the solver ran with no CAA issuer domain, so the CAA check authorized anything")
	}
	if !strings.Contains(err.Error(), "CAA issuer domain") {
		t.Errorf("error = %v, want the missing-CAA-issuer reason", err)
	}
}

// The census says dns-01 only, and means it.
//
// http-01 upstream would need an inbound listener on the validated host, which
// this architecture does not have. Advertising it would make the driver select
// it and then fail at publish time — the failure the census discipline exists
// to prevent.
func TestUpstreamSolverAdvertisesOnlyWhatItSolves(t *testing.T) {
	solver := &upstreamACMEDNS01Solver{}
	got := solver.SolvableChallenges()
	if len(got) != 1 || got[0] != acmekey.ChallengeDNS01 {
		t.Fatalf("SolvableChallenges = %v, want [dns-01] only", got)
	}
	if _, err := solver.Solve(context.Background(), acmekey.ChallengeRequest{
		Type: acmekey.ChallengeHTTP01, TenantID: "t", Identifier: "a.test",
	}); err == nil {
		t.Error("the solver accepted an http-01 challenge it cannot solve")
	}
}

// The late-binding holder fails closed before the automation is attached.
//
// The external-CA factories are built before the DNS-01 automation exists, so
// there is a window where the holder is empty. An order arriving in that window
// must fail with the missing-solver reason rather than appear to validate.
func TestUpstreamHolderFailsClosedBeforeItIsFilled(t *testing.T) {
	binding := (&upstreamDVHolder{}).bind("letsencrypt.org", "le")
	if got := binding.SolvableChallenges(); len(got) != 0 {
		t.Errorf("an unfilled holder advertises %v; it can solve nothing yet", got)
	}
	if _, err := binding.Solve(context.Background(), acmekey.ChallengeRequest{
		TenantID: "t", Type: acmekey.ChallengeDNS01, Identifier: "a.test",
	}); err == nil {
		t.Fatal("an unfilled holder solved a challenge")
	}
}

// Each ACME authority validates against its OWN CAA identifier.
//
// The first version of this seam held one solver for the whole process, so a
// second configured ACME CA silently inherited the first one's issuer domain. A
// CAA check that authorizes the wrong CA is the same defect as one that
// authorizes every CA, and harder to see: it passes, and the certificate comes
// from an issuer the domain's policy may exclude.
func TestEachAuthorityBindsItsOwnCAAIssuerDomain(t *testing.T) {
	holder := &upstreamDVHolder{}
	holder.set(&servedACMEDNS01Automation{}, nil)

	le := holder.bind("letsencrypt.org", "le")
	private := holder.bind("pki.example.test", "private")

	if got := le.solver().caaIssuerDomain; got != "letsencrypt.org" {
		t.Errorf("Let's Encrypt binding resolved issuer %q", got)
	}
	if got := private.solver().caaIssuerDomain; got != "pki.example.test" {
		t.Errorf("private ACME binding resolved issuer %q; it inherited another authority's identifier", got)
	}
}

// seedDNS01Config writes a provider config through the store, the way the
// projection does.
func seedDNS01Config(t *testing.T, ctx context.Context, h *servedHarness, cfg store.ACMEDNS01ProviderConfig) {
	t.Helper()
	cfg.TenantID = h.tenant
	if cfg.ID == "" {
		cfg.ID = uuid.NewString()
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return h.store.ApplyACMEDNS01ProviderConfigUpsertedTx(ctx, tx, cfg)
	}); err != nil {
		t.Fatalf("seed dns-01 provider config: %v", err)
	}
}

// The seam is CLOSED by the running server, not merely declared (epic B7).
//
// This is the test the epic actually needed. Every other test here exercises the
// solver directly, which proves the logic and proves nothing about whether the
// binary ever reaches it — and for most of this epic's life it did not: the
// holder the external-CA factories captured at startup was never filled, so an
// upstream order would have failed with "not configured" while every unit test
// passed. That is the same defect shape as a no-op solver, one layer up.
func TestTheRunningServerFillsTheUpstreamDVSeam(t *testing.T) {
	holder := &upstreamDVHolder{}
	binding := holder.bind("letsencrypt.org", "le")

	// Before the server exists the seam fails closed rather than pretending.
	if _, err := binding.Solve(context.Background(), acmekey.ChallengeRequest{
		TenantID: "t", Type: acmekey.ChallengeDNS01, Identifier: "a.test",
	}); err == nil {
		t.Fatal("the seam solved a challenge before any server had filled it")
	}

	newServedHarness(t, config.Protocols{}, func(d *Deps) { d.UpstreamDV = holder })

	if got := binding.SolvableChallenges(); len(got) != 1 || got[0] != acmekey.ChallengeDNS01 {
		t.Fatalf("after the server booted, the seam advertises %v; the running binary never "+
			"attached the DNS-01 automation, so upstream orders would fail as unconfigured", got)
	}
}

// The ACME factory branch that attaches the solver must not quietly disappear.
//
// This one is structural rather than behavioural, and it is worth saying why.
// Exercising the branch for real means standing up an ACME account signer and a
// directory, which the DoD external-CA runtime proof already does at a cost
// this package should not pay per-run. What is cheap and still load-bearing is
// asserting the wiring EXISTS: the letsencrypt case must consult
// item.UpstreamDNS01 and pass a binding to the plugin. If someone deletes those
// lines, every other test here still passes — the solver works, the server
// fills the seam — and no upstream order ever reaches either.
func TestTheACMEFactoryStillAttachesTheSolver(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile("external_ca_config.go")
	if err != nil {
		t.Fatalf("read external_ca_config.go: %v", err)
	}
	for _, want := range []string{
		"item.UpstreamDNS01",
		"upstreamDV.bind(item.CAAIssuerDomain, item.ID)",
		"letsencrypt.WithChallengeSolver(binding)",
		"letsencrypt.WithDVObserver(binding)",
	} {
		if !strings.Contains(string(src), want) {
			t.Errorf("the ACME external-CA factory no longer contains %q, so a configured "+
				"authority gets no challenge solver and upstream domain validation is dead "+
				"wiring that every other test in this file still passes over", want)
		}
	}
}

// The upstream CAA check must actually RUN in a shipped binary (epic B7).
//
// This is the defect an adversarial review found and no test could: the check
// read automation.caaResolver, a field whose only writer in the entire repo is
// a test helper. In production it was always nil, so the check returned nil —
// no lookup, no policy evaluation, publish proceeds — while configuration
// validation went on REQUIRING caa_issuer_domain and telling the operator the
// check "must name the authority that will issue".
//
// A mandatory field naming a control the binary cannot execute is worse than no
// control, and it is the exact failure this file's own comments warn about. The
// served-direction twin, enforceLiveCAA, has always defaulted to a live
// resolver; only the upstream path did not.
//
// Asserting on the resolver rather than on a lookup keeps this test free of
// network I/O while still failing if the defaulting is removed.
func TestUpstreamCAAResolvesEvenWhenNothingInjectedOne(t *testing.T) {
	t.Parallel()

	// Exactly the shape production builds: an automation from the real
	// constructor, which sets store/log/outbox/kek/crypto/plugins and leaves
	// caaResolver nil.
	solver := &upstreamACMEDNS01Solver{
		automation:      &servedACMEDNS01Automation{},
		caaIssuerDomain: "letsencrypt.org",
	}
	if solver.caaResolver() == nil {
		t.Fatal("the upstream CAA check has no resolver when none is injected, so it evaluates " +
			"nothing and every domain's CAA policy is treated as permitting the issuer — while " +
			"config validation tells the operator the check is mandatory")
	}

	// An injected resolver still wins, so tests and any future operator
	// override keep control of what the check talks to.
	injected := &countingCAAResolver{}
	solver.automation.caaResolver = injected
	if got := solver.caaResolver(); got != acme.CAAResolver(injected) {
		t.Errorf("an injected resolver was ignored in favour of the default; %T", got)
	}
}

// countingCAAResolver is a resolver that records use without touching DNS.
type countingCAAResolver struct{ calls int }

func (r *countingCAAResolver) LookupCAA(_ context.Context, _ string) ([]acme.CAARecord, error) {
	r.calls++
	return nil, nil
}

// Selection FILTERS on consent and on the wildcard, rather than checking them
// after the fact (epic B7).
//
// Both flags are per config, and a zone is often covered by more than one. An
// earlier version stripped the "*." before selection — which silently disabled
// the selector's own wildcard filter, since that filter is guarded by
// IsWildcard — and checked consent on whichever config matched first. Either
// mistake fails an order while a config that would have worked sits beside the
// one that was picked.
func TestUpstreamSelectionPicksTheConfigThatCanActuallyDoTheJob(t *testing.T) {
	ctx := context.Background()
	h := newServedHarness(t, config.Protocols{})

	// Two configs for the same zone. The first one listed is the one that
	// cannot do the job: no wildcards, no upstream consent.
	seedDNS01Config(t, ctx, h, store.ACMEDNS01ProviderConfig{
		Name: "aaa-server-side-only", Provider: "manual", Zone: "twoconfigs.test",
		AllowedMethods: []string{"dns-01"}, AllowWildcards: false, AllowUpstreamDV: false,
	})
	seedDNS01Config(t, ctx, h, store.ACMEDNS01ProviderConfig{
		Name: "zzz-upstream-capable", Provider: "manual", Zone: "twoconfigs.test",
		AllowedMethods: []string{"dns-01"}, AllowWildcards: true, AllowUpstreamDV: true,
	})

	cfg, err := h.srv.acmeDNS01.selectProviderConfigForUpstream(ctx, h.tenant, "*.twoconfigs.test")
	if err != nil {
		t.Fatalf("selection failed for a wildcard the tenant has a config for: %v — an order "+
			"failed while a config that would have worked sat beside the one that was picked", err)
	}
	if cfg.Name != "zzz-upstream-capable" {
		t.Errorf("selected %q; selection must filter on consent and wildcard support rather than "+
			"checking them on whichever config matched first", cfg.Name)
	}
}

// When a zone IS covered but nothing consented, the error says so rather than
// claiming no config matches — those send an operator to different places.
func TestUpstreamSelectionDistinguishesNoConsentFromNoConfig(t *testing.T) {
	ctx := context.Background()
	h := newServedHarness(t, config.Protocols{})
	seedDNS01Config(t, ctx, h, store.ACMEDNS01ProviderConfig{
		Name: "noconsent-server-side-only", Provider: "manual", Zone: "noconsent.test",
		AllowedMethods: []string{"dns-01"}, AllowUpstreamDV: false,
	})

	_, err := h.srv.acmeDNS01.selectProviderConfigForUpstream(ctx, h.tenant, "app.noconsent.test")
	if err == nil {
		t.Fatal("an unconsented config was selected for upstream publication")
	}
	if !strings.Contains(err.Error(), "allow_upstream_dv") {
		t.Errorf("error = %v; it must name the flag, or the operator is told the zone has no "+
			"config when it has one they only need to enable", err)
	}

	if _, err := h.srv.acmeDNS01.selectProviderConfigForUpstream(ctx, h.tenant, "nothing-covers-this.test"); err == nil {
		t.Fatal("a domain with no provider config at all was selected for")
	} else if strings.Contains(err.Error(), "allow_upstream_dv") {
		t.Errorf("error = %v; a domain with NO config must not be reported as a consent problem", err)
	}
}

// A second solve of the same authorization must publish AGAIN (epic B7).
//
// The idempotency key used to be (config, record, value). A retried order
// carries the same token, so the same key authorization, so the same TXT value
// — and the second solve found the first one's row already enqueued and
// returned success. The first publish had been retracted when its attempt
// finished, so trstctl reported a record live in public DNS that was not there,
// the authority looked and found nothing, and the authorization went invalid
// with nothing in trstctl having failed.
//
// The assertion is on the ENQUEUED rows rather than on delivery: this harness
// runs no outbox worker, and the enqueue is the step deduplication acts on.
func TestASecondSolveOfTheSameAuthorizationEnqueuesItsOwnPublish(t *testing.T) {
	ctx := context.Background()
	h := newServedHarness(t, config.Protocols{})
	seedDNS01Config(t, ctx, h, store.ACMEDNS01ProviderConfig{
		Name: "republish", Provider: "manual", Zone: "republish.test",
		AllowedMethods: []string{"dns-01"}, AllowUpstreamDV: true,
	})

	// A stub resolver, because the CAA check is real now: it would otherwise
	// try to resolve a .test name that does not exist and fail before the
	// publish this test is about. No records means no CAA policy, which RFC
	// 8659 treats as permitting any issuer.
	h.srv.acmeDNS01.caaResolver = &countingCAAResolver{}

	solver := &upstreamACMEDNS01Solver{
		automation: h.srv.acmeDNS01, log: h.log, caaIssuerDomain: "letsencrypt.org",
	}
	req := acmekey.ChallengeRequest{
		TenantID: h.tenant, Type: acmekey.ChallengeDNS01,
		Identifier: "app.republish.test", Token: "tok", KeyAuth: "tok.thumb",
	}

	// Two attempts with the IDENTICAL token and key authorization. Each gets a
	// short deadline because nothing here delivers the row; the enqueue has
	// already happened by the time the wait gives up.
	for attempt := 1; attempt <= 2; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
		_, _ = solver.Solve(attemptCtx, req)
		cancel()
	}

	if got := countUpstreamPresentRows(t, ctx, h); got < 2 {
		t.Errorf("%d present rows across two solves of the same authorization; the second was "+
			"deduplicated against the first, so trstctl would report a TXT record live in public "+
			"DNS that it had already retracted", got)
	}
}

// countUpstreamPresentRows counts enqueued DNS-01 publish effects.
func countUpstreamPresentRows(t *testing.T, ctx context.Context, h *servedHarness) int {
	t.Helper()
	var n int
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2`,
			h.tenant, destinationACMEDNS01Present).Scan(&n)
	}); err != nil {
		t.Fatalf("count outbox rows: %v", err)
	}
	return n
}
