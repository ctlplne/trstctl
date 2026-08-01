// SPDX-License-Identifier: LicenseRef-trstctl-EE

package engine_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/ee/agentid/reach"
	"trstctl.com/trstctl/ee/agentid/reach/engine"
)

// verdict_test.go exercises the crypto-only reach verdict/ceiling/verify surface end to end
// against reachable sets produced by the engine — the AGID-claim-25 mechanism: compute the
// reachable set of a requested authority set, produce a signed reachability verdict, verify it. It lives in the engine_test package (which
// imports both reach and the engine) because the tests resolve a realistic set with the
// engine, then assert the reach package's Evaluate / NewVerdict / VerifyVerdict /
// DetermineOrFailClosed behavior over it. The reach package itself stays crypto-only (no
// engine import); this external test bridges the two halves.

// prodPolicy is a ceiling policy for the "payments-agent" class that ALLOWS the payments
// reachable set (cardinality 3, restricted sensitivity) — used where the verdict should be
// within ceilings.
func prodPolicy() *reach.CeilingPolicy {
	return reach.NewCeilingPolicy(map[string]reach.Ceiling{
		"payments-agent": {MaxCardinality: 10, MaxSensitivity: reach.SensitivityRestricted, MaxTenantSpan: 1},
	})
}

// TestReachability_VerdictBindsWatermarkAndDigest is a CANONICAL test (AGID-claim-6 / INV-A5):
// the verdict binds the reachable-set digest + ceiling determination + graph watermark, and
// verification is INVARIANT to graph changes AFTER the watermark (freshness is bounded by
// the watermark). It produces a signed verdict at wm-1, mutates the underlying graph, and
// shows the SAME verdict still verifies (the signer trusts the signed digest, not a live
// graph) — and that a verdict re-derived from the changed graph binds a DIFFERENT digest,
// so the two are distinguishable.
func TestReachability_VerdictBindsWatermarkAndDigest(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	src := newStaticGraphSource()
	src.set(tenant, fixtureGraph(), "wm-1")
	e := engine.NewEngine(src)
	vs := newVerdictSigner(t, "reach-signer-1")

	set, wm, err := e.Resolve(context.Background(), paymentsRequest(tenant))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	subject := []byte("authority-digest-A")
	det := reach.Evaluate(set, "payments-agent", mustCeiling(t, prodPolicy(), "payments-agent"))
	verdict, err := reach.NewVerdict(set, det, wm, subject, 1000, vs.keyRef()).Sign(vs.signer)
	if err != nil {
		t.Fatalf("sign verdict: %v", err)
	}

	// The verdict BINDS the three things.
	if !bytes.Equal(verdict.ReachableDigest, set.Digest()) {
		t.Errorf("verdict does not bind the reachable-set digest")
	}
	if verdict.Watermark != "wm-1" {
		t.Errorf("verdict watermark = %q, want wm-1", verdict.Watermark)
	}
	if verdict.Determination.Exceeded {
		t.Errorf("determination should be within ceilings (not exceeded)")
	}

	verify := func(v reach.Verdict) error {
		return reach.VerifyVerdict(reach.VerifyInput{Verdict: v, TenantID: tenant, SubjectDigest: subject, Trust: vs.trust()})
	}
	// Baseline: verifies.
	if err := verify(verdict); err != nil {
		t.Fatalf("fresh verdict must verify: %v", err)
	}

	// Mutate the graph AFTER the watermark. The signed verdict is UNCHANGED and must still
	// verify — verification is invariant to post-watermark graph changes (the signer trusts
	// the signed digest, computing nothing from a graph).
	g2 := fixtureGraph()
	g2.AddNode(nodeWithSensitivity("res:new-secret", "restricted"))
	g2.AddEdge(edge("cred:cert-payments", "res:new-secret"))
	src.set(tenant, g2, "wm-1") // same watermark, changed graph
	if err := verify(verdict); err != nil {
		t.Fatalf("verdict must remain valid after post-watermark graph change (invariance): %v", err)
	}

	// Sanity: a verdict re-derived from the CHANGED graph (bumped watermark) binds a
	// DIFFERENT reachable-set digest, so the binding actually reflects graph state.
	src.set(tenant, g2, "wm-2")
	set2, wm2, err := e.Resolve(context.Background(), paymentsRequest(tenant))
	if err != nil {
		t.Fatalf("Resolve changed: %v", err)
	}
	if bytes.Equal(set.Digest(), set2.Digest()) {
		t.Fatalf("changed-graph reachable-set digest must differ from the original")
	}
	if wm2 != "wm-2" {
		t.Fatalf("wm2 = %q", wm2)
	}
}

// TestVerdict_VerifyRejectsTamperStaleUntrustedWrongSubject is the negative battery for the
// pure in-signer verification: a tampered, unsigned, stale-watermark, untrusted-signer,
// wrong-tenant, or wrong-subject verdict all FAIL CLOSED (a non-nil error the gate turns
// into a refusal). This is the reachability half of INV-A5's fail-closed spine.
func TestVerdict_VerifyRejectsTamperStaleUntrustedWrongSubject(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	src := newStaticGraphSource()
	src.set(tenant, fixtureGraph(), "wm-1")
	e := engine.NewEngine(src)
	vs := newVerdictSigner(t, "reach-signer-1")
	subject := []byte("authority-digest-A")

	set, wm, err := e.Resolve(context.Background(), paymentsRequest(tenant))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	det := reach.Evaluate(set, "payments-agent", mustCeiling(t, prodPolicy(), "payments-agent"))
	good, err := reach.NewVerdict(set, det, wm, subject, 1000, vs.keyRef()).Sign(vs.signer)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	base := reach.VerifyInput{Verdict: good, TenantID: tenant, SubjectDigest: subject, Trust: vs.trust()}
	if err := reach.VerifyVerdict(base); err != nil {
		t.Fatalf("good verdict must verify: %v", err)
	}

	// (a) Absent verdict (zero value) ⇒ ErrNoVerdict.
	if err := reach.VerifyVerdict(reach.VerifyInput{TenantID: tenant, SubjectDigest: subject, Trust: vs.trust()}); !errors.Is(err, reach.ErrNoVerdict) {
		t.Errorf("absent verdict: err = %v, want ErrNoVerdict", err)
	}

	// (b) Unsigned verdict ⇒ signature failure.
	unsigned := good
	unsigned.Signature = nil
	if err := reach.VerifyVerdict(withVerdict(base, unsigned)); !errors.Is(err, reach.ErrVerdictSignature) {
		t.Errorf("unsigned verdict: err = %v, want ErrVerdictSignature", err)
	}

	// (c) Tampered bound field (flip the determination to not-exceeded is already the case;
	// instead tamper the reachable digest) ⇒ signature no longer verifies.
	tampered := good
	tampered.ReachableDigest = append([]byte(nil), good.ReachableDigest...)
	tampered.ReachableDigest[0] ^= 0xff
	if err := reach.VerifyVerdict(withVerdict(base, tampered)); !errors.Is(err, reach.ErrVerdictSignature) {
		t.Errorf("tampered verdict: err = %v, want ErrVerdictSignature", err)
	}

	// (d) Stale/empty watermark ⇒ ErrVerdictStale. Re-sign with an empty watermark so the
	// signature is valid but the watermark is absent.
	staleV, err := reach.NewVerdict(set, det, "", subject, 1000, vs.keyRef()).Sign(vs.signer)
	if err != nil {
		t.Fatalf("sign stale: %v", err)
	}
	if err := reach.VerifyVerdict(withVerdict(base, staleV)); !errors.Is(err, reach.ErrVerdictStale) {
		t.Errorf("empty-watermark verdict: err = %v, want ErrVerdictStale", err)
	}
	// A watermark rejected by a staleness policy ⇒ ErrVerdictStale.
	stalePolicy := reach.WatermarkPolicy(func(_, w string) bool { return w == "wm-current" })
	if err := reach.VerifyVerdict(reach.VerifyInput{Verdict: good, TenantID: tenant, SubjectDigest: subject, Trust: vs.trust(), Watermark: stalePolicy}); !errors.Is(err, reach.ErrVerdictStale) {
		t.Errorf("policy-rejected watermark: err = %v, want ErrVerdictStale", err)
	}

	// (e) Untrusted signer (trust lookup returns false) ⇒ ErrUntrustedVerdictSigner.
	if err := reach.VerifyVerdict(reach.VerifyInput{Verdict: good, TenantID: tenant, SubjectDigest: subject, Trust: func(string) ([]byte, bool) { return nil, false }}); !errors.Is(err, reach.ErrUntrustedVerdictSigner) {
		t.Errorf("untrusted signer: err = %v, want ErrUntrustedVerdictSigner", err)
	}
	// Nil trust lookup ⇒ ErrUntrustedVerdictSigner (fail-closed).
	if err := reach.VerifyVerdict(reach.VerifyInput{Verdict: good, TenantID: tenant, SubjectDigest: subject}); !errors.Is(err, reach.ErrUntrustedVerdictSigner) {
		t.Errorf("nil trust: err = %v, want ErrUntrustedVerdictSigner", err)
	}

	// (f) Wrong tenant ⇒ ErrVerdictTenantMismatch.
	if err := reach.VerifyVerdict(reach.VerifyInput{Verdict: good, TenantID: "22222222-2222-2222-2222-222222222222", SubjectDigest: subject, Trust: vs.trust()}); !errors.Is(err, reach.ErrVerdictTenantMismatch) {
		t.Errorf("wrong tenant: err = %v, want ErrVerdictTenantMismatch", err)
	}

	// (g) Wrong subject ⇒ ErrVerdictSubjectMismatch (a verdict for a different authority).
	if err := reach.VerifyVerdict(reach.VerifyInput{Verdict: good, TenantID: tenant, SubjectDigest: []byte("authority-digest-B"), Trust: vs.trust()}); !errors.Is(err, reach.ErrVerdictSubjectMismatch) {
		t.Errorf("wrong subject: err = %v, want ErrVerdictSubjectMismatch", err)
	}
	// Empty requested subject can never match (fail-closed).
	if err := reach.VerifyVerdict(reach.VerifyInput{Verdict: good, TenantID: tenant, SubjectDigest: nil, Trust: vs.trust()}); !errors.Is(err, reach.ErrVerdictSubjectMismatch) {
		t.Errorf("empty subject: err = %v, want ErrVerdictSubjectMismatch", err)
	}
}

// TestEvaluate_CeilingDimensions checks each ceiling dimension produces an Exceeded
// determination naming the right ceiling with a non-empty offending-subset digest, and
// that a within-ceilings set is not exceeded.
func TestEvaluate_CeilingDimensions(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	src := newStaticGraphSource()
	src.set(tenant, fixtureGraph(), "wm-1")
	e := engine.NewEngine(src)
	set, _, err := e.Resolve(context.Background(), paymentsRequest(tenant))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	cases := []struct {
		name    string
		ceiling reach.Ceiling
		want    reach.CeilingKind
	}{
		{"cardinality", reach.Ceiling{MaxCardinality: 1, MaxSensitivity: reach.SensitivityRestricted}, reach.CeilingCardinality},
		{"sensitivity", reach.Ceiling{MaxCardinality: 10, MaxSensitivity: reach.SensitivityInternal}, reach.CeilingSensitivity},
		{"tenant_span", reach.Ceiling{MaxCardinality: 10, MaxSensitivity: reach.SensitivityRestricted, MaxTenantSpan: 0 /*unbounded*/}, ""}, // span 1 with no bound => ok
		{"prohibited_label", reach.Ceiling{MaxCardinality: 10, MaxSensitivity: reach.SensitivityRestricted, ProhibitedLabels: []string{"env=prod"}}, reach.CeilingProhibitedLabel},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			det := reach.Evaluate(set, "payments-agent", tc.ceiling)
			if tc.want == "" {
				if det.Exceeded {
					t.Fatalf("%s: unexpectedly exceeded: %+v", tc.name, det.Violations)
				}
				return
			}
			if !det.Exceeded {
				t.Fatalf("%s: expected exceeded", tc.name)
			}
			if det.Violations[0].Ceiling != tc.want {
				t.Fatalf("%s: violated ceiling = %s, want %s", tc.name, det.Violations[0].Ceiling, tc.want)
			}
			if len(det.Violations[0].OffendingDigest) == 0 {
				t.Fatalf("%s: offending-subset digest must be non-empty", tc.name)
			}
		})
	}

	// A tenant-span ceiling of 0 with a set spanning 1 tenant is NOT a violation (0 means
	// unbounded); a span ceiling that is exceeded is modeled but not reachable under a
	// single-tenant build. Assert a within-ceilings set overall.
	det := reach.Evaluate(set, "payments-agent", reach.Ceiling{MaxCardinality: 10, MaxSensitivity: reach.SensitivityRestricted, MaxTenantSpan: 1})
	if det.Exceeded {
		t.Fatalf("within-ceilings set unexpectedly exceeded: %+v", det.Violations)
	}
}

// TestDetermineOrFailClosed_UnconfiguredClassFailsClosed proves the OUTSIDE-signer
// fail-closed policy: a requester class with NO configured ceiling yields an Exceeded
// determination (never a silent allow), so the signer refuses.
func TestDetermineOrFailClosed_UnconfiguredClassFailsClosed(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	src := newStaticGraphSource()
	src.set(tenant, fixtureGraph(), "wm-1")
	e := engine.NewEngine(src)
	set, _, err := e.Resolve(context.Background(), paymentsRequest(tenant))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	det := reach.DetermineOrFailClosed(set, "unknown-class", reach.NewCeilingPolicy(nil))
	if !det.Exceeded {
		t.Fatalf("unconfigured class must fail closed (Exceeded)")
	}
	// A fallback ceiling allows an un-enumerated class rather than refusing it.
	detFB := reach.DetermineOrFailClosed(set, "unknown-class", reach.NewCeilingPolicy(nil).WithFallbackCeiling(reach.Ceiling{MaxCardinality: 100, MaxSensitivity: reach.SensitivityRestricted}))
	if detFB.Exceeded {
		t.Fatalf("fallback ceiling should allow the set: %+v", detFB.Violations)
	}
}

// ---- helpers ----

func withVerdict(in reach.VerifyInput, v reach.Verdict) reach.VerifyInput {
	in.Verdict = v
	return in
}

func mustCeiling(t *testing.T, p *reach.CeilingPolicy, class string) reach.Ceiling {
	t.Helper()
	c, ok := p.Ceiling(class)
	if !ok {
		t.Fatalf("no ceiling for class %q", class)
	}
	return c
}
