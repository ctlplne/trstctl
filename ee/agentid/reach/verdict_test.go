// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reach

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// prodPolicy is a ceiling policy for the "payments-agent" class that ALLOWS the payments
// reachable set (cardinality 3, restricted sensitivity) — used where the verdict should be
// within ceilings.
func prodPolicy() *CeilingPolicy {
	return NewCeilingPolicy(map[string]Ceiling{
		"payments-agent": {MaxCardinality: 10, MaxSensitivity: SensitivityRestricted, MaxTenantSpan: 1},
	})
}

// TestReachability_VerdictBindsWatermarkAndDigest is a CANONICAL test (claim 6 / INV-A5):
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
	e := NewEngine(src)
	vs := newVerdictSigner(t, "reach-signer-1")

	set, wm, err := e.Resolve(context.Background(), paymentsRequest(tenant))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	subject := []byte("authority-digest-A")
	det := Evaluate(set, "payments-agent", mustCeiling(t, prodPolicy(), "payments-agent"))
	verdict, err := NewVerdict(set, det, wm, subject, 1000, vs.keyRef()).Sign(vs.signer)
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

	verify := func(v Verdict) error {
		return VerifyVerdict(VerifyInput{Verdict: v, TenantID: tenant, SubjectDigest: subject, Trust: vs.trust()})
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
	e := NewEngine(src)
	vs := newVerdictSigner(t, "reach-signer-1")
	subject := []byte("authority-digest-A")

	set, wm, err := e.Resolve(context.Background(), paymentsRequest(tenant))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	det := Evaluate(set, "payments-agent", mustCeiling(t, prodPolicy(), "payments-agent"))
	good, err := NewVerdict(set, det, wm, subject, 1000, vs.keyRef()).Sign(vs.signer)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	base := VerifyInput{Verdict: good, TenantID: tenant, SubjectDigest: subject, Trust: vs.trust()}
	if err := VerifyVerdict(base); err != nil {
		t.Fatalf("good verdict must verify: %v", err)
	}

	// (a) Absent verdict (zero value) ⇒ ErrNoVerdict.
	if err := VerifyVerdict(VerifyInput{TenantID: tenant, SubjectDigest: subject, Trust: vs.trust()}); !errors.Is(err, ErrNoVerdict) {
		t.Errorf("absent verdict: err = %v, want ErrNoVerdict", err)
	}

	// (b) Unsigned verdict ⇒ signature failure.
	unsigned := good
	unsigned.Signature = nil
	if err := VerifyVerdict(withVerdict(base, unsigned)); !errors.Is(err, ErrVerdictSignature) {
		t.Errorf("unsigned verdict: err = %v, want ErrVerdictSignature", err)
	}

	// (c) Tampered bound field (flip the determination to not-exceeded is already the case;
	// instead tamper the reachable digest) ⇒ signature no longer verifies.
	tampered := good
	tampered.ReachableDigest = append([]byte(nil), good.ReachableDigest...)
	tampered.ReachableDigest[0] ^= 0xff
	if err := VerifyVerdict(withVerdict(base, tampered)); !errors.Is(err, ErrVerdictSignature) {
		t.Errorf("tampered verdict: err = %v, want ErrVerdictSignature", err)
	}

	// (d) Stale/empty watermark ⇒ ErrVerdictStale. Re-sign with an empty watermark so the
	// signature is valid but the watermark is absent.
	staleV, err := NewVerdict(set, det, "", subject, 1000, vs.keyRef()).Sign(vs.signer)
	if err != nil {
		t.Fatalf("sign stale: %v", err)
	}
	if err := VerifyVerdict(withVerdict(base, staleV)); !errors.Is(err, ErrVerdictStale) {
		t.Errorf("empty-watermark verdict: err = %v, want ErrVerdictStale", err)
	}
	// A watermark rejected by a staleness policy ⇒ ErrVerdictStale.
	stalePolicy := WatermarkPolicy(func(_, w string) bool { return w == "wm-current" })
	if err := VerifyVerdict(VerifyInput{Verdict: good, TenantID: tenant, SubjectDigest: subject, Trust: vs.trust(), Watermark: stalePolicy}); !errors.Is(err, ErrVerdictStale) {
		t.Errorf("policy-rejected watermark: err = %v, want ErrVerdictStale", err)
	}

	// (e) Untrusted signer (trust lookup returns false) ⇒ ErrUntrustedVerdictSigner.
	if err := VerifyVerdict(VerifyInput{Verdict: good, TenantID: tenant, SubjectDigest: subject, Trust: func(string) ([]byte, bool) { return nil, false }}); !errors.Is(err, ErrUntrustedVerdictSigner) {
		t.Errorf("untrusted signer: err = %v, want ErrUntrustedVerdictSigner", err)
	}
	// Nil trust lookup ⇒ ErrUntrustedVerdictSigner (fail-closed).
	if err := VerifyVerdict(VerifyInput{Verdict: good, TenantID: tenant, SubjectDigest: subject}); !errors.Is(err, ErrUntrustedVerdictSigner) {
		t.Errorf("nil trust: err = %v, want ErrUntrustedVerdictSigner", err)
	}

	// (f) Wrong tenant ⇒ ErrVerdictTenantMismatch.
	if err := VerifyVerdict(VerifyInput{Verdict: good, TenantID: "22222222-2222-2222-2222-222222222222", SubjectDigest: subject, Trust: vs.trust()}); !errors.Is(err, ErrVerdictTenantMismatch) {
		t.Errorf("wrong tenant: err = %v, want ErrVerdictTenantMismatch", err)
	}

	// (g) Wrong subject ⇒ ErrVerdictSubjectMismatch (a verdict for a different authority).
	if err := VerifyVerdict(VerifyInput{Verdict: good, TenantID: tenant, SubjectDigest: []byte("authority-digest-B"), Trust: vs.trust()}); !errors.Is(err, ErrVerdictSubjectMismatch) {
		t.Errorf("wrong subject: err = %v, want ErrVerdictSubjectMismatch", err)
	}
	// Empty requested subject can never match (fail-closed).
	if err := VerifyVerdict(VerifyInput{Verdict: good, TenantID: tenant, SubjectDigest: nil, Trust: vs.trust()}); !errors.Is(err, ErrVerdictSubjectMismatch) {
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
	e := NewEngine(src)
	set, _, err := e.Resolve(context.Background(), paymentsRequest(tenant))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	cases := []struct {
		name    string
		ceiling Ceiling
		want    CeilingKind
	}{
		{"cardinality", Ceiling{MaxCardinality: 1, MaxSensitivity: SensitivityRestricted}, CeilingCardinality},
		{"sensitivity", Ceiling{MaxCardinality: 10, MaxSensitivity: SensitivityInternal}, CeilingSensitivity},
		{"tenant_span", Ceiling{MaxCardinality: 10, MaxSensitivity: SensitivityRestricted, MaxTenantSpan: 0 /*unbounded*/}, ""}, // span 1 with no bound => ok
		{"prohibited_label", Ceiling{MaxCardinality: 10, MaxSensitivity: SensitivityRestricted, ProhibitedLabels: []string{"env=prod"}}, CeilingProhibitedLabel},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			det := Evaluate(set, "payments-agent", tc.ceiling)
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
	det := Evaluate(set, "payments-agent", Ceiling{MaxCardinality: 10, MaxSensitivity: SensitivityRestricted, MaxTenantSpan: 1})
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
	e := NewEngine(src)
	set, _, err := e.Resolve(context.Background(), paymentsRequest(tenant))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	det := determineOrFailClosed(set, "unknown-class", NewCeilingPolicy(nil))
	if !det.Exceeded {
		t.Fatalf("unconfigured class must fail closed (Exceeded)")
	}
	// A fallback ceiling allows an un-enumerated class rather than refusing it.
	detFB := determineOrFailClosed(set, "unknown-class", NewCeilingPolicy(nil).WithFallbackCeiling(Ceiling{MaxCardinality: 100, MaxSensitivity: SensitivityRestricted}))
	if detFB.Exceeded {
		t.Fatalf("fallback ceiling should allow the set: %+v", detFB.Violations)
	}
}

// ---- helpers ----

func withVerdict(in VerifyInput, v Verdict) VerifyInput {
	in.Verdict = v
	return in
}

func mustCeiling(t *testing.T, p *CeilingPolicy, class string) Ceiling {
	t.Helper()
	c, ok := p.Ceiling(class)
	if !ok {
		t.Fatalf("no ceiling for class %q", class)
	}
	return c
}
