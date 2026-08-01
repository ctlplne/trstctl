// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"testing"
	"time"

	"trstctl.com/trstctl/ee/agentid/reach"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// reachability_test.go drives the AGID-06 in-signer reachability precondition (AGID-claims-5/6 /
// INV-A5) through the SAME AGID-04b instrumented-keystore ordering harness the chain,
// attestation, and task-envelope tests use (runGatedIssue / instrumentedKeystore /
// orderLog). A gate with a reachability trust lookup verifies a SIGNED reachability verdict
// as a precondition of the key op, bound to the FINAL record's authority; a within-ceilings
// verdict lets the key op run (strictly after the gate), while an absent / unsigned /
// tampered / stale / ceiling-exceeded verdict performs ZERO key ops and mints a signed
// refusal naming the reachability check.

// reachVerdictSigner is a software ECDSA verdict signer plus its public DER and key id.
type reachVerdictSigner struct {
	signer crypto.Signer
	keyID  string
	pubDER []byte
}

func newReachVerdictSigner(t *testing.T, keyID string) reachVerdictSigner {
	t.Helper()
	s, der := signerWithDER(t)
	return reachVerdictSigner{signer: s, keyID: keyID, pubDER: der}
}

func (r reachVerdictSigner) keyRef() reach.VerdictKeyRef {
	return reach.VerdictKeyRef{ID: r.keyID, Algorithm: "ECDSA-P256"}
}

// reachFixture builds a gate fixture whose reachability trust lookup resolves exactly the
// given verdict-signer key, with the clock pinned. It mirrors newGateFixtureWithTaskEnv but
// wires the reachability precondition instead of the task-envelope one.
func reachFixture(t *testing.T, anchors map[string]RootAnchor, vs reachVerdictSigner, now int64) gateFixture {
	t.Helper()
	log := &orderLog{}
	refusal, refusalDER := signerWithDER(t)
	attestor := newFakeAttestor(log)
	trust := func(keyID string) ([]byte, bool) {
		if keyID == vs.keyID {
			return vs.pubDER, true
		}
		return nil, false
	}
	gate, err := NewGate(Config{
		SignerID:          "test-signer",
		Roots:             NewTrustStore(anchors),
		RefusalSigner:     refusal,
		Revocations:       NeverRevoked{},
		Attestor:          attestor,
		Clock:             fixedClock(now),
		ReachabilityTrust: trust,
		// ReachabilityWatermark nil ⇒ any non-empty watermark accepted (invariance to
		// post-watermark graph changes still holds; the signer trusts the signed digest).
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("CA key: %v", err)
	}
	caIssued, err := crypto.SelfSignedHierarchyCA(caKey, crypto.HierarchyCAProfile{CommonName: "AGID Test CA", TTL: time.Hour})
	if err != nil {
		t.Fatalf("CA cert: %v", err)
	}
	return gateFixture{
		gate:       gate,
		refusalPub: refusalDER,
		caCertDER:  caIssued.CertificateDER,
		caSigner:   caKey,
		log:        log,
		keystore:   &instrumentedKeystore{log: log},
		attestor:   attestor,
	}
}

// reachSetFor builds a representative reachable set the tests reason about: a set of the
// given cardinality and max sensitivity in the given tenant, carrying an "env=prod" label
// so prohibited-label ceilings can be exercised. It is a hand-built set (not from a graph)
// so the delegation test exercises the GATE's verdict verification via the exported reach
// API without standing up a graph here (the engine/graph path is covered in the reach
// package's own tests).
func reachSetFor(tenantID string, cardinality int, maxSens reach.Sensitivity) reach.ReachableSet {
	set := reach.ReachableSet{TenantID: tenantID}
	for i := 0; i < cardinality; i++ {
		sens := reach.SensitivityPublic
		if i == 0 {
			sens = maxSens // one node carries the max sensitivity + the prohibited label
		}
		n := reach.ReachedNode{
			ID:          nodeID(i),
			Kind:        "resource",
			Sensitivity: sens,
		}
		if i == 0 {
			n.Labels = []string{"env=prod"}
		}
		set.Nodes = append(set.Nodes, n)
		if sens > set.MaxSensitivity {
			set.MaxSensitivity = sens
		}
	}
	set.Cardinality = len(set.Nodes)
	if set.Cardinality > 0 {
		set.TenantSpan = 1
		set.PresentLabels = []string{"env=prod"}
	}
	return set
}

func nodeID(i int) string {
	return "res:node-" + string(rune('a'+i))
}

// spanSet builds a reachable set the engine has classified as spanning `span` tenants (a
// TenantSpan a single-tenant build cannot itself produce, but which the verdict can carry
// so the in-signer tenant-span ceiling is exercised end to end). It has one node so it is
// otherwise within cardinality/sensitivity ceilings.
func spanSet(tenantID string, span int) reach.ReachableSet {
	set := reach.ReachableSet{
		TenantID:       tenantID,
		Nodes:          []reach.ReachedNode{{ID: "res:node-a", Kind: "resource", Sensitivity: reach.SensitivityInternal}},
		Cardinality:    1,
		MaxSensitivity: reach.SensitivityInternal,
		TenantSpan:     span,
	}
	return set
}

// signedVerdictFor produces a signed reachability verdict bound to the head authority of
// the chain, for the given reachable set + class + policy, at watermark wm.
func signedVerdictFor(t *testing.T, vs reachVerdictSigner, reg *ToolRegistry, head Record, set reach.ReachableSet, class string, policy *reach.CeilingPolicy, wm string, issuedAt int64) reach.Verdict {
	t.Helper()
	subject, err := CanonicalDigest(head.Authority, reg)
	if err != nil {
		t.Fatalf("head authority digest: %v", err)
	}
	det := determineForTest(set, class, policy)
	v, err := reach.NewVerdict(set, det, wm, subject, issuedAt, vs.keyRef()).Sign(vs.signer)
	if err != nil {
		t.Fatalf("sign verdict: %v", err)
	}
	return v
}

// determineForTest evaluates the set against the class's ceiling (mirrors the engine's
// fail-closed determination without importing an unexported helper).
func determineForTest(set reach.ReachableSet, class string, policy *reach.CeilingPolicy) reach.Determination {
	c, ok := policy.Ceiling(class)
	if !ok {
		// Fail-closed determination for an unconfigured class.
		return reach.Determination{RequesterClass: class, Exceeded: true, Violations: []reach.Violation{{
			Ceiling: reach.CeilingCardinality, Reason: "no ceiling configured", OffendingDigest: set.Digest(),
		}}}
	}
	return reach.Evaluate(set, class, c)
}

// encodePreconditionsWithReach marshals a PreconditionsBody carrying the encoded chain and
// the encoded reachability verdict.
func encodePreconditionsWithReach(t *testing.T, body PreconditionsBody, v reach.Verdict) []byte {
	t.Helper()
	enc, err := reach.EncodeVerdict(v)
	if err != nil {
		t.Fatalf("encode verdict: %v", err)
	}
	body.ReachabilityVerdict = enc
	b, err := jsonMarshal(body)
	if err != nil {
		t.Fatalf("marshal preconditions: %v", err)
	}
	return b
}

// allowPolicy is a ceiling policy for "payments-agent" that ALLOWS a small restricted set.
func allowPolicy() *reach.CeilingPolicy {
	return reach.NewCeilingPolicy(map[string]reach.Ceiling{
		"payments-agent": {MaxCardinality: 10, MaxSensitivity: reach.SensitivityRestricted, MaxTenantSpan: 1},
	})
}

// TestReachability_VerdictSignedAndVerifiedInSigner is a CANONICAL test (AGID-claim-6 / INV-A5):
// with the instrumented-keystore ordering harness, a VALID signed verdict verifies as a
// key-op precondition (the key op runs, strictly after the gate), while an ABSENT, UNSIGNED,
// or TAMPERED verdict performs ZERO key ops and mints a signed refusal naming the
// reachability check. Computation runs OUTSIDE the signer (the verdict is produced by the
// exported engine API here); the signer verifies only the signed result.
func TestReachability_VerdictSignedAndVerifiedInSigner(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	const now = 1500
	const wm = "wm-1"

	// ---- valid verdict: verifies, key op runs strictly after the gate ----
	t.Run("valid-verifies-keyop-after-gate", func(t *testing.T) {
		vs := newReachVerdictSigner(t, "reach-key")
		envs, anchors, bc := singleAnchorChain(t, reg, "t1", "fido2:root")
		head := envs[len(envs)-1].Record
		set := reachSetFor("t1", 3, reach.SensitivityRestricted)
		v := signedVerdictFor(t, vs, reg, head, set, "payments-agent", allowPolicy(), wm, now)
		f := reachFixture(t, anchors, vs, now)

		pre := encodePreconditionsWithReach(t, PreconditionsBody{Chain: envs}, v)
		req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}

		res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
		if !res.decision.Approved {
			t.Fatalf("valid reachability verdict refused: %s", refusalReason(t, res.decision))
		}
		if !res.keyOpRan || f.keystore.keyOps() != 1 {
			t.Fatalf("expected exactly one key op after approval, got %d", f.keystore.keyOps())
		}
		// Ordering (INV-A1/A5): the gate consult strictly precedes the single key op, so the
		// verdict is verified BEFORE any key op.
		if gi, ki := f.log.index("gate"), f.log.index("keyop"); gi < 0 || ki < 0 || gi >= ki {
			t.Fatalf("call order = %v, want gate strictly before keyop", f.log.snapshot())
		}
		// The credential still binds the chain head (reachability binds nothing itself;
		// the graph is an input to a refusal gate only).
		bm, err := ExtractBindingMaterial(res.credential)
		if err != nil {
			t.Fatalf("extract binding: %v", err)
		}
		if !bytesEqual(bm.ChainHeadDigest, bc.headDigest) {
			t.Fatalf("bound chain-head digest = %x, want %x", bm.ChainHeadDigest, bc.headDigest)
		}
	})

	// ---- absent verdict (reachability enabled + chain present): ZERO key ops + refusal ----
	t.Run("absent-refuses-no-keyop", func(t *testing.T) {
		vs := newReachVerdictSigner(t, "reach-key")
		envs, anchors, _ := singleAnchorChain(t, reg, "t1", "fido2:root")
		f := reachFixture(t, anchors, vs, now)

		// No reachability verdict in the body, but the gate has reachability enabled.
		pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: envs})
		req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}

		res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
		assertRefusedNoKeyOp(t, f, res, CheckReachability, "absent verdict")
	})

	// ---- unsigned verdict: ZERO key ops + refusal ----
	t.Run("unsigned-refuses-no-keyop", func(t *testing.T) {
		vs := newReachVerdictSigner(t, "reach-key")
		envs, anchors, _ := singleAnchorChain(t, reg, "t1", "fido2:root")
		head := envs[len(envs)-1].Record
		set := reachSetFor("t1", 3, reach.SensitivityRestricted)
		v := signedVerdictFor(t, vs, reg, head, set, "payments-agent", allowPolicy(), wm, now)
		v.Signature = nil // strip the signature
		f := reachFixture(t, anchors, vs, now)

		pre := encodePreconditionsWithReach(t, PreconditionsBody{Chain: envs}, v)
		req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}

		res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
		assertRefusedNoKeyOp(t, f, res, CheckReachability, "unsigned verdict")
	})

	// ---- tampered verdict (a bound field altered after signing): ZERO key ops + refusal ----
	t.Run("tampered-refuses-no-keyop", func(t *testing.T) {
		vs := newReachVerdictSigner(t, "reach-key")
		envs, anchors, _ := singleAnchorChain(t, reg, "t1", "fido2:root")
		head := envs[len(envs)-1].Record
		set := reachSetFor("t1", 3, reach.SensitivityRestricted)
		v := signedVerdictFor(t, vs, reg, head, set, "payments-agent", allowPolicy(), wm, now)
		// Tamper: flip the bound reachable digest so the signature no longer verifies.
		v.ReachableDigest = append([]byte(nil), v.ReachableDigest...)
		v.ReachableDigest[0] ^= 0xff
		f := reachFixture(t, anchors, vs, now)

		pre := encodePreconditionsWithReach(t, PreconditionsBody{Chain: envs}, v)
		req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}

		res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
		assertRefusedNoKeyOp(t, f, res, CheckReachability, "tampered verdict")
	})

	// ---- stale-watermark verdict (empty watermark): ZERO key ops + refusal ----
	t.Run("stale-watermark-refuses-no-keyop", func(t *testing.T) {
		vs := newReachVerdictSigner(t, "reach-key")
		envs, anchors, _ := singleAnchorChain(t, reg, "t1", "fido2:root")
		head := envs[len(envs)-1].Record
		set := reachSetFor("t1", 3, reach.SensitivityRestricted)
		v := signedVerdictFor(t, vs, reg, head, set, "payments-agent", allowPolicy(), "", now) // empty watermark
		f := reachFixture(t, anchors, vs, now)

		pre := encodePreconditionsWithReach(t, PreconditionsBody{Chain: envs}, v)
		req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}

		res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
		assertRefusedNoKeyOp(t, f, res, CheckReachability, "stale-watermark verdict")
	})

	// ---- verdict bound to a DIFFERENT authority (wrong subject): ZERO key ops + refusal ----
	t.Run("wrong-subject-refuses-no-keyop", func(t *testing.T) {
		vs := newReachVerdictSigner(t, "reach-key")
		envs, anchors, _ := singleAnchorChain(t, reg, "t1", "fido2:root")
		// Build a verdict bound to a DIFFERENT authority than the chain head's.
		otherHead := Record{Authority: widerAuthority()}
		set := reachSetFor("t1", 3, reach.SensitivityRestricted)
		v := signedVerdictFor(t, vs, reg, otherHead, set, "payments-agent", allowPolicy(), wm, now)
		f := reachFixture(t, anchors, vs, now)

		pre := encodePreconditionsWithReach(t, PreconditionsBody{Chain: envs}, v)
		req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}

		res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
		assertRefusedNoKeyOp(t, f, res, CheckReachability, "wrong-subject verdict")
	})
}

// TestReachability_ExceedsCeilingRefused is a CANONICAL test (AGID-claim-5 / INV-A5): a reachable
// set exceeding a CARDINALITY, SENSITIVITY-CLASS, or TENANT-SPAN ceiling ⇒ the request is
// refused with a signed refusal naming the reachability check, and ZERO key ops. The
// verdict carries the Exceeded determination (computed outside the signer); the signer
// honors it.
func TestReachability_ExceedsCeilingRefused(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	const now = 1500
	const wm = "wm-1"

	cases := []struct {
		name   string
		set    reach.ReachableSet
		policy *reach.CeilingPolicy
	}{
		{
			name:   "cardinality",
			set:    reachSetFor("t1", 5, reach.SensitivityInternal),
			policy: reach.NewCeilingPolicy(map[string]reach.Ceiling{"payments-agent": {MaxCardinality: 2, MaxSensitivity: reach.SensitivityRestricted}}),
		},
		{
			name:   "sensitivity",
			set:    reachSetFor("t1", 2, reach.SensitivityRestricted),
			policy: reach.NewCeilingPolicy(map[string]reach.Ceiling{"payments-agent": {MaxCardinality: 10, MaxSensitivity: reach.SensitivityInternal}}),
		},
		{
			name:   "tenant-span",
			set:    spanSet("t1", 2), // a set the (out-of-signer) engine marked as spanning 2 tenants
			policy: reach.NewCeilingPolicy(map[string]reach.Ceiling{"payments-agent": {MaxCardinality: 10, MaxSensitivity: reach.SensitivityRestricted, MaxTenantSpan: 1}}),
		},
		{
			name:   "prohibited-label",
			set:    reachSetFor("t1", 2, reach.SensitivityInternal), // carries env=prod
			policy: reach.NewCeilingPolicy(map[string]reach.Ceiling{"payments-agent": {MaxCardinality: 10, MaxSensitivity: reach.SensitivityRestricted, ProhibitedLabels: []string{"env=prod"}}}),
		},
		{
			name:   "unconfigured-class-fail-closed",
			set:    reachSetFor("t1", 1, reach.SensitivityPublic),
			policy: reach.NewCeilingPolicy(nil), // no ceiling for the class ⇒ fail closed
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vs := newReachVerdictSigner(t, "reach-key")
			envs, anchors, _ := singleAnchorChain(t, reg, "t1", "fido2:root")
			head := envs[len(envs)-1].Record
			v := signedVerdictFor(t, vs, reg, head, tc.set, "payments-agent", tc.policy, wm, now)
			// Sanity: the determination the engine computed IS exceeded.
			if !v.Determination.Exceeded {
				t.Fatalf("%s: precondition — verdict determination should be exceeded", tc.name)
			}
			f := reachFixture(t, anchors, vs, now)

			pre := encodePreconditionsWithReach(t, PreconditionsBody{Chain: envs}, v)
			req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}

			res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
			art := assertRefusedNoKeyOp(t, f, res, CheckReachability, tc.name+" ceiling")
			// The refusal detail names the violated ceiling (AGID-claim-5).
			if tc.name != "unconfigured-class-fail-closed" {
				wantCeiling := map[string]reach.CeilingKind{
					"cardinality":      reach.CeilingCardinality,
					"sensitivity":      reach.CeilingSensitivity,
					"tenant-span":      reach.CeilingTenantSpan,
					"prohibited-label": reach.CeilingProhibitedLabel,
				}[tc.name]
				if wantCeiling != "" && !containsSubstr(art.Detail, string(wantCeiling)) {
					t.Fatalf("%s: refusal detail %q does not name ceiling %q", tc.name, art.Detail, wantCeiling)
				}
			}
		})
	}
}

// TestReachability_InertWhenNotConfigured proves NO REGRESSION: a gate with NO reachability
// trust lookup and RequireReachability=false ignores reachability entirely — a chain with no
// verdict issues exactly as AGID-05 (the reachability precondition is inert). This is what
// keeps every existing AGID-04b/05 test green.
func TestReachability_InertWhenNotConfigured(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	envs, anchors, bc := singleAnchorChain(t, reg, "t1", "fido2:root")
	f := newGateFixture(t, anchors, nil, nil, nil) // NO reachability trust configured

	pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: envs})
	req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}

	res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
	if !res.decision.Approved {
		t.Fatalf("reachability-unconfigured issuance refused: %s", refusalReason(t, res.decision))
	}
	if !res.keyOpRan || f.keystore.keyOps() != 1 {
		t.Fatalf("expected exactly one key op, got %d", f.keystore.keyOps())
	}
	bm, err := ExtractBindingMaterial(res.credential)
	if err != nil {
		t.Fatalf("extract binding: %v", err)
	}
	if !bytesEqual(bm.ChainHeadDigest, bc.headDigest) {
		t.Fatalf("bound chain-head digest mismatch")
	}
}

// TestReachability_RequireWithoutTrustFailsClosed proves the RequireReachability gap-closer:
// a gate that REQUIRES reachability but holds no trust lookup refuses a chain-bearing
// request fail-closed (no key op), so an operator asserting "no issuance without a
// reachability bound" cannot be silently defeated by a missing trust wiring.
func TestReachability_RequireWithoutTrustFailsClosed(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	envs, anchors, _ := singleAnchorChain(t, reg, "t1", "fido2:root")

	log := &orderLog{}
	refusal, refusalDER := signerWithDER(t)
	gate, err := NewGate(Config{
		SignerID:            "test-signer",
		Roots:               NewTrustStore(anchors),
		RefusalSigner:       refusal,
		Revocations:         NeverRevoked{},
		Clock:               fixedClock(1500),
		RequireReachability: true, // required, but NO ReachabilityTrust
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	f := gateFixture{gate: gate, refusalPub: refusalDER, log: log, keystore: &instrumentedKeystore{log: log}}

	pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: envs})
	req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}

	res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
	assertRefusedNoKeyOp(t, f, res, CheckReachability, "required-but-no-trust")
}

// assertRefusedNoKeyOp asserts the decision is a refusal naming wantCheck, with ZERO key
// ops, a signed refusal that verifies, and returns the decoded refusal artifact.
func assertRefusedNoKeyOp(t *testing.T, f gateFixture, res gatedResult, wantCheck, ctx string) RefusalArtifact {
	t.Helper()
	if res.decision.Approved {
		t.Fatalf("%s: was approved (must refuse)", ctx)
	}
	if res.keyOpRan || f.keystore.keyOps() != 0 {
		t.Fatalf("%s: performed %d key ops, want ZERO (INV-A1/A5)", ctx, f.keystore.keyOps())
	}
	art := decodeRefusalForTest(t, res.decision.RefusalRecord)
	if art.FailedCheck != wantCheck {
		t.Fatalf("%s: failed_check = %q, want %q (detail: %q)", ctx, art.FailedCheck, wantCheck, art.Detail)
	}
	if err := VerifyRefusal(f.refusalPub, art); err != nil {
		t.Fatalf("%s: signed refusal does not verify: %v", ctx, err)
	}
	return art
}
