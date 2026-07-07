// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// gateFixture bundles a constructed gate with the material a test needs to drive it and
// verify its outputs: the refusal-verify public key, the issuing CA, and the order log.
type gateFixture struct {
	gate       *Gate
	refusalPub []byte
	caCertDER  []byte
	caSigner   crypto.DigestSigner
	log        *orderLog
	keystore   *instrumentedKeystore
	attestor   *fakeAttestor
}

// newGateFixture constructs a gate over a software refusal key, an in-boundary issuing
// CA, an instrumented fake keystore, and a fake attestor, with the supplied anchors,
// min-class policy, revocation reader, and clock.
func newGateFixture(t *testing.T, anchors map[string]RootAnchor, minClass MinClassPolicy, rev RevocationReader, clock func() time.Time) gateFixture {
	t.Helper()
	log := &orderLog{}
	refusal, refusalDER := signerWithDER(t)
	attestor := newFakeAttestor(log)
	if rev == nil {
		rev = NeverRevoked{}
	}
	gate, err := NewGate(Config{
		SignerID:      "test-signer",
		Roots:         NewTrustStore(anchors),
		RefusalSigner: refusal,
		Revocations:   rev,
		Attestor:      attestor,
		MinClass:      minClass,
		Clock:         clock,
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	// In-boundary issuing CA for credential minting.
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

// mintKeyOp returns a keyOp closure that generates an agent key in the instrumented fake
// keystore (recording "keyop") and mints the credential binding the decision's material.
// It is the after-approval arm of INV-A1: it is passed to runGatedIssue, which invokes it
// ONLY when the gate approved.
func (f gateFixture) mintKeyOp(t *testing.T) func(signing.IssuanceDecision) ([]byte, error) {
	t.Helper()
	return func(dec signing.IssuanceDecision) ([]byte, error) {
		bm, err := DecodeBindingMaterial(dec.BindingMaterial)
		if err != nil {
			return nil, err
		}
		agent, destroy, err := f.keystore.GenerateAgentKey(crypto.ECDSAP256)
		if err != nil {
			return nil, err
		}
		defer destroy()
		return MintCredential(f.caCertDER, f.caSigner, agent, "agent-subject", 0, bm)
	}
}

// singleAnchorChain builds a valid two-hop narrowing chain (root -> narrower) and returns
// its envelopes plus the anchor map to seed the trust store.
func singleAnchorChain(t *testing.T, reg *ToolRegistry, tenantID, authRef string) ([]RecordEnvelope, map[string]RootAnchor, builtChain) {
	t.Helper()
	rootSigner, rootDER := signerWithDER(t)
	midSigner, midDER := signerWithDER(t)
	hops := []hop{
		{delegatorID: "root", delegatorKeyID: "root-key", delegateID: "mid", authority: wideAuthority(), depthRemaining: 3, validity: openWindow()},
		{delegatorID: "mid", delegatorKeyID: "mid-key", delegateID: "leaf", authority: narrowerAuthority(), depthRemaining: 2, validity: openWindow()},
	}
	bc := buildChain(t, reg, tenantID, hops, []crypto.Signer{rootSigner, midSigner}, [][]byte{rootDER, midDER})
	anchors := map[string]RootAnchor{"root-key": {PublicDER: rootDER, AuthRef: authRef}}
	return bc.envelopes, anchors, bc
}

// TestIssue_VerifiesChainBeforeKeyOp proves INV-A1: with an instrumented fake keystore
// recording call order, the gate verifies the whole chain and approves BEFORE any key op,
// and exactly one key op runs, strictly after the gate consult. It also asserts a refused
// chain yields ZERO key ops.
func TestIssue_VerifiesChainBeforeKeyOp(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	envs, anchors, bc := singleAnchorChain(t, reg, "t1", "fido2:root-authenticator")
	f := newGateFixture(t, anchors, nil, nil, nil)

	body := PreconditionsBody{Chain: envs}
	pre, err := (func() ([]byte, error) { return encodePreconditionsForTest(body) })()
	if err != nil {
		t.Fatalf("encode preconditions: %v", err)
	}
	req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}

	res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
	if !res.decision.Approved {
		t.Fatalf("expected approval for a valid narrowing chain; got refusal: %s", refusalReason(t, res.decision))
	}
	if !res.keyOpRan {
		t.Fatal("keyOp did not run on approval")
	}
	if n := f.keystore.keyOps(); n != 1 {
		t.Fatalf("observed %d key ops, want exactly 1", n)
	}
	// Ordering: the gate consult ("gate") must strictly precede the single key op
	// ("keyop") -- no key op before the checks completed (INV-A1).
	got := f.log.snapshot()
	gi, ki := f.log.index("gate"), f.log.index("keyop")
	if gi < 0 || ki < 0 || gi >= ki {
		t.Fatalf("call order = %v, want gate strictly before keyop (INV-A1)", got)
	}
	// The credential must bind this chain's head digest.
	bm, err := ExtractBindingMaterial(res.credential)
	if err != nil {
		t.Fatalf("extract binding: %v", err)
	}
	if !bytesEqual(bm.ChainHeadDigest, bc.headDigest) {
		t.Fatalf("bound chain-head digest = %x, want %x", bm.ChainHeadDigest, bc.headDigest)
	}
}

// TestIssue_RefusesWithoutPrivateKeyOp proves that a failed check ⇒ no private-key op +
// a signed refusal (INV-A1 fail-closed spine). It uses a chain whose head WIDENS its
// parent, which the narrowing check must refuse, and asserts zero key ops and a verifying
// signed refusal naming the failed check.
func TestIssue_RefusesWithoutPrivateKeyOp(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	rootSigner, rootDER := signerWithDER(t)
	midSigner, midDER := signerWithDER(t)
	// Hop 1 WIDENS the root (adds scope "admin") -- a chain that widens is refused.
	hops := []hop{
		{delegatorID: "root", delegatorKeyID: "root-key", delegateID: "mid", authority: wideAuthority(), depthRemaining: 3, validity: openWindow()},
		{delegatorID: "mid", delegatorKeyID: "mid-key", delegateID: "leaf", authority: widerAuthority(), depthRemaining: 2, validity: openWindow()},
	}
	bc := buildChain(t, reg, "t1", hops, []crypto.Signer{rootSigner, midSigner}, [][]byte{rootDER, midDER})
	anchors := map[string]RootAnchor{"root-key": {PublicDER: rootDER, AuthRef: "fido2:x"}}
	f := newGateFixture(t, anchors, nil, nil, nil)

	pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: bc.envelopes})
	req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}

	res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
	if res.decision.Approved {
		t.Fatal("a widening chain was approved (INV-A2 enforcement failed)")
	}
	if res.keyOpRan || f.keystore.keyOps() != 0 {
		t.Fatalf("a refused issuance performed %d key ops, want ZERO (INV-A1)", f.keystore.keyOps())
	}
	art := decodeRefusalForTest(t, res.decision.RefusalRecord)
	if art.FailedCheck != CheckNarrowing {
		t.Fatalf("refusal failed_check = %q, want %q", art.FailedCheck, CheckNarrowing)
	}
	if art.HopIndex != 1 {
		t.Fatalf("refusal hop_index = %d, want 1 (the widening hop)", art.HopIndex)
	}
	if err := VerifyRefusal(f.refusalPub, art); err != nil {
		t.Fatalf("signed refusal does not verify: %v", err)
	}
}

// TestAuthority_WideningRefused proves the comparator monotonicity is RE-CHECKED in the
// signer: a chain widening ANY single dimension is refused, for each dimension. This is
// INV-A2's enforcement half, differential against the AGID-01 comparator.
func TestAuthority_WideningRefused(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	base := wideAuthority()
	widen := map[string]Authority{
		"scopes":            func() Authority { a := base; a.Scopes = append(append([]string{}, a.Scopes...), "admin"); return a }(),
		"tools":             func() Authority { a := base; a.Tools = append(append([]string{}, a.Tools...), "shell"); return a }(),
		"spend":             func() Authority { a := base; a.Spend = Budget{Amount: 5000, Currency: "usd"}; return a }(),
		"rate":              func() Authority { a := base; a.Rate = Rate{Limit: 500, Per: "minute"}; return a }(),
		"currency-mismatch": func() Authority { a := base; a.Spend = Budget{Amount: 10, Currency: "eur"}; return a }(),
		"validity": func() Authority {
			a := base
			a.Validity = Window{NotBefore: 1, NotAfter: 1 << 40}
			// parent has zero window (unbounded in the authority sense); widen makes child
			// exceed via a set NotAfter beyond parent's zero -> windowNested false.
			return a
		}(),
	}
	for name, child := range widen {
		t.Run(name, func(t *testing.T) {
			rootSigner, rootDER := signerWithDER(t)
			midSigner, midDER := signerWithDER(t)
			hops := []hop{
				{delegatorID: "root", delegatorKeyID: "root-key", delegateID: "mid", authority: base, depthRemaining: 3, validity: openWindow()},
				{delegatorID: "mid", delegatorKeyID: "mid-key", delegateID: "leaf", authority: child, depthRemaining: 2, validity: openWindow()},
			}
			bc := buildChain(t, reg, "t1", hops, []crypto.Signer{rootSigner, midSigner}, [][]byte{rootDER, midDER})
			anchors := map[string]RootAnchor{"root-key": {PublicDER: rootDER, AuthRef: "fido2:x"}}
			f := newGateFixture(t, anchors, nil, nil, nil)
			pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: bc.envelopes})
			req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}
			res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
			if res.decision.Approved {
				t.Fatalf("widening dimension %q was approved (must be refused)", name)
			}
			if f.keystore.keyOps() != 0 {
				t.Fatalf("widening %q performed a key op, want zero", name)
			}
			art := decodeRefusalForTest(t, res.decision.RefusalRecord)
			if art.FailedCheck != CheckNarrowing {
				t.Fatalf("widening %q: failed_check = %q, want %q", name, art.FailedCheck, CheckNarrowing)
			}
		})
	}
}

// TestIssue_ChainOnlyNoAgentStack proves fallback claim 31: a valid narrowing chain with
// NO agent-stack element yields a credential that binds the chain digest, verified before
// keygen. The bound material carries the chain-head digest and no agent-stack digest.
func TestIssue_ChainOnlyNoAgentStack(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	envs, anchors, bc := singleAnchorChain(t, reg, "t1", "fido2:root")
	f := newGateFixture(t, anchors, nil, nil, nil)
	pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: envs})
	// No SubjectRepr, no Attestation.
	req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}

	res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
	if !res.decision.Approved {
		t.Fatalf("chain-only issuance refused: %s", refusalReason(t, res.decision))
	}
	if f.log.index("gate") >= f.log.index("keyop") {
		t.Fatal("keygen did not follow verification (INV-A1)")
	}
	bm, err := ExtractBindingMaterial(res.credential)
	if err != nil {
		t.Fatalf("extract binding: %v", err)
	}
	if !bytesEqual(bm.ChainHeadDigest, bc.headDigest) {
		t.Fatalf("chain-only credential bound head %x, want %x", bm.ChainHeadDigest, bc.headDigest)
	}
	if len(bm.AgentStackDigest) != 0 {
		t.Fatalf("chain-only credential bound an agent-stack digest %x, want none (claim 31)", bm.AgentStackDigest)
	}
}

// ---- shared test-only encode/decode helpers ----

// encodePreconditionsForTest marshals a PreconditionsBody to the opaque seam bytes.
func encodePreconditionsForTest(body PreconditionsBody) ([]byte, error) {
	return jsonMarshal(body)
}

// refusalReason decodes and returns a human-readable refusal reason for failure messages.
func refusalReason(t *testing.T, dec signing.IssuanceDecision) string {
	t.Helper()
	if len(dec.RefusalRecord) == 0 {
		return "(no refusal record)"
	}
	art, err := DecodeRefusal(dec.RefusalRecord)
	if err != nil {
		return "(undecodable refusal)"
	}
	return art.FailedCheck + ": " + art.Detail
}

// decodeRefusalForTest decodes a refusal artifact, failing the test on error.
func decodeRefusalForTest(t *testing.T, b []byte) RefusalArtifact {
	t.Helper()
	if len(b) == 0 {
		t.Fatal("expected a signed refusal record, got none")
	}
	art, err := DecodeRefusal(b)
	if err != nil {
		t.Fatalf("decode refusal: %v", err)
	}
	return art
}
