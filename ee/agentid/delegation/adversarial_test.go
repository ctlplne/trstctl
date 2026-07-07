// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// TestGate_AdversarialChainsFailClosed is the adversarial table (card): forged /
// replayed / spliced-from-different-trees / widened / attestation-replay each ⇒ a signed
// refusal + ZERO key ops, inside the boundary. Every case drives the real gate through
// the instrumented fake keystore.
func TestGate_AdversarialChainsFailClosed(t *testing.T) {
	reg := (*ToolRegistry)(nil)

	type tc struct {
		name      string
		build     func(t *testing.T) (req signing.IssuancePreconditions, anchors map[string]RootAnchor, seedAtt func(*fakeAttestor))
		wantCheck string
	}

	cases := []tc{
		{
			name: "forged-signature (tampered authority after signing)",
			build: func(t *testing.T) (signing.IssuancePreconditions, map[string]RootAnchor, func(*fakeAttestor)) {
				envs, anchors, _ := singleAnchorChain(t, reg, "t1", "fido2:root")
				// Tamper the head hop's authority AFTER it was signed: widen scopes. The
				// carried signature no longer covers these bytes -> signature check fails.
				envs[1].Record.Authority.Scopes = append(envs[1].Record.Authority.Scopes, "admin")
				pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: envs})
				return signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}, anchors, nil
			},
			wantCheck: CheckHopSignature,
		},
		{
			name: "forged-root-key (attacker attaches own key to a self-anchored record)",
			build: func(t *testing.T) (signing.IssuancePreconditions, map[string]RootAnchor, func(*fakeAttestor)) {
				// The attacker mints a fully valid, self-consistent chain with THEIR OWN
				// root key -- signatures verify against the carried key, but the key is not
				// a held anchor.
				attackerRoot, attackerDER := signerWithDER(t)
				midSigner, midDER := signerWithDER(t)
				hops := []hop{
					{delegatorID: "evil", delegatorKeyID: "evil-key", delegateID: "mid", authority: wideAuthority(), depthRemaining: 3, validity: openWindow()},
					{delegatorID: "mid", delegatorKeyID: "mid-key", delegateID: "leaf", authority: narrowerAuthority(), depthRemaining: 2, validity: openWindow()},
				}
				bc := buildChain(t, reg, "t1", hops, []crypto.Signer{attackerRoot, midSigner}, [][]byte{attackerDER, midDER})
				pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: bc.envelopes})
				// The trust store holds a DIFFERENT root key, not the attacker's.
				_, legitDER := signerWithDER(t)
				anchors := map[string]RootAnchor{"legit-key": {PublicDER: legitDER, AuthRef: "fido2:legit"}}
				return signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}, anchors, nil
			},
			wantCheck: CheckRootAnchor,
		},
		{
			name: "spliced-chain (head from a different tree, wrong parent digest)",
			build: func(t *testing.T) (signing.IssuancePreconditions, map[string]RootAnchor, func(*fakeAttestor)) {
				// Tree A: valid root -> mid.
				envsA, anchors, _ := singleAnchorChain(t, reg, "t1", "fido2:root")
				// Tree B: an unrelated hop signed by a different mid key, whose ParentDigest
				// points at tree B's (absent) root, not tree A's mid.
				otherMid, otherMidDER := signerWithDER(t)
				spliced := Record{
					TenantID: "t1", DelegatorID: "other-mid", DelegatorKey: KeyRef{ID: "other-mid-key", Algorithm: "ECDSA-P256"},
					DelegateID: "leaf", Authority: narrowerAuthority(), DepthRemaining: 1, Validity: openWindow(),
					ParentDigest: []byte("this-is-not-tree-As-mid-digest!!"),
				}
				signedSpliced, err := spliced.Sign(otherMid, reg)
				if err != nil {
					t.Fatalf("sign spliced: %v", err)
				}
				chain := append(append([]RecordEnvelope{}, envsA[0]), RecordEnvelope{Record: signedSpliced, DelegatorPublicDER: otherMidDER})
				pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: chain})
				return signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}, anchors, nil
			},
			wantCheck: CheckChainLinkage,
		},
		{
			name: "widened-scopes (head broader than parent)",
			build: func(t *testing.T) (signing.IssuancePreconditions, map[string]RootAnchor, func(*fakeAttestor)) {
				rootSigner, rootDER := signerWithDER(t)
				midSigner, midDER := signerWithDER(t)
				hops := []hop{
					{delegatorID: "root", delegatorKeyID: "root-key", delegateID: "mid", authority: wideAuthority(), depthRemaining: 3, validity: openWindow()},
					{delegatorID: "mid", delegatorKeyID: "mid-key", delegateID: "leaf", authority: widerAuthority(), depthRemaining: 2, validity: openWindow()},
				}
				bc := buildChain(t, reg, "t1", hops, []crypto.Signer{rootSigner, midSigner}, [][]byte{rootDER, midDER})
				anchors := map[string]RootAnchor{"root-key": {PublicDER: rootDER, AuthRef: "fido2:x"}}
				pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: bc.envelopes})
				return signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}, anchors, nil
			},
			wantCheck: CheckNarrowing,
		},
		{
			name: "attestation-replay (a payload the verifier does not accept)",
			build: func(t *testing.T) (signing.IssuancePreconditions, map[string]RootAnchor, func(*fakeAttestor)) {
				envs, anchors, _ := singleAnchorChain(t, reg, "t1", "fido2:root")
				pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: envs, DesignatedClass: "privileged"})
				req := signing.IssuancePreconditions{
					TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre,
					Attestation:       attBody(t, "tpm", []byte("REPLAYED-STALE-QUOTE")),
					AttestationMethod: "tpm",
				}
				// Seed the verifier with the GENUINE payload only; the replayed one differs.
				return req, anchors, func(fa *fakeAttestor) {
					fa.seed("tpm", []byte("genuine-fresh-quote"), VerifiedAttestation{Subject: "i-1", Method: "tpm"})
				}
			},
			wantCheck: CheckAttestation,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, anchors, seedAtt := c.build(t)
			minClass := MinClassPolicy{"privileged": ClassHardwareTPM}
			f := newGateFixture(t, anchors, minClass, nil, nil)
			if seedAtt != nil {
				seedAtt(f.attestor)
			}
			res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
			if res.decision.Approved {
				t.Fatalf("%s: adversarial input was APPROVED (must fail closed)", c.name)
			}
			if f.keystore.keyOps() != 0 {
				t.Fatalf("%s: %d key ops on an adversarial input, want ZERO (INV-A1)", c.name, f.keystore.keyOps())
			}
			art := decodeRefusalForTest(t, res.decision.RefusalRecord)
			if art.FailedCheck != c.wantCheck {
				t.Fatalf("%s: failed_check = %q, want %q (detail: %q)", c.name, art.FailedCheck, c.wantCheck, art.Detail)
			}
			if err := VerifyRefusal(f.refusalPub, art); err != nil {
				t.Fatalf("%s: signed refusal does not verify: %v", c.name, err)
			}
		})
	}
}

// TestGate_ExpiryDepthRevocationRefused covers the remaining first-limb checks: an
// expired hop, a depth violation, and a revoked hop each ⇒ refusal + zero key ops.
func TestGate_ExpiryDepthRevocationRefused(t *testing.T) {
	reg := (*ToolRegistry)(nil)

	t.Run("expired-hop", func(t *testing.T) {
		rootSigner, rootDER := signerWithDER(t)
		midSigner, midDER := signerWithDER(t)
		hops := []hop{
			{delegatorID: "root", delegatorKeyID: "root-key", delegateID: "mid", authority: wideAuthority(), depthRemaining: 3, validity: Window{NotBefore: 1000, NotAfter: 2000}},
			{delegatorID: "mid", delegatorKeyID: "mid-key", delegateID: "leaf", authority: narrowerAuthority(), depthRemaining: 2, validity: Window{NotBefore: 1000, NotAfter: 2000}},
		}
		bc := buildChain(t, reg, "t1", hops, []crypto.Signer{rootSigner, midSigner}, [][]byte{rootDER, midDER})
		anchors := map[string]RootAnchor{"root-key": {PublicDER: rootDER, AuthRef: "fido2:x"}}
		// Clock is 3000 -- past NotAfter 2000.
		f := newGateFixture(t, anchors, nil, nil, fixedClock(3000))
		pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: bc.envelopes})
		req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}
		res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
		if res.decision.Approved || f.keystore.keyOps() != 0 {
			t.Fatalf("expired chain approved or performed a key op")
		}
		if art := decodeRefusalForTest(t, res.decision.RefusalRecord); art.FailedCheck != CheckExpiry {
			t.Fatalf("failed_check = %q, want %q", art.FailedCheck, CheckExpiry)
		}
	})

	t.Run("depth-not-decremented", func(t *testing.T) {
		rootSigner, rootDER := signerWithDER(t)
		midSigner, midDER := signerWithDER(t)
		// Child depth_remaining (3) is NOT less than parent's (3): depth accounting fails.
		hops := []hop{
			{delegatorID: "root", delegatorKeyID: "root-key", delegateID: "mid", authority: wideAuthority(), depthRemaining: 3, validity: openWindow()},
			{delegatorID: "mid", delegatorKeyID: "mid-key", delegateID: "leaf", authority: narrowerAuthority(), depthRemaining: 3, validity: openWindow()},
		}
		bc := buildChain(t, reg, "t1", hops, []crypto.Signer{rootSigner, midSigner}, [][]byte{rootDER, midDER})
		anchors := map[string]RootAnchor{"root-key": {PublicDER: rootDER, AuthRef: "fido2:x"}}
		f := newGateFixture(t, anchors, nil, nil, nil)
		pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: bc.envelopes})
		req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}
		res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
		if res.decision.Approved || f.keystore.keyOps() != 0 {
			t.Fatalf("depth-violating chain approved or performed a key op")
		}
		if art := decodeRefusalForTest(t, res.decision.RefusalRecord); art.FailedCheck != CheckDepth {
			t.Fatalf("failed_check = %q, want %q", art.FailedCheck, CheckDepth)
		}
	})

	t.Run("revoked-ancestor", func(t *testing.T) {
		envs, anchors, bc := singleAnchorChain(t, reg, "t1", "fido2:root")
		// Revoke the ROOT hop digest: an ancestor revocation stops a fresh descendant.
		rootDigest, err := envs[0].Record.Digest(reg)
		if err != nil {
			t.Fatalf("root digest: %v", err)
		}
		rev := MapRevocationReader{Revoked: map[string]map[string]struct{}{
			"t1": {hexOf(rootDigest): {}},
		}}
		f := newGateFixture(t, anchors, nil, rev, nil)
		pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: envs})
		req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}
		res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
		if res.decision.Approved || f.keystore.keyOps() != 0 {
			t.Fatalf("revoked chain approved or performed a key op")
		}
		if art := decodeRefusalForTest(t, res.decision.RefusalRecord); art.FailedCheck != CheckRevocation {
			t.Fatalf("failed_check = %q, want %q", art.FailedCheck, CheckRevocation)
		}
		_ = bc
	})

	t.Run("revocation-reader-error-fails-closed", func(t *testing.T) {
		envs, anchors, _ := singleAnchorChain(t, reg, "t1", "fido2:root")
		rev := MapRevocationReader{Err: errReader}
		f := newGateFixture(t, anchors, nil, rev, nil)
		pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: envs})
		req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}
		res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
		if res.decision.Approved || f.keystore.keyOps() != 0 {
			t.Fatal("a revocation-reader error did not fail closed")
		}
		if art := decodeRefusalForTest(t, res.decision.RefusalRecord); art.FailedCheck != CheckRevocation {
			t.Fatalf("failed_check = %q, want %q", art.FailedCheck, CheckRevocation)
		}
	})
}

// errReader is a sentinel error for the reader-error fail-closed case.
var errReader = errReaderErr{}

type errReaderErr struct{}

func (errReaderErr) Error() string { return "revocation reader unavailable" }
