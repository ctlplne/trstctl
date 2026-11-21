// SPDX-License-Identifier: BUSL-1.1

package delegation

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

func criticalValidityChain(t *testing.T, authority Window) ([]RecordEnvelope, map[string]RootAnchor) {
	t.Helper()
	rootSigner, rootDER := signerWithDER(t)
	midSigner, midDER := signerWithDER(t)
	wide, narrow := wideAuthority(), narrowerAuthority()
	wide.Validity, narrow.Validity = authority, authority
	hops := []hop{
		{delegatorID: "root", delegatorKeyID: "root-key", delegateID: "mid", authority: wide, depthRemaining: 3, validity: openWindow()},
		{delegatorID: "mid", delegatorKeyID: "mid-key", delegateID: "leaf", authority: narrow, depthRemaining: 2, validity: openWindow()},
	}
	chain := buildChain(t, nil, "t1", hops, []crypto.Signer{rootSigner, midSigner}, [][]byte{rootDER, midDER}).envelopes
	return chain, map[string]RootAnchor{"root-key": {PublicDER: rootDER, AuthRef: "fido2:root"}}
}

func TestCR949SignerRefusesExpiredConferredAuthority(t *testing.T) {
	chain, anchors := criticalValidityChain(t, Window{NotBefore: 1, NotAfter: 2})
	f := newGateFixture(t, anchors, nil, nil, fixedClock(2_000_000_000))
	pre, err := encodePreconditionsForTest(PreconditionsBody{Chain: chain})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := f.gate.VerifyIssuancePreconditions(t.Context(), signing.IssuancePreconditions{
		TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Approved {
		t.Fatal("signer approved a delegation whose conferred authority expired in 1970")
	}
	if refusal := decodeRefusalForTest(t, decision.RefusalRecord); refusal.FailedCheck != CheckExpiry {
		t.Fatalf("refusal check = %q, want %q", refusal.FailedCheck, CheckExpiry)
	}
}

func TestCR949AuthorityWindowBoundsSubHourCredential(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	chain, _ := criticalValidityChain(t, Window{NotBefore: now.Add(-time.Minute).Unix(), NotAfter: now.Add(90 * time.Second).Unix()})
	ttl, err := SubHourCeiling(chain, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	if ttl > 90*time.Second {
		t.Fatalf("authority expires in 90 seconds but signer ceiling is %s", ttl)
	}
}

func TestCR292SignerLifetimeNeverDefaultsPastChainCeiling(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	chain, _ := criticalValidityChain(t, Window{NotBefore: now.Add(-time.Minute).Unix(), NotAfter: now.Add(20 * time.Minute).Unix()})
	pre, err := encodePreconditionsForTest(PreconditionsBody{Chain: chain})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		notAfter int64
		max      int64
	}{
		{name: "implicit expiry", max: 20 * 60},
		{name: "expired request", notAfter: now.Unix() - 1, max: 0},
		{name: "ten-year request", notAfter: now.Add(10 * 365 * 24 * time.Hour).Unix(), max: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ttl := issuanceTTLSeconds(signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre, NotAfter: tc.notAfter}, now)
			if ttl > tc.max {
				t.Fatalf("signer TTL = %d seconds, want at most %d", ttl, tc.max)
			}
		})
	}
}

func TestCR292GatedIssueRefusesOverlongOrExpiredLifetimeBeforeKeygen(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	chain, anchors := criticalValidityChain(t, Window{NotBefore: now.Add(-time.Minute).Unix(), NotAfter: now.Add(20 * time.Minute).Unix()})
	pre, err := encodePreconditionsForTest(PreconditionsBody{Chain: chain})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		notAfter int64
	}{
		{name: "past", notAfter: now.Add(-time.Second).Unix()},
		{name: "beyond authority", notAfter: now.Add(21 * time.Minute).Unix()},
		{name: "ten years", notAfter: now.Add(10 * 365 * 24 * time.Hour).Unix()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newGateFixture(t, anchors, nil, nil, fixedClock(now.Unix()))
			res := runGatedIssue(t, f.log, f.gate, signing.IssuancePreconditions{
				TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre, NotAfter: tc.notAfter,
			}, f.mintKeyOp(t))
			if res.decision.Approved || res.keyOpRan || f.keystore.keyOps() != 0 {
				t.Fatalf("invalid lifetime approved=%t, key op ran=%t, key ops=%d", res.decision.Approved, res.keyOpRan, f.keystore.keyOps())
			}
			if refusal := decodeRefusalForTest(t, res.decision.RefusalRecord); refusal.FailedCheck != CheckExpiry {
				t.Fatalf("refusal check = %q, want %q", refusal.FailedCheck, CheckExpiry)
			}
		})
	}
}

func TestCR292SignerKeyOpSignsWithinConferredAuthority(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	bound := now.Add(20 * time.Minute)
	chain, _ := criticalValidityChain(t, Window{NotBefore: now.Add(-time.Minute).Unix(), NotAfter: bound.Unix()})
	pre, err := encodePreconditionsForTest(PreconditionsBody{Chain: chain})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := NewBindingMaterial([]byte("chain-head-digest"), nil, "", nil, "fido2:root", nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := binding.Encode()
	if err != nil {
		t.Fatal(err)
	}
	op := NewIssuanceKeyOp(IssuanceKeyOpConfig{})
	_ = signing.NewServer(signing.WithIssuanceKeyOp(op)) // inject real signer custody
	issued, err := op.MintApprovedCredential(context.Background(), signing.IssuancePreconditions{
		TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre,
	}, signing.IssuanceDecision{Approved: true, BindingMaterial: encoded}, crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	_, notAfter, err := crypto.CertValidity(issued.EncodedRecord)
	if err != nil {
		t.Fatal(err)
	}
	if notAfter.After(bound) {
		t.Fatalf("signed certificate expires at %s after conferred authority at %s", notAfter, bound)
	}
}
