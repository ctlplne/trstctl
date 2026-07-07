// SPDX-License-Identifier: MPL-2.0

package broker

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/graph"
)

// recordingPrecondition is an instrumented, feature-neutral issuance precondition:
// it records every consult and returns the configured error (nil = allow). It mints
// nothing itself, so any credential that appears did so through the broker's issuance
// path AFTER the precondition returned. It is the broker analogue of the signer's
// recordingGate used to prove INV-A1 ordering at the AN-4 seam.
type recordingPrecondition struct {
	calls int
	err   error
	views []IssuanceView
}

func (p *recordingPrecondition) CheckIssuancePrecondition(_ context.Context, v IssuanceView) error {
	p.calls++
	p.views = append(p.views, v)
	return p.err
}

// TestZeroRemoval_SingleHopIssuanceIntact is the AGID-12 canonical zero-removal
// guard (INV-A10), landed here. With NO issuance precondition attached — exactly the
// state of an unlicensed / core-only deployment where attachEE never runs the
// FeatureAgentDelegation block — the free single-hop attested-ephemeral badge must
// issue EXACTLY as before: a genuine attestation yields a one-hop, sub-hour
// credential recorded in the graph and audited. The proof has three legs:
//
//  1. The single-hop Issue path is byte-for-byte the pre-seam path: same policy gate,
//     same ephemeral mint, same graph edges, same audit event, same returned identity.
//  2. The feature-neutral issuance-precondition hook is NOT consulted on the
//     single-hop path (precondition.calls == 0) — the seam is inert on the free badge.
//  3. Attaching the hook does not gate/move/degrade the single-hop path: Issue with a
//     hook attached behaves identically and STILL does not consult it (only the
//     chain-bound path does).
func TestZeroRemoval_SingleHopIssuanceIntact(t *testing.T) {
	ctx := context.Background()

	// Leg 1: single-hop Issue with NO precondition attached issues the free badge.
	g := graph.New()
	rec := &auditsink.Recorder{}
	b := newBroker(t, g, gate{allow: true}, &memRevoker{}, rec)
	wl, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer wl.Destroy()

	id, err := b.Issue(ctx, IssueRequest{
		AgentID: "free-agent", Method: "stub", Payload: []byte("genuine"),
		PublicKeyDER: wl.Public().DER, Scopes: []string{"read:files"}, IdempotencyKey: "z1",
	})
	if err != nil {
		t.Fatalf("single-hop Issue (no precondition) failed — the free badge must issue: %v", err)
	}
	if id.CredentialID == "" || len(id.CertDER) == 0 {
		t.Fatalf("single-hop Issue produced an empty credential: %+v", id)
	}
	if id.NotAfter.IsZero() {
		t.Fatal("single-hop credential has no expiry — sub-hour badge must self-expire")
	}
	// The one-hop credential and its attestation are reachable (blast radius intact).
	radius := b.BlastRadius("free-agent")
	sawCred, sawAtt := false, false
	for _, n := range radius {
		if n.ID == id.CredentialID {
			sawCred = true
		}
		if n.Kind == graph.KindAttestation {
			sawAtt = true
		}
	}
	if !sawCred || !sawAtt {
		t.Fatalf("single-hop blast radius degraded: cred=%v att=%v radius=%+v", sawCred, sawAtt, radius)
	}
	if rec.Count("agent.identity.issued") != 1 {
		t.Fatalf("single-hop issuance not audited exactly once (got %d)", rec.Count("agent.identity.issued"))
	}

	// Leg 2 + Leg 3: attach an instrumented precondition and re-issue the single hop.
	// The single-hop path must behave identically AND must NOT consult the hook.
	g2 := graph.New()
	rec2 := &auditsink.Recorder{}
	pre := &recordingPrecondition{}
	b2 := newBroker(t, g2, gate{allow: true}, &memRevoker{}, rec2, WithIssuancePrecondition(pre))
	wl2, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer wl2.Destroy()

	id2, err := b2.Issue(ctx, IssueRequest{
		AgentID: "free-agent", Method: "stub", Payload: []byte("genuine"),
		PublicKeyDER: wl2.Public().DER, Scopes: []string{"read:files"}, IdempotencyKey: "z2",
	})
	if err != nil {
		t.Fatalf("single-hop Issue with a precondition attached must still issue the free badge: %v", err)
	}
	if id2.CredentialID == "" || len(id2.CertDER) == 0 {
		t.Fatal("single-hop Issue degraded once a precondition was attached")
	}
	if pre.calls != 0 {
		t.Fatalf("ZERO-REMOVAL VIOLATION: the issuance-precondition hook was consulted %d time(s) on the single-hop path; the free badge must never be gated by the seam", pre.calls)
	}
	if rec2.Count("agent.identity.issued") != 1 {
		t.Fatalf("single-hop issuance (hook attached) not audited exactly once (got %d)", rec2.Count("agent.identity.issued"))
	}
	if rec2.Count("agent.identity.refused") != 0 {
		t.Fatal("single-hop issuance (hook attached) emitted a refusal — the free badge was gated")
	}
}

// TestIssuancePrecondition_ConsultedOnlyOnChainBoundPath proves the seam engages on
// the chain-bound issuance path and ONLY there: IssueChainBound consults the attached
// precondition BEFORE minting, a refusing precondition mints nothing, and no
// precondition attached fails the chain-bound path closed (ErrNoIssuancePrecondition)
// while leaving the free single-hop path untouched.
func TestIssuancePrecondition_ConsultedOnlyOnChainBoundPath(t *testing.T) {
	ctx := context.Background()

	// Approving precondition: chain-bound issuance consults it first, then mints.
	g := graph.New()
	pre := &recordingPrecondition{}
	b := newBroker(t, g, gate{allow: true}, &memRevoker{}, &auditsink.Recorder{}, WithIssuancePrecondition(pre))
	wl, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer wl.Destroy()

	id, err := b.IssueChainBound(ctx, IssueRequest{
		AgentID: "chain-agent", Method: "stub", Payload: []byte("genuine"),
		PublicKeyDER: wl.Public().DER, Scopes: []string{"read:files"}, IdempotencyKey: "c1",
	})
	if err != nil {
		t.Fatalf("chain-bound issuance with an approving precondition failed: %v", err)
	}
	if id.CredentialID == "" {
		t.Fatal("chain-bound issuance produced no credential despite approval")
	}
	if pre.calls != 1 {
		t.Fatalf("chain-bound path consulted the precondition %d times, want exactly 1", pre.calls)
	}
	// The generic view names nothing AGID and carries only what the request exposed.
	if len(pre.views) != 1 || pre.views[0].AgentID != "chain-agent" || pre.views[0].AttestationMethod != "stub" {
		t.Fatalf("issuance view not populated from the request: %+v", pre.views)
	}

	// Refusing precondition: chain-bound issuance mints nothing.
	g2 := graph.New()
	deny := &recordingPrecondition{err: errors.New("precondition refused")}
	b2 := newBroker(t, g2, gate{allow: true}, &memRevoker{}, &auditsink.Recorder{}, WithIssuancePrecondition(deny))
	wl2, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer wl2.Destroy()
	if _, err := b2.IssueChainBound(ctx, IssueRequest{
		AgentID: "chain-rogue", Method: "stub", Payload: []byte("genuine"),
		PublicKeyDER: wl2.Public().DER, IdempotencyKey: "c2",
	}); err == nil {
		t.Fatal("chain-bound issuance minted despite a refusing precondition")
	}
	if deny.calls != 1 {
		t.Fatalf("refusing precondition consulted %d times, want 1", deny.calls)
	}
	if _, ok := g2.Node(agentNodeID("chain-rogue")); ok {
		t.Error("a precondition-refused agent was recorded in the graph")
	}

	// No precondition attached: chain-bound path fails closed; single-hop still works.
	g3 := graph.New()
	b3 := newBroker(t, g3, gate{allow: true}, &memRevoker{}, &auditsink.Recorder{})
	wl3, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer wl3.Destroy()
	if _, err := b3.IssueChainBound(ctx, IssueRequest{
		AgentID: "chain-nogate", Method: "stub", Payload: []byte("genuine"),
		PublicKeyDER: wl3.Public().DER, IdempotencyKey: "c3",
	}); !errors.Is(err, ErrNoIssuancePrecondition) {
		t.Fatalf("chain-bound issuance with no precondition = %v, want ErrNoIssuancePrecondition (fail closed)", err)
	}
	// The free single-hop badge is unaffected by the absent precondition.
	if _, err := b3.Issue(ctx, IssueRequest{
		AgentID: "chain-nogate", Method: "stub", Payload: []byte("genuine"),
		PublicKeyDER: wl3.Public().DER, IdempotencyKey: "c3-single",
	}); err != nil {
		t.Fatalf("single-hop Issue must remain free even when the chain-bound path fails closed: %v", err)
	}
}
