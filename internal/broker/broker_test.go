package broker

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/ephemeral"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/policy"
)

type stubAtt struct{}

func (stubAtt) Method() string { return "stub" }
func (stubAtt) Attest(_ context.Context, p []byte) (attest.Attestation, error) {
	if string(p) != "genuine" {
		return attest.Attestation{}, errors.New("forged")
	}
	return attest.Attestation{Subject: "agent-workload", Selectors: []string{"stub:1"}}, nil
}

type gate struct {
	allow  bool
	reason string
}

func (g gate) Evaluate(_ context.Context, _ policy.Input) (policy.Decision, error) {
	return policy.Decision{Allow: g.allow, Reason: g.reason}, nil
}

type memRevoker struct{ revoked []string }

func (m *memRevoker) Revoke(_ context.Context, _, id string) error {
	m.revoked = append(m.revoked, id)
	return nil
}

func newBroker(t *testing.T, g *graph.Graph, pg PolicyGate, rev Revoker, rec auditsink.Auditor) *Broker {
	t.Helper()
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Destroy)
	caDER, _ := crypto.SelfSignedCACert(ca, "Agent CA", time.Hour)
	v, _ := attest.NewVerifier(attest.Config{TenantID: "t1", Attestors: []attest.Attestor{stubAtt{}}, Graph: g})
	sign := func(_ context.Context, att attest.Attestation, pubDER []byte, ttl time.Duration) ([]byte, error) {
		return crypto.SignSVID(caDER, ca, pubDER, "spiffe://example.org/agent/"+att.Subject, ttl)
	}
	eph, err := ephemeral.New(ephemeral.Config{
		TenantID: "t1", Verifier: v, Sign: sign,
		Policy: ephemeral.TTLPolicy{Default: 10 * time.Minute}, Idem: ephemeral.NewMemoryIdempotencer(),
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(Config{TenantID: "t1", Issuer: eph, Policy: pg, Graph: g, Audit: rec, Revoker: rev})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBrokerIssuesScopedAttestedIdentityWithBlastRadius(t *testing.T) {
	g := graph.New()
	rec := &auditsink.Recorder{}
	rev := &memRevoker{}
	b := newBroker(t, g, gate{allow: true}, rev, rec)
	wl, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer wl.Destroy()

	id, err := b.Issue(context.Background(), IssueRequest{
		AgentID: "agent-7", Method: "stub", Payload: []byte("genuine"),
		PublicKeyDER: wl.Public().DER, Scopes: []string{"read:files"}, IdempotencyKey: "k1",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// blast radius: the credential and the attestation it exhibits are reachable.
	radius := b.BlastRadius("agent-7")
	if len(radius) < 2 {
		t.Fatalf("blast radius = %d nodes, want >=2 (credential + attestation)", len(radius))
	}
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
		t.Errorf("blast radius missing credential(%v) or attestation(%v): %+v", sawCred, sawAtt, radius)
	}
	if rec.Count("agent.identity.issued") != 1 {
		t.Error("issuance not audited")
	}

	// one-action revoke
	if err := b.Revoke(context.Background(), "agent-7"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(rev.revoked) != 1 || rev.revoked[0] != id.CredentialID {
		t.Errorf("revoked = %v, want [%s]", rev.revoked, id.CredentialID)
	}
	if rec.Count("agent.identity.revoked") != 1 {
		t.Error("revocation not audited")
	}
}

func TestBrokerRefusesPolicyViolation(t *testing.T) {
	g := graph.New()
	rec := &auditsink.Recorder{}
	b := newBroker(t, g, gate{allow: false, reason: "scope not permitted"}, &memRevoker{}, rec)
	wl, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer wl.Destroy()
	if _, err := b.Issue(context.Background(), IssueRequest{
		AgentID: "rogue", Method: "stub", Payload: []byte("genuine"),
		PublicKeyDER: wl.Public().DER, Scopes: []string{"admin:*"}, IdempotencyKey: "k2",
	}); err == nil {
		t.Fatal("broker issued despite a policy denial")
	}
	if rec.Count("agent.identity.refused") != 1 {
		t.Error("policy refusal not audited")
	}
	if _, ok := g.Node(agentNodeID("rogue")); ok {
		t.Error("a denied agent was recorded in the graph")
	}
}
