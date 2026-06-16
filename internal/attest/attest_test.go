package attest

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/graph"
)

type stubAttestor struct{}

func (stubAttestor) Method() string { return "stub" }
func (stubAttestor) Attest(_ context.Context, payload []byte) (Attestation, error) {
	if string(payload) != "genuine" {
		return Attestation{}, errors.New("bad proof")
	}
	return Attestation{Subject: "node-1", Selectors: []string{"stub:node:node-1"}, Claims: map[string]string{"region": "us"}}, nil
}

func TestVerifyRecordsAndBinds(t *testing.T) {
	g := graph.New()
	rec := &auditsink.Recorder{}
	v, err := NewVerifier(Config{TenantID: "t1", Attestors: []Attestor{stubAttestor{}}, Graph: g, Audit: rec})
	if err != nil {
		t.Fatal(err)
	}
	att, err := v.Verify(context.Background(), "stub", []byte("genuine"))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if att.ID == "" || att.Method != "stub" || att.Subject != "node-1" {
		t.Fatalf("bad attestation: %+v", att)
	}
	if _, ok := g.Node(att.ID); !ok {
		t.Error("attestation is not represented in the graph")
	}
	if rec.Count("attestation.verified") != 1 {
		t.Error("verification was not audited")
	}

	g.AddNode(graph.Node{ID: "cred-1", Kind: graph.KindCredential, Name: "cred"})
	if err := v.Bind(context.Background(), att, "cred-1"); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if !g.Reaches("cred-1", att.ID) {
		t.Error("no graph edge from the credential to the attestation it exhibits")
	}
	if rec.Count("attestation.bound") != 1 {
		t.Error("binding was not audited")
	}
}

func TestVerifyFailsClosedOnForgery(t *testing.T) {
	g := graph.New()
	rec := &auditsink.Recorder{}
	v, _ := NewVerifier(Config{TenantID: "t1", Attestors: []Attestor{stubAttestor{}}, Graph: g, Audit: rec})
	if _, err := v.Verify(context.Background(), "stub", []byte("forged")); err == nil {
		t.Fatal("Verify accepted a forged proof")
	}
	if g.Order() != 0 {
		t.Error("a forged attestation left a node in the graph")
	}
	if rec.Count("attestation.rejected") != 1 {
		t.Error("the rejection was not audited")
	}
}

func TestConformStub(t *testing.T) {
	if err := Conform(stubAttestor{}, []byte("genuine"), []byte("forged")); err != nil {
		t.Fatalf("Conform: %v", err)
	}
}
