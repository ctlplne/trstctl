package broker

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/graph"
)

func TestBrokerNewValidation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("empty TenantID accepted")
	}
	if _, err := New(Config{TenantID: "t1", Policy: gate{allow: true}, Graph: graph.New()}); err == nil {
		t.Error("missing Issuer accepted")
	}
}

func TestBrokerRevokeUnknownAgent(t *testing.T) {
	b := newBroker(t, graph.New(), gate{allow: true}, &memRevoker{}, &auditsink.Recorder{})
	if err := b.Revoke(context.Background(), "ghost"); err == nil {
		t.Error("revoking an unknown agent should error")
	}
}

func TestBrokerMissingAgentID(t *testing.T) {
	b := newBroker(t, graph.New(), gate{allow: true}, &memRevoker{}, &auditsink.Recorder{})
	wl, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer wl.Destroy()
	if _, err := b.Issue(context.Background(), IssueRequest{Method: "stub", Payload: []byte("genuine"), PublicKeyDER: wl.Public().DER}); err == nil {
		t.Error("empty AgentID accepted")
	}
}
