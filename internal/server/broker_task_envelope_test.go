// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
)

// B-7: the rule that makes a task binding worth anything is what the core does
// when it CANNOT verify one. Silently issuing an unscoped credential in place
// of the scoped one the caller asked for is the failure an attacker would
// engineer, so it must be a refusal.
func TestBrokerRefusesTaskEnvelopeWithoutLicensedGate(t *testing.T) {
	svc := &agentBrokerService{} // no gate: Community / core-only build

	digest, err := svc.bindTaskEnvelope(context.Background(), "tenant-a", api.BrokerAgentIdentityRequest{
		TaskEnvelope: []byte(`{"requester_id":"r"}`),
	})
	if err == nil {
		t.Fatal("an envelope-bearing request was issued with no gate installed")
	}
	if !errors.Is(err, api.ErrBrokerRejected) {
		t.Fatalf("error = %v, want ErrBrokerRejected so the caller sees a refusal, not a server fault", err)
	}
	if digest != nil {
		t.Fatal("a refused envelope returned a digest")
	}
}

// No envelope means the ordinary single-hop badge, unchanged (INV-A10 zero
// removal): the free path must not acquire a new precondition.
func TestBrokerWithoutTaskEnvelopeIsUnchanged(t *testing.T) {
	svc := &agentBrokerService{}

	digest, err := svc.bindTaskEnvelope(context.Background(), "tenant-a", api.BrokerAgentIdentityRequest{})
	if err != nil || digest != nil {
		t.Fatalf("free single-hop path changed: digest=%v err=%v", digest, err)
	}
}

func TestBrokerBindsVerifiedTaskEnvelopeDigest(t *testing.T) {
	var sawTenant string
	svc := &agentBrokerService{
		taskEnvelopeGate: func(_ context.Context, tenantID string, envelope []byte, _ time.Time) ([]byte, error) {
			sawTenant = tenantID
			if len(envelope) == 0 {
				t.Error("gate received an empty envelope")
			}
			return []byte{0xde, 0xad}, nil
		},
	}

	digest, err := svc.bindTaskEnvelope(context.Background(), "tenant-a", api.BrokerAgentIdentityRequest{
		TaskEnvelope: []byte(`{"requester_id":"r"}`),
	})
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	if string(digest) != string([]byte{0xde, 0xad}) {
		t.Fatalf("digest = %x, want the gate's verified digest", digest)
	}
	// The gate is tenant-scoped: a requester key trusted for one tenant must
	// not be resolved on behalf of another.
	if sawTenant != "tenant-a" {
		t.Fatalf("gate called with tenant %q", sawTenant)
	}
}

func TestBrokerRefusesWhenGateRejectsOrReturnsNoDigest(t *testing.T) {
	rejecting := &agentBrokerService{
		taskEnvelopeGate: func(context.Context, string, []byte, time.Time) ([]byte, error) {
			return nil, errors.New("taskenv: task envelope is expired or not yet valid")
		},
	}
	if _, err := rejecting.bindTaskEnvelope(context.Background(), "t", api.BrokerAgentIdentityRequest{TaskEnvelope: []byte("x")}); err == nil {
		t.Fatal("a rejected envelope was accepted")
	} else if !errors.Is(err, api.ErrBrokerRejected) {
		t.Fatalf("error = %v, want ErrBrokerRejected", err)
	}

	// A gate that verifies but yields nothing to bind is a broken gate, not a
	// licence to issue an unbound credential.
	silent := &agentBrokerService{
		taskEnvelopeGate: func(context.Context, string, []byte, time.Time) ([]byte, error) { return nil, nil },
	}
	if _, err := silent.bindTaskEnvelope(context.Background(), "t", api.BrokerAgentIdentityRequest{TaskEnvelope: []byte("x")}); err == nil {
		t.Fatal("a gate returning no digest was treated as success")
	}
}
