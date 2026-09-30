// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// Reproduces a real legacy state in which two CA-pinned identities both wrote
// one Apache destination. New enrollment must refuse the second writer, and an
// existing conflict must stop renewal before it can enqueue another overwrite.
func TestTargetBindingConflictStopsEnrollmentAndRenewal(t *testing.T) {
	ctx := t.Context()
	st, log := newStore(t), openLog(t)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	owner, err := orch.CreateOwner(ctx, tenantA, "workload", "target owner", "")
	if err != nil {
		t.Fatal(err)
	}
	target, err := orch.UpsertDeploymentTarget(ctx, tenantA, store.DeploymentTarget{
		Name: "shared-apache", Type: "apache", Config: json.RawMessage(`{"executor":"agent"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := orch.CreateIdentity(ctx, tenantA, store.Identity{Kind: store.KindX509Certificate, Name: "shared.example.test", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	issuer := store.IdentityEndpointIssuer{OwnerID: owner.ID, Source: "platform", ID: "trstctl-issuing-ca", Name: "Platform CA", PreviewFingerprint: strings.Repeat("a", 64)}
	if _, err := orch.BindIdentityEndpoint(ctx, tenantA, first.ID, target, issuer); err != nil {
		t.Fatal(err)
	}
	if err := orch.Transition(ctx, tenantA, first.ID, orchestrator.StateIssued, "fixture issuance"); err != nil {
		t.Fatal(err)
	}
	if err := orch.Transition(ctx, tenantA, first.ID, orchestrator.StateDeployed, "fixture delivery"); err != nil {
		t.Fatal(err)
	}
	second, err := orch.CreateIdentity(ctx, tenantA, store.Identity{Kind: store.KindX509Certificate, Name: first.Name, OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	before, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orch.BindIdentityEndpoint(ctx, tenantA, second.ID, target, issuer); !errors.Is(err, store.ErrIdentityEnrollmentConflict) {
		t.Fatalf("second writer enrollment = %v, want target conflict", err)
	}
	after, err := log.LastSequence(ctx)
	if err != nil || after != before {
		t.Fatalf("refused enrollment changed event sequence %d -> %d: %v", before, after, err)
	}
	// Simulate the pre-repair competing binding as an old projection fixture.
	// It is deliberately not a command path; current commands must reject it.
	second.Status = "deployed"
	second.Attributes = json.RawMessage(`{"deployment_target_id":"` + target.ID + `","issuing_authority_source":"external","issuing_authority_id":"other-ca"}`)
	if err := st.UpsertIdentity(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := orch.Transition(ctx, tenantA, first.ID, orchestrator.StateRenewing, "scheduler due"); !errors.Is(err, store.ErrIdentityEnrollmentConflict) {
		t.Fatalf("competing renewal = %v, want target conflict", err)
	}
	after, err = log.LastSequence(ctx)
	if err != nil || after != before {
		t.Fatalf("refused renewal changed event sequence %d -> %d: %v", before, after, err)
	}
	conflicts, err := st.ConflictingTargetBindings(ctx, tenantB, target.ID, first.ID, "", false)
	if err != nil || len(conflicts) != 0 {
		t.Fatalf("foreign tenant learned binding %v: %v", conflicts, err)
	}
}
