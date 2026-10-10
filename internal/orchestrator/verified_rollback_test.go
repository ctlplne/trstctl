// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

func TestVerifiedHostRollbackUndeploysWithoutAnotherEffect(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	ctx := context.Background()
	mustRegisterTenant(t, st, tenantA)
	owner, err := orch.CreateOwner(ctx, tenantA, "team", "rollback", "rollback@example.test")
	if err != nil {
		t.Fatal(err)
	}
	identity := issuedIdentity(t, ctx, st, orch, tenantA, owner.ID, "host-rollback")
	if err := orch.Transition(ctx, tenantA, identity.ID, orchestrator.StateDeployed, "deployed on host"); err != nil {
		t.Fatal(err)
	}
	if orchestrator.CanTransition(orchestrator.StateDeployed, orchestrator.StateIssued) {
		t.Fatal("public lifecycle preview exposes the privileged rollback edge")
	}
	before := countOutboxDestination(t, st, tenantA, "connector.rollback")
	if err := orch.Transition(ctx, tenantA, identity.ID, orchestrator.StateIssued, "claim rollback"); err == nil {
		t.Fatal("generic lifecycle caller claimed a host rollback")
	}
	if err := orch.TransitionAfterCompletedSideEffect(ctx, tenantA, identity.ID, orchestrator.StateIssued, "claim rollback", "connector.rollback"); err == nil {
		t.Fatal("generic completed-side-effect caller claimed a host rollback")
	}
	mustStatus(t, st, tenantA, identity.ID, "deployed")
	if err := orch.TransitionAfterVerifiedRollback(ctx, tenantA, identity.ID); err != nil {
		t.Fatal(err)
	}
	mustStatus(t, st, tenantA, identity.ID, "issued")
	if countIdentityTransitions(t, st, tenantA, identity.ID, projections.EventIdentityUndeployed) != 1 {
		t.Fatal("verified rollback has no durable identity history")
	}
	if after := countOutboxDestination(t, st, tenantA, "connector.rollback"); after != before {
		t.Fatalf("completed host rollback enqueued a second external effect: %d to %d", before, after)
	}
}
