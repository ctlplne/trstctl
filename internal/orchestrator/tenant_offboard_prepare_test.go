// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/tenancy"
)

func TestTenantOffboardPreparationBindsActorWithoutDeletingData(t *testing.T) {
	ctx := events.ContextWithActor(t.Context(), events.Actor{Subject: "original-admin", Roles: []string{"admin"}})
	st, log := newStore(t), openLog(t)
	projector := projections.New(st)
	registration, err := orchestrator.ExecuteTenantRegistration(ctx, log, st, projector,
		orchestrator.NewIdempotency(st), registrationCommand(tenantA, "Prepared customer", "register-prepared"))
	if err != nil {
		t.Fatal(err)
	}
	orch := orchestrator.NewOrchestrator(log, st, nil, orchestrator.WithProjector(projector))
	owner, err := orch.CreateOwner(ctx, tenantA, "team", "Preserved during preparation", "qa@example.test")
	if err != nil {
		t.Fatal(err)
	}
	command := orchestrator.TenantOffboardCommand{TenantID: tenantA, RegistrationIdentity: registration.ID}
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := orch.PrepareTenantOffboard(ctx, command); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.RequireLiveTenantService(ctx, tenantA); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Fatalf("prepared core service = %v", err)
	}
	if _, err := st.GetOwner(ctx, tenantA, owner.ID); err != nil {
		t.Fatalf("preparation removed customer owner: %v", err)
	}
	if _, err := st.GetTenant(ctx, tenantA); err != nil {
		t.Fatalf("preparation removed customer tenant: %v", err)
	}
	if after, err := log.LastSequence(ctx); err != nil || after != head {
		t.Fatalf("preparation appended source event: %d -> %d, %v", head, after, err)
	}
	otherActor := events.ContextWithActor(t.Context(), events.Actor{Subject: "different-admin", Roles: []string{"admin"}})
	if err := orch.PrepareTenantOffboard(otherActor, command); !errors.Is(err, orchestrator.ErrIdempotencyConflict) {
		t.Fatalf("different actor took prepared command: %v", err)
	}
	wrong := command
	wrong.RegistrationIdentity = "different-registration"
	if err := orch.PrepareTenantOffboard(ctx, wrong); !errors.Is(err, orchestrator.ErrIdempotencyConflict) {
		t.Fatalf("different registration took prepared command: %v", err)
	}
	// A fresh orchestrator recovers only from the durable receiver and log.
	restarted := orchestrator.NewOrchestrator(log, st, nil, orchestrator.WithProjector(projector))
	if _, err := restarted.OffboardTenant(otherActor, command); !errors.Is(err, orchestrator.ErrIdempotencyConflict) {
		t.Fatalf("different actor completed prepared deletion: %v", err)
	}
	if _, err := restarted.OffboardTenant(ctx, command); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetTenant(ctx, tenantA); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("exact completion left tenant: %v", err)
	}
	if countTenantEvents(t, log, tenantA, projections.EventTenantOffboarded) != 1 {
		t.Fatal("prepared completion did not retain exactly one deletion event")
	}
	if err := restarted.PrepareTenantOffboard(ctx, command); err != nil {
		t.Fatalf("completed preparation retry: %v", err)
	}
}
