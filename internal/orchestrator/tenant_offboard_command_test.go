// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

func TestTenantOffboardCommandBindsRegistrationAndPreservesOtherTenant(t *testing.T) {
	ctx := events.ContextWithActor(t.Context(), events.Actor{Subject: "authorized-customer-admin", Roles: []string{"admin"}})
	st := newStore(t)
	log := openLog(t)
	extension := &tenantLifecycleRegressionProjection{store: st}
	projector := projections.New(st, projections.WithEventProjection(extension))
	idem := orchestrator.NewIdempotency(st)
	register := func(id, name, key string) events.Event {
		t.Helper()
		event, err := orchestrator.ExecuteTenantRegistration(ctx, log, st, projector, idem, registrationCommand(id, name, key))
		if err != nil {
			t.Fatal(err)
		}
		return event
	}
	firstRegistration := register(tenantA, "first-customer", "first-registration")
	register(tenantB, "other-customer", "other-registration")
	orch := orchestrator.NewOrchestrator(log, st, nil, orchestrator.WithProjector(projector))
	for _, id := range []string{tenantA, tenantB} {
		if _, err := orch.CreateOwner(ctx, id, "team", "retained only for live tenant", "qa@example.test"); err != nil {
			t.Fatal(err)
		}
	}
	proof, err := orchestrator.ResolveLiveTenantRegistrationAuthority(ctx, log, st, tenantA)
	if err != nil || proof.EventID != firstRegistration.ID {
		t.Fatalf("registration authority=%+v error=%v", proof, err)
	}
	command := orchestrator.TenantOffboardCommand{TenantID: tenantA, RegistrationIdentity: proof.EventID}
	if _, err := orch.OffboardTenant(ctx, orchestrator.TenantOffboardCommand{
		TenantID: tenantA, RegistrationIdentity: "another-registration",
	}); !errors.Is(err, orchestrator.ErrIdempotencyConflict) {
		t.Fatalf("wrong registration accepted: %v", err)
	}
	if got := countTenantEvents(t, log, tenantA, projections.EventTenantOffboarded); got != 0 {
		t.Fatalf("rejected registration appended %d offboard events", got)
	}
	deleted, err := orch.OffboardTenant(ctx, command)
	if err != nil {
		t.Fatalf("offboard: %v", err)
	}
	if deleted.ID != projections.TenantOffboardEventID(tenantA, firstRegistration.ID) || deleted.Actor == nil || deleted.Actor.Subject != "authorized-customer-admin" {
		t.Fatalf("offboard lost authorized identity: %+v", deleted)
	}
	assertRows := func(tenant string, want int) {
		t.Helper()
		if err := st.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			for _, table := range []string{"tenants", "owners"} {
				var n int
				if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE tenant_id=$1", tenant).Scan(&n); err != nil {
					return err
				}
				if n != want {
					t.Errorf("%s %s rows=%d want %d", tenant, table, n, want)
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	assertRows(tenantA, 0)
	assertRows(tenantB, 1)
	replayed, err := orch.OffboardTenant(ctx, command)
	if err != nil || replayed.ID != deleted.ID || replayed.Sequence != deleted.Sequence || !replayed.Time.Equal(deleted.Time) {
		t.Fatalf("completed retry=%+v error=%v want retained %+v", replayed, err, deleted)
	}
	if extension.offboardedTx != 2 || extension.postCommitCalls != 0 {
		t.Fatalf("lifecycle extension escaped transaction: %+v", extension)
	}
	secondRegistration := register(tenantA, "new-customer", "new-registration")
	if _, err := orch.CreateOwner(ctx, tenantA, "team", "new-customer-owner", "new@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := orch.OffboardTenant(ctx, command); !errors.Is(err, orchestrator.ErrIdempotencyConflict) {
		t.Fatalf("old offboard against re-registration=%v, want conflict", err)
	}
	current, err := st.GetTenant(ctx, tenantA)
	if err != nil || current.EventSeq != secondRegistration.Sequence {
		t.Fatalf("old command changed new customer: %+v error=%v", current, err)
	}
	assertRows(tenantA, 1)
	assertRows(tenantB, 1)
	if got := countTenantEvents(t, log, tenantA, projections.EventTenantOffboarded); got != 1 {
		t.Fatalf("offboard event count=%d want 1", got)
	}
}

// Model a crash after the immutable event append but before the SQL transaction
// commits. The retry must finish that event, including every lifecycle extension,
// rather than minting another deletion or accepting a different actor's command.
func TestTenantOffboardCommandRecoversAfterProjectionFailure(t *testing.T) {
	ctx := events.ContextWithActor(t.Context(), events.Actor{Subject: "authorized-customer-admin", Roles: []string{"admin"}})
	st := newStore(t)
	log := openLog(t)
	interrupted := errors.New("test: offboard projection interrupted")
	extension := &offboardInterruptionProjection{
		tenantLifecycleRegressionProjection: tenantLifecycleRegressionProjection{store: st},
		failure:                             interrupted,
	}
	projector := projections.New(st, projections.WithEventProjection(extension))
	registration, err := orchestrator.ExecuteTenantRegistration(ctx, log, st, projector,
		orchestrator.NewIdempotency(st), registrationCommand(tenantA, "recover-customer", "recover-registration"))
	if err != nil {
		t.Fatal(err)
	}
	orch := orchestrator.NewOrchestrator(log, st, nil, orchestrator.WithProjector(projector))
	owner, err := orch.CreateOwner(ctx, tenantA, "team", "recover-owner", "qa@example.test")
	if err != nil {
		t.Fatal(err)
	}
	command := orchestrator.TenantOffboardCommand{TenantID: tenantA, RegistrationIdentity: registration.ID}
	if _, err := orch.OffboardTenant(ctx, command); !errors.Is(err, interrupted) {
		t.Fatalf("interrupted erase=%v, want injected projection failure", err)
	}
	if _, err := st.GetTenant(ctx, tenantA); err != nil {
		t.Fatalf("failed transaction deleted the tenant: %v", err)
	}
	if _, err := st.GetOwner(ctx, tenantA, owner.ID); err != nil {
		t.Fatalf("failed transaction deleted the owner: %v", err)
	}
	if got := countTenantEvents(t, log, tenantA, projections.EventTenantOffboarded); got != 1 {
		t.Fatalf("interrupted command retained %d events, want 1", got)
	}
	otherActor := events.ContextWithActor(t.Context(), events.Actor{Subject: "different-admin", Roles: []string{"admin"}})
	if _, err := orch.OffboardTenant(otherActor, command); !errors.Is(err, orchestrator.ErrIdempotencyConflict) {
		t.Fatalf("different actor borrowed pending command: %v", err)
	}
	extension.failure = nil
	completed, err := orch.OffboardTenant(ctx, command)
	if err != nil {
		t.Fatalf("recover original command: %v", err)
	}
	if completed.ID != projections.TenantOffboardEventID(tenantA, registration.ID) {
		t.Fatalf("recovery changed event identity: %+v", completed)
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		for _, table := range []string{"tenants", "owners", "idempotency_keys"} {
			var n int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE tenant_id=$1", tenantA).Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				t.Errorf("recovery left %d rows in %s", n, table)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := orch.OffboardTenant(otherActor, command); !errors.Is(err, orchestrator.ErrIdempotencyConflict) {
		t.Fatalf("different actor borrowed completed command: %v", err)
	}
	replayed, err := orch.OffboardTenant(ctx, command)
	if err != nil || replayed.ID != completed.ID || replayed.Sequence != completed.Sequence || !replayed.Time.Equal(completed.Time) {
		t.Fatalf("completed retry=%+v error=%v, want %+v", replayed, err, completed)
	}
	if got := countTenantEvents(t, log, tenantA, projections.EventTenantOffboarded); got != 1 {
		t.Fatalf("recovery appended another deletion: %d events", got)
	}
	if extension.postCommitCalls != 0 {
		t.Fatalf("recovery ran %d lifecycle projections outside the transaction", extension.postCommitCalls)
	}
}

type offboardInterruptionProjection struct {
	tenantLifecycleRegressionProjection
	failure error
}

func (p *offboardInterruptionProjection) ApplyTx(ctx context.Context, tx pgx.Tx, event events.Event) error {
	if err := p.tenantLifecycleRegressionProjection.ApplyTx(ctx, tx, event); err != nil {
		return err
	}
	if event.Type == projections.EventTenantOffboarded {
		return p.failure
	}
	return nil
}

func TestTenantOffboardCommandRequiresRegistrationIdentity(t *testing.T) {
	for _, command := range []orchestrator.TenantOffboardCommand{
		{}, {TenantID: tenantA}, {RegistrationIdentity: "registration-without-customer"},
	} {
		if _, err := (*orchestrator.Orchestrator)(nil).OffboardTenant(context.Background(), command); err == nil {
			t.Fatalf("incomplete command %+v accepted", command)
		}
	}
}
