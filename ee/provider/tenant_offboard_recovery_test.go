// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

// Recovery rebuilds Provider views from the complete history, including core
// deletion. A Provider-only fold must not restore rows erased by that history.
func TestProviderRecoveryPreservesCoreTenantOffboard(t *testing.T) {
	st, log, sink := authorityReplayFixture(t)
	ctx := events.ContextWithActor(t.Context(), events.Actor{Subject: "customer-admin", Roles: []string{"admin"}})
	now := time.Now().UTC()
	deletedID := CustomerID("core-offboard-recovery")
	otherID := CustomerID("core-offboard-other-customer")
	var oldProvision events.Event
	for _, id := range []string{deletedID, otherID} {
		tenant := Tenant{ID: id, Slug: "customer-" + id, Name: "Recovery customer", Status: TenantActive, CreatedAt: now, UpdatedAt: now}
		event, err := sink.Append(ctx, "provision-"+id, AuditTenantProvisioned, id, AuthorityEvent{Tenant: &tenant, EffectiveAt: now})
		if err != nil {
			t.Fatal(err)
		}
		if id == deletedID {
			oldProvision = event
		}
		if _, err := sink.Append(ctx, "grant-"+id, EventDelegationGranted, id, AuthorityEvent{
			Delegation:  &DelegationMutation{OperatorID: "operator-1", CustomerID: id, Operation: OpRead, GrantedBy: "admin"},
			EffectiveAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	payload, err := json.Marshal(map[string]string{"name": "Recovery customer"})
	if err != nil {
		t.Fatal(err)
	}
	runtime := NewAuthorityRuntime(st, log)
	projector := projections.New(st, runtime.ProjectionOptions...)
	registration, err := orchestrator.ExecuteTenantRegistration(ctx, log, st, projector, orchestrator.NewIdempotency(st),
		orchestrator.TenantRegistrationCommand{TenantID: deletedID, Name: "Recovery customer", IdempotencyKey: "register-customer",
			RequestMaterial: payload, PayloadAt: func(time.Time) ([]byte, error) { return payload, nil }})
	if err != nil {
		t.Fatal(err)
	}
	orch := orchestrator.NewOrchestrator(log, st, nil, orchestrator.WithProjector(projector))
	deleted, err := orch.OffboardTenant(ctx, orchestrator.TenantOffboardCommand{TenantID: deletedID, RegistrationIdentity: registration.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewPGStore(st).Tenant(ctx, deletedID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("core erasure left customer registry: %v", err)
	}
	assertReplayAuthority(t, st, "operator-1", deletedID, false)
	assertReplayAuthority(t, st, "operator-1", otherID, true)
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	restarted := NewAuthorityRuntime(st, log)
	if err := restarted.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPGStore(st).Tenant(ctx, deletedID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Provider restart resurrected core-erased customer: %v", err)
	}
	assertReplayAuthority(t, st, "operator-1", deletedID, false)
	assertReplayAuthority(t, st, "operator-1", otherID, true)
	if _, err := NewPGStore(st).Tenant(ctx, otherID); err != nil {
		t.Fatalf("recovery removed other customer: %v", err)
	}
	if after, err := log.LastSequence(ctx); err != nil || after != head {
		t.Fatalf("recovery appended source history: head=%d after=%d error=%v", head, after, err)
	}
	// An old inline provision retry must remain a no-op after the deletion fold.
	if err := restarted.Projection.Apply(ctx, oldProvision); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPGStore(st).Tenant(ctx, deletedID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old provision resurrected erased customer: %v", err)
	}
	// Core's extension catch-up resets Provider views, independently of the
	// earlier bootstrap fold. It must receive the deletion too.
	if err := projections.New(st, restarted.ProjectionOptions...).Project(ctx, log); err != nil {
		t.Fatalf("core extension catch-up: %v", err)
	}
	if _, err := NewPGStore(st).Tenant(ctx, deletedID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("core catch-up restored erased customer: %v", err)
	}
	assertReplayAuthority(t, st, "operator-1", deletedID, false)
	assertReplayAuthority(t, st, "operator-1", otherID, true)
	if err := projections.New(st, restarted.ProjectionOptions...).Rebuild(ctx, log); err != nil {
		t.Fatalf("full transactional rebuild: %v", err)
	}
	if _, err := NewPGStore(st).Tenant(ctx, deletedID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("full rebuild restored erased customer: %v", err)
	}
	assertReplayAuthority(t, st, "operator-1", deletedID, false)
	assertReplayAuthority(t, st, "operator-1", otherID, true)
	// Later explicit provisioning is allowed; a stale offboard projection must
	// not erase that new customer generation or revoke its new delegation.
	later := Tenant{ID: deletedID, Slug: "new-customer", Name: "New customer", Status: TenantActive, CreatedAt: now.Add(time.Minute), UpdatedAt: now.Add(time.Minute)}
	if _, err := restarted.Mutations.Append(ctx, "new-provision", AuditTenantProvisioned, deletedID, AuthorityEvent{Tenant: &later, EffectiveAt: later.CreatedAt}); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Mutations.Append(ctx, "new-grant", EventDelegationGranted, deletedID, AuthorityEvent{
		Delegation:  &DelegationMutation{OperatorID: "operator-1", CustomerID: deletedID, Operation: OpRead, GrantedBy: "admin"},
		EffectiveAt: later.CreatedAt,
	}); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Projection.Apply(ctx, deleted); err != nil {
		t.Fatal(err)
	}
	if got, err := NewPGStore(st).Tenant(ctx, deletedID); err != nil || got.Name != later.Name {
		t.Fatalf("old deletion changed new customer: %+v error=%v", got, err)
	}
	assertReplayAuthority(t, st, "operator-1", deletedID, true)
}

func TestProviderOffboardRollsBackWithCoreAndRestoresRLSScope(t *testing.T) {
	st, log, sink := authorityReplayFixture(t)
	ctx := events.ContextWithActor(t.Context(), events.Actor{Subject: "customer-admin", Roles: []string{"admin"}})
	id := CustomerID("offboard-rollback-and-scope")
	now := time.Now().UTC()
	tenant := Tenant{ID: id, Slug: "offboard-rollback-and-scope", Name: "Rollback customer", Status: TenantActive, CreatedAt: now, UpdatedAt: now}
	if _, err := sink.Append(ctx, "provision", AuditTenantProvisioned, id, AuthorityEvent{Tenant: &tenant, EffectiveAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := sink.Append(ctx, "grant", EventDelegationGranted, id, AuthorityEvent{
		Delegation: &DelegationMutation{OperatorID: "operator-1", CustomerID: id, Operation: OpRead, GrantedBy: "admin"}, EffectiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	interrupted := errors.New("test: later lifecycle extension interrupted")
	check := &providerLifecycleScopeCheck{tenantID: id, failure: interrupted}
	if err := st.WithTenant(ctx, id, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT current_user, current_setting('search_path')`).Scan(&check.role, &check.searchPath)
	}); err != nil {
		t.Fatal(err)
	}
	runtime := NewAuthorityRuntime(st, log)
	options := append(runtime.ProjectionOptions, projections.WithEventProjection(check))
	projector := projections.New(st, options...)
	payload := []byte(`{"name":"Rollback customer"}`)
	registration, err := orchestrator.ExecuteTenantRegistration(ctx, log, st, projector, orchestrator.NewIdempotency(st),
		orchestrator.TenantRegistrationCommand{TenantID: id, Name: tenant.Name, IdempotencyKey: "registration", RequestMaterial: payload,
			PayloadAt: func(time.Time) ([]byte, error) { return payload, nil }})
	if err != nil {
		t.Fatal(err)
	}
	orch := orchestrator.NewOrchestrator(log, st, nil, orchestrator.WithProjector(projector))
	command := orchestrator.TenantOffboardCommand{TenantID: id, RegistrationIdentity: registration.ID}
	if _, err := orch.OffboardTenant(ctx, command); !errors.Is(err, interrupted) {
		t.Fatalf("offboard=%v, want later extension failure", err)
	}
	if _, err := st.GetTenant(ctx, id); err != nil {
		t.Fatalf("rollback lost core tenant: %v", err)
	}
	if _, err := NewPGStore(st).Tenant(ctx, id); err != nil {
		t.Fatalf("rollback lost Provider tenant: %v", err)
	}
	assertReplayAuthority(t, st, "operator-1", id, true)
	var receipts int
	if err := st.SystemPool().QueryRow(ctx, `SELECT count(*) FROM provider_authority_projection_receipts
		WHERE tenant_id=$1 AND event_id=$2`, providerAuthorityTenant, projections.TenantOffboardEventID(id, registration.ID)).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if receipts != 0 {
		t.Fatalf("rolled-back deletion retained %d completion receipts", receipts)
	}
	check.failure = nil
	if _, err := orch.OffboardTenant(ctx, command); err != nil {
		t.Fatalf("retry interrupted deletion: %v", err)
	}
	assertReplayAuthority(t, st, "operator-1", id, false)
	if _, err := NewPGStore(st).Tenant(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("successful retry left Provider customer: %v", err)
	}
	if check.calls != 2 {
		t.Fatalf("scope checked %d times, want failed attempt and successful retry", check.calls)
	}
}

type providerLifecycleScopeCheck struct {
	tenantID, role, searchPath string
	failure                    error
	calls                      int
}

func (*providerLifecycleScopeCheck) Name() string                              { return "test.provider_lifecycle_scope" }
func (*providerLifecycleScopeCheck) ProjectsTenantLifecycle()                  {}
func (*providerLifecycleScopeCheck) Reset(context.Context) error               { return nil }
func (*providerLifecycleScopeCheck) ResetTx(context.Context, pgx.Tx) error     { return nil }
func (*providerLifecycleScopeCheck) Apply(context.Context, events.Event) error { return nil }
func (p *providerLifecycleScopeCheck) ReplayTenantLifecycleTx(ctx context.Context, tx pgx.Tx, event events.Event) error {
	return p.ApplyTx(ctx, tx, event)
}
func (p *providerLifecycleScopeCheck) ApplyTx(ctx context.Context, tx pgx.Tx, event events.Event) error {
	if event.Type != projections.EventTenantOffboarded {
		return nil
	}
	p.calls++
	var tenant, role, path string
	if err := tx.QueryRow(ctx, `SELECT current_setting('trstctl.tenant_id'), current_user, current_setting('search_path')`).Scan(&tenant, &role, &path); err != nil {
		return err
	}
	if tenant != p.tenantID || role != p.role || path != p.searchPath {
		return fmt.Errorf("test: Provider changed caller scope: tenant=%s role=%s path=%s", tenant, role, path)
	}
	var visible int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM provider_operator_delegations WHERE tenant_id=$1`, providerAuthorityTenant).Scan(&visible); err != nil {
		return err
	}
	if visible != 0 {
		return errors.New("test: customer RLS context can see Provider authority rows")
	}
	return p.failure
}
