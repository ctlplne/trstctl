// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"testing"

	"context"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

func TestColdSnapshotRestoresExactLiveTenantRegistrations(t *testing.T) {
	st, log, projector := recordingSpine(t)
	ctx := t.Context()
	orch := orchestrator.NewOrchestrator(log, st, nil)
	proof, err := orchestrator.ResolveLiveTenantRegistrationAuthority(ctx, log, st, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orch.OffboardTenant(ctx, orchestrator.TenantOffboardCommand{TenantID: tenantA, RegistrationIdentity: proof.EventID}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{tenantA, tenantB} {
		if _, err := orchestrator.ExecuteTenantRegistration(ctx, log, st, projector,
			orchestrator.NewIdempotency(st), registrationCommand(id, "current-"+id, "register-"+id)); err != nil {
			t.Fatal(err)
		}
	}
	certificate, _ := recordingCertificates(t)
	if _, err := orch.RecordCertificate(ctx, tenantA, certificate); err != nil {
		t.Fatal(err)
	}
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	before, err := st.GetTenant(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	// Erase the neighbor before capture; the saved live set must contain only
	// the current lifetime of customer A.
	neighbor, err := orchestrator.ResolveLiveTenantRegistrationAuthority(ctx, log, st, tenantB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orch.OffboardTenant(ctx, orchestrator.TenantOffboardCommand{TenantID: tenantB, RegistrationIdentity: neighbor.EventID}); err != nil {
		t.Fatal(err)
	}
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	if n, err := projector.Snapshot(ctx); err != nil || n != 1 {
		t.Fatalf("capture=%d error=%v", n, err)
	}
	tx, err := st.SystemPool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := st.ResetProjectionCheckpointTx(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	cold := projections.New(st)
	if restored, err := cold.RestoreFromSnapshot(ctx, log); err != nil || !restored {
		t.Fatalf("cold restore=%t error=%v", restored, err)
	}
	after, err := st.GetTenant(ctx, tenantA)
	if err != nil {
		t.Fatalf("cold restore lost current tenant registration: %v", err)
	}
	if before.TenantID != after.TenantID || before.Name != after.Name || before.EventSeq != after.EventSeq || !before.CreatedAt.Equal(after.CreatedAt) {
		t.Fatalf("restored registration differs: before=%+v after=%+v", before, after)
	}
	if _, err := st.GetTenant(ctx, tenantB); err == nil {
		t.Fatal("snapshot resurrected the neighbor erased in its tail")
	}
	if err := st.RequireLiveTenantService(ctx, tenantA); err != nil {
		t.Fatalf("restored customer service unavailable: %v", err)
	}
	if err := st.RequireLiveTenantService(ctx, tenantB); err == nil {
		t.Fatal("erased neighbor regained service")
	}
	current, err := orchestrator.ResolveLiveTenantRegistrationAuthority(ctx, log, st, tenantA)
	if err != nil || current.EventSequence != before.EventSeq {
		t.Fatalf("restored authority=%+v error=%v", current, err)
	}
}
