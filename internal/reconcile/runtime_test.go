// SPDX-License-Identifier: BUSL-1.1

package reconcile_test

import (
	"context"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/reconcile"
	"trstctl.com/trstctl/internal/reconcile/quarantine"
)

// TestRuntime_QuarantineSurvivesRestart is the wiring half of the AH-59cce24d
// fail-open tripwire. NewRuntime is exactly what a process restart runs
// (cmd/trstctl/ee_attach.go calls it on every boot): before this fix it
// allocated an empty quarantine MemoryState, registered no fold for it, and
// loaded nothing -- so a tenant quarantined before the bounce was admitted again
// on the served mint path.
//
// Three things must hold and each is asserted separately:
//  1. the runtime EXPOSES the containment fold, so the core projector can reset
//     it and replay the log from sequence 0 on boot;
//  2. the fold and the admission hook share ONE substrate -- this is the
//     invariant that actually makes the restart work, and an arity check on
//     ProjectionOptions cannot see it;
//  3. the hook handed to served issuance refuses the rebuilt-quarantined tenant.
func TestRuntime_QuarantineSurvivesRestart(t *testing.T) {
	ctx := context.Background()

	// The durable substrate: the tenant's own quarantine-entered event, exactly as
	// Manager.ObserveWitness appended it before the restart.
	data, err := json.Marshal(quarantine.Entered{
		TenantID:     "tenant-a",
		AuthorityID:  "vault",
		WitnessID:    "witness-1",
		Reason:       "policy_violation",
		FromState:    quarantine.StateConsistent,
		ThroughState: quarantine.StateDiverged,
		ToState:      quarantine.StateQuarantined,
		EnteredAt:    1800000000,
	})
	if err != nil {
		t.Fatalf("marshal entered payload: %v", err)
	}
	entered := eventspec.Event{
		ID:            "event-1",
		Type:          quarantine.EventTypeEntered,
		TenantID:      "tenant-a",
		SchemaVersion: eventspec.DefaultSchemaVersion,
		Sequence:      1,
		Data:          data,
	}

	// ---- the restart: a FRESH runtime object graph ----
	rt, err := reconcile.NewRuntime(reconcile.RuntimeConfig{})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	if rt.QuarantineProjection == nil {
		t.Fatal("runtime exposes no quarantine containment projection: a restart cannot rebuild containment")
	}
	if got := rt.QuarantineProjection.Name(); got != "xrec.quarantine.state" {
		t.Fatalf("projection name = %q, want xrec.quarantine.state", got)
	}
	if len(rt.ProjectionOptions) < 2 {
		t.Fatalf("ProjectionOptions = %d, want the quarantine fold registered alongside drift", len(rt.ProjectionOptions))
	}
	if rt.QuarantineState == nil {
		t.Fatal("runtime exposes no containment read seam")
	}

	// What projections.Projector.ProjectCatchUp does on boot: reset the registered
	// event projections, then replay the log from sequence 0 through them.
	if err := rt.QuarantineProjection.Reset(ctx); err != nil {
		t.Fatalf("projection reset: %v", err)
	}
	if err := rt.QuarantineProjection.Apply(ctx, entered); err != nil {
		t.Fatalf("projection apply entered: %v", err)
	}

	// The load-bearing invariant: the fold the projector drives and the state the
	// admission hook reads are ONE substrate. Registering some other projection,
	// or a second MemoryState, keeps the arity check above green while containment
	// silently reverts to fail-open.
	open, err := rt.QuarantineState.HasOpenTenantQuarantine(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("HasOpenTenantQuarantine after replay: %v", err)
	}
	if !open {
		t.Fatal("the registered fold and the admission read seam are not the same containment state")
	}

	// This runtime has no event log, so the refusal surfaces as an error rather
	// than a recorded refusal event -- which is itself fail closed
	// (internal/server/issuance.go turns the error into a refused issuance). What
	// must never happen is Allowed=true, which is exactly what the unpatched tree
	// returned here.
	decision, err := rt.IssuanceAdmission.Admit(ctx, editionseam.AdmissionRequest{
		TenantID:       "tenant-a",
		Operation:      "issue",
		IdentityID:     "identity-1",
		IdempotencyKey: "idem-after-restart",
		ObservedInputs: []editionseam.ObservedStateInput{{
			AuthorityID: "vault",
			RecordKey:   "tenant-a/x509_certificate/cert-a",
			Source:      "policy",
		}},
	})
	if decision.Allowed {
		t.Fatalf("restart un-quarantined tenant-a: decision = %+v (err = %v)", decision, err)
	}

	// AN-1: the rebuilt containment state is tenant-scoped.
	other, err := rt.IssuanceAdmission.Admit(ctx, editionseam.AdmissionRequest{
		TenantID:       "tenant-b",
		Operation:      "issue",
		IdentityID:     "identity-2",
		IdempotencyKey: "idem-other-tenant",
		ObservedInputs: []editionseam.ObservedStateInput{{
			AuthorityID: "vault",
			RecordKey:   "tenant-b/x509_certificate/cert-b",
			Source:      "policy",
		}},
	})
	if err != nil {
		t.Fatalf("Admit unrelated tenant: %v", err)
	}
	if !other.Allowed {
		t.Fatalf("quarantine leaked across tenants: %+v", other)
	}
}
