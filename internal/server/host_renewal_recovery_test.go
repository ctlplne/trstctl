// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestPQCHostCSRVerifiedResultClosesBothLifecycleEdges(t *testing.T) {
	ctx := context.Background()
	h := newIssuanceDispatcherHarness(t)
	projector := projections.New(h.store, projections.WithOwnershipAttestationCadence(time.Hour))
	orch := orchestrator.NewOrchestrator(h.log, h.store, h.outbox,
		orchestrator.WithProjector(projector), orchestrator.WithOwnershipAttestationCadence(time.Hour))
	srv := &Server{orch: orch}
	owner, err := orch.CreateOwnerRecord(ctx, store.Owner{TenantID: h.tenant, Kind: store.OwnerService,
		Name: "PQC host CSR owner", ApplicationID: "pqc-host", Environment: "test"})
	if err != nil {
		t.Fatal(err)
	}
	owner, err = orch.AttestOwnership(ctx, h.tenant, owner.ID, "qa-operator")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := orch.CreateIdentity(ctx, h.tenant, store.Identity{Kind: store.KindX509Certificate,
		Name: "pqc-host.example.test", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(RelayDeployIntent{IdentityID: identity.ID, PQCRunID: "pqc-verified-run"})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.completeHostRenewal(ctx, h.tenant, payload, transport.JobOutcomeVerified, nil); err != nil {
		t.Fatalf("verified host CSR lifecycle: %v", err)
	}
	if state, err := orch.State(ctx, h.tenant, identity.ID); err != nil || state != orchestrator.StateDeployed {
		t.Fatalf("verified host CSR state=%s, err=%v", state, err)
	}
	if err := srv.completeHostRenewal(ctx, h.tenant, payload, transport.JobOutcomeVerified, nil); err != nil {
		t.Fatalf("duplicate signed result retransitioned: %v", err)
	}
	for _, destination := range []string{"ca.issue", "connector.deploy"} {
		var queued int
		if err := h.store.SystemPool().QueryRow(ctx,
			`SELECT count(*) FROM outbox WHERE tenant_id=$1 AND destination=$2`, h.tenant, destination).Scan(&queued); err != nil {
			t.Fatal(err)
		}
		if queued != 0 {
			t.Fatalf("completed %s queued %d duplicate effects", destination, queued)
		}
	}
	if err := projector.Rebuild(ctx, h.log); err != nil {
		t.Fatalf("cold replay of completed host CSR: %v", err)
	}
	if state, err := orch.State(ctx, h.tenant, identity.ID); err != nil || state != orchestrator.StateDeployed {
		t.Fatalf("cold replay host CSR state=%s, err=%v", state, err)
	}
}

// The real NGINX outage recovered on the host but its lifecycle report was
// refused only when the production ownership-attestation gate was enabled.
func TestHostRenewalRecoveryPreservesOwnershipAuthority(t *testing.T) {
	for _, current := range []bool{true, false} {
		name := "current owner"
		if !current {
			name = "changed owner requires reattestation"
		}
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			h := newIssuanceDispatcherHarness(t)
			projector := projections.New(h.store, projections.WithOwnershipAttestationCadence(time.Hour))
			orch := orchestrator.NewOrchestrator(h.log, h.store, h.outbox,
				orchestrator.WithProjector(projector), orchestrator.WithOwnershipAttestationCadence(time.Hour))
			srv := &Server{orch: orch}
			owner, err := orch.CreateOwnerRecord(ctx, store.Owner{
				TenantID: h.tenant, Kind: store.OwnerService, Name: "recovery owner", ApplicationID: "recovery", Environment: "test",
			})
			if err != nil {
				t.Fatal(err)
			}
			owner, err = orch.AttestOwnership(ctx, h.tenant, owner.ID, "qa-operator")
			if err != nil {
				t.Fatal(err)
			}
			identity, err := orch.CreateIdentity(ctx, h.tenant, store.Identity{
				Kind: store.KindX509Certificate, Name: "recovery.example.test", OwnerID: owner.ID,
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, to := range []orchestrator.State{orchestrator.StateIssued, orchestrator.StateDeployed, orchestrator.StateRenewing} {
				if err := orch.Transition(ctx, h.tenant, identity.ID, to, "fixture setup"); err != nil {
					t.Fatal(err)
				}
			}
			payload, err := json.Marshal(RelayDeployIntent{IdentityID: identity.ID, Target: "owned-nginx"})
			if err != nil {
				t.Fatal(err)
			}
			if err := srv.completeHostRenewal(ctx, h.tenant, payload, transport.JobOutcomeFailed, nil); err != nil {
				t.Fatal(err)
			}
			if !current {
				owner.Environment = "changed-after-failure"
				if _, err := orch.UpdateOwnerRecord(ctx, owner); err != nil {
					t.Fatal(err)
				}
			}
			before, err := h.outbox.Pending(ctx, h.tenant)
			if err != nil {
				t.Fatal(err)
			}
			err = srv.completeHostRenewal(ctx, h.tenant, payload, transport.JobOutcomeVerified, nil)
			if !current {
				if err == nil {
					t.Fatal("retry bypassed changed ownership authority")
				}
				if state, err := orch.State(ctx, h.tenant, identity.ID); err != nil || state != orchestrator.StateRenewalFailed {
					t.Fatalf("refused recovery state=%s, error=%v", state, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("verified retry with current ownership was refused: %v", err)
			}
			if state, err := orch.State(ctx, h.tenant, identity.ID); err != nil || state != orchestrator.StateDeployed {
				t.Fatalf("verified retry state=%s, error=%v", state, err)
			}
			if err := srv.completeHostRenewal(ctx, h.tenant, payload, transport.JobOutcomeVerified, nil); err != nil {
				t.Fatal(err)
			}
			after, err := h.outbox.Pending(ctx, h.tenant)
			if err != nil || len(after) != len(before) {
				t.Fatalf("recovery queued another external effect: before=%d after=%d error=%v", len(before), len(after), err)
			}
			recovered := 0
			if err := h.log.Replay(ctx, 1, func(event events.Event) error {
				if event.Type != projections.EventIdentityRenewalRecovered {
					return nil
				}
				recovered++
				var body struct {
					Ownership *store.OwnershipReadinessEvidence `json:"ownership_readiness"`
					Effect    json.RawMessage                   `json:"side_effect"`
				}
				if err := json.Unmarshal(event.Data, &body); err != nil {
					return err
				}
				if event.SchemaVersion != projections.LifecycleOwnershipReadinessEventSchemaVersion || body.Ownership == nil || body.Ownership.IdentityID != identity.ID || len(body.Effect) != 0 {
					t.Fatalf("recovery event lost exact authority or invented an effect: %+v", body)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if recovered != 1 {
				t.Fatalf("recovered event count=%d, want one", recovered)
			}
			// Event history must reconstruct the same recovered state after a
			// restart/rebuild, without inventing another deployment intent.
			if err := projector.Rebuild(ctx, h.log); err != nil {
				t.Fatalf("rebuild recovered lifecycle: %v", err)
			}
			if state, err := orch.State(ctx, h.tenant, identity.ID); err != nil || state != orchestrator.StateDeployed {
				t.Fatalf("rebuilt recovery state=%s, error=%v", state, err)
			}
			if _, err := orch.ReconcileOutbox(ctx, h.log); err != nil {
				t.Fatalf("reconcile recovered lifecycle: %v", err)
			}
			after, err = h.outbox.Pending(ctx, h.tenant)
			if err != nil || len(after) != len(before) {
				t.Fatalf("replay recreated an external effect: before=%d after=%d error=%v", len(before), len(after), err)
			}
		})
	}
}
