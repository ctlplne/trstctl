// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestN0008RollbackRestoreFailureNeverAppendsAndOldEventIsIsolated(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	runID := "40400000-0000-4000-8000-000000000081"
	start, startActions, err := migration.StartRun(migration.Run{ID: runID,
		Waves: []migration.RunWave{{ID: "canary", Ordinal: 1, Members: []migration.RunMember{{
			IdentityID: "identity-a", Binding: migration.MemberBinding{
				IssuingAuthorityID: "40400000-0000-4000-8000-000000000043",
				TargetID:           "target-a", TargetRevision: "revision-a", Connector: "nginx", Target: "edge-a",
				TargetConfig:    json.RawMessage(`{"executor":"agent","required_agent_id":"40400000-0000-4000-8000-000000000041"}`),
				RequiredAgentID: "40400000-0000-4000-8000-000000000041",
				TrustAnchorPath: "/etc/trstctl/next-root.pem", TrustAnchorPEM: []byte("public-ca-pem"),
				TrustAnchorFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				VerifyAddress:          "127.0.0.1:443", SubjectCommonName: "edge.example.test",
				SubjectDNSNames:          []string{"edge.example.test"},
				PredecessorCertificateID: "40400000-0000-4000-8000-000000000042",
				PredecessorFingerprint:   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orch.RecordMigrationRun(ctx, tenantA,
		orchestrator.MigrationEventID(tenantA, runID, "start"), start, startActions); err != nil {
		t.Fatalf("start migration: %v", err)
	}
	failed := start
	failed, _, err = migration.Observe(failed, migration.Observation{
		WaveID: "canary", IdentityID: "identity-a", Stage: migration.StageTrust,
		Verdict: migration.VerdictVerified,
	})
	if err != nil {
		t.Fatal(err)
	}
	failed, _, err = migration.Observe(failed, migration.Observation{
		WaveID: "canary", IdentityID: "identity-a", Stage: migration.StageSuccessor,
		Verdict: migration.VerdictFailed,
	})
	if err != nil {
		t.Fatal(err)
	}
	failed.Waves[0].Members[0].Binding.SuccessorFingerprint = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	failed, actions, err := migration.Observe(failed, migration.Observation{
		WaveID: "canary", IdentityID: "identity-a", Stage: migration.StageRollbackSuccessor,
		Verdict: migration.VerdictVerified,
	})
	if err != nil {
		t.Fatal(err)
	}
	eventID := orchestrator.MigrationEventID(tenantA, runID, "invalid-restore")
	if _, err := orch.UpdateMigrationRun(ctx, tenantA, runID, eventID,
		func(migration.Run) (migration.Run, []migration.Action, error) {
			return failed, actions, nil
		}); !errors.Is(err, store.ErrMigrationRestoreInconsistent) {
		t.Fatalf("preappend restore check = %v, want inconsistent inventory", err)
	}
	if _, found, err := log.EventByID(ctx, eventID); err != nil || found {
		t.Fatalf("invalid restore reached JetStream: found=%v err=%v", found, err)
	}
	data, err := json.Marshal(projections.MigrationRunRecorded{Run: failed, Actions: actions})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{ID: eventID, Type: projections.EventMigrationRunRecorded,
		TenantID: tenantA, Data: data}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered,
		TenantID: tenantB, Data: []byte(`{"name":"healthy"}`)}); err != nil {
		t.Fatal(err)
	}
	p := projections.New(st)
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("old restore event blocked global catch-up: %v", err)
	}
	if quarantined, err := st.ProjectionTenantQuarantined(ctx, tenantA); err != nil || !quarantined {
		t.Fatalf("old restore tenant quarantine=%v err=%v", quarantined, err)
	}
	if _, err := st.GetTenant(ctx, tenantB); err != nil {
		t.Fatalf("later healthy tenant was blocked: %v", err)
	}
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("old restore event blocked rebuild: %v", err)
	}
}
