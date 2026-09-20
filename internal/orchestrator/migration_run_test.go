// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

func TestMigrationRunEventProjectsQueuesRecoversAndIsolatesAUD40(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	ctx := context.Background()
	runID := "40400000-0000-4000-8000-000000000040"
	agentID := "40400000-0000-4000-8000-000000000041"
	run, actions, err := migration.StartRun(migration.Run{ID: runID, Waves: []migration.RunWave{{
		ID: "canary", Ordinal: 1, Members: []migration.RunMember{{
			IdentityID: "identity-a",
			Binding: migration.MemberBinding{
				IssuingAuthorityID: "40400000-0000-4000-8000-000000000043",
				TargetID:           "target-a", TargetRevision: "revision-a", Connector: "nginx", Target: "edge-a",
				TargetConfig: json.RawMessage(`{"executor":"agent"}`), RequiredAgentID: agentID,
				TrustAnchorPath: "/etc/trstctl/next-root.pem", TrustAnchorPEM: []byte("public-ca-pem"),
				TrustAnchorFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				VerifyAddress:          "127.0.0.1:443", SubjectCommonName: "edge.example.test",
				SubjectDNSNames:          []string{"edge.example.test"},
				PredecessorCertificateID: "40400000-0000-4000-8000-000000000042",
				PredecessorFingerprint:   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	eventID := orchestrator.MigrationEventID(tenantA, runID, "start")
	got, err := orch.RecordMigrationRun(ctx, tenantA, eventID, run, actions)
	if err != nil {
		t.Fatal(err)
	}
	if got.Run.Status != migration.RunRunning || got.Run.Waves[0].Phase != migration.PhaseVerifyingTrust {
		t.Fatalf("projected run = %+v", got.Run)
	}
	if _, err := st.GetMigrationRun(ctx, tenantB, runID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("tenant B read tenant A migration = %v", err)
	}

	key := "migration:" + runID + ":canary:identity-a:distribute_trust"
	var destination, requiredRole, requiredAgent string
	var payload []byte
	if err := st.SystemPool().QueryRow(ctx,
		`SELECT destination, required_agent_role, required_agent_id::text, payload
		   FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`, tenantA, key).
		Scan(&destination, &requiredRole, &requiredAgent, &payload); err != nil {
		t.Fatal(err)
	}
	if destination != relay.KindTrustDistribute || requiredRole != "host" || requiredAgent != agentID {
		t.Fatalf("trust command route = %s/%s/%s", destination, requiredRole, requiredAgent)
	}
	var intent relay.TrustDistributionIntent
	if err := json.Unmarshal(payload, &intent); err != nil || intent.RunID != runID || intent.AnchorPath == "" {
		t.Fatalf("trust intent = %+v, err=%v", intent, err)
	}

	// Model the append-won/SQL-lost crash by removing only the independent
	// outbox row. Reconciliation must reconstruct the exact-agent command from
	// the retained event snapshot.
	if _, err := st.SystemPool().Exec(ctx,
		`DELETE FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`, tenantA, key); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SystemPool().Exec(ctx,
		`UPDATE outbox_reconciliation_checkpoint SET reconciled_seq = 0 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	healed, err := orch.ReconcileOutbox(ctx, log)
	if err != nil || healed != 1 || countOutbox(t, ctx, st.SystemPool(), tenantA, key) != 1 {
		t.Fatalf("reconcile healed=%d err=%v", healed, err)
	}

	if _, err := st.SystemPool().Exec(ctx, `TRUNCATE migration_runs`); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := st.GetMigrationRun(ctx, tenantA, runID)
	if err != nil || rebuilt.Run.Status != migration.RunRunning {
		t.Fatalf("rebuilt migration = %+v, err=%v", rebuilt, err)
	}
}

func TestMigrationRunDifferentReceiptCatchesUpAppendWonProjectionLostAUD40(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	ctx := context.Background()
	runID := "40400000-0000-4000-8000-000000000050"
	run, startActions, err := migration.StartRun(migration.Run{ID: runID, Waves: []migration.RunWave{{
		ID: "canary", Ordinal: 1, Members: []migration.RunMember{{
			IdentityID: "identity-a",
			Binding: migration.MemberBinding{
				IssuingAuthorityID: "40400000-0000-4000-8000-000000000053",
				TargetID:           "target-a", TargetRevision: "revision-a", Connector: "nginx", Target: "edge-a",
				TargetConfig: json.RawMessage(`{"executor":"agent"}`), RequiredAgentID: "40400000-0000-4000-8000-000000000051",
				TrustAnchorPath: "/etc/trstctl/next-root.pem", TrustAnchorPEM: []byte("public-ca-pem"),
				TrustAnchorFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				VerifyAddress:          "127.0.0.1:443", SubjectCommonName: "edge.example.test",
				SubjectDNSNames:          []string{"edge.example.test"},
				PredecessorCertificateID: "40400000-0000-4000-8000-000000000052",
				PredecessorFingerprint:   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	projected, err := orch.RecordMigrationRun(ctx, tenantA,
		orchestrator.MigrationEventID(tenantA, runID, "start"), run, startActions)
	if err != nil {
		t.Fatal(err)
	}

	// The trust receipt reaches the immutable stream, then its SQL transaction
	// disappears. The next, different receipt must first project that retained
	// transition instead of branching from the older trust gate.
	trustVerified, issueActions, err := migration.Observe(projected.Run, migration.Observation{
		WaveID: "canary", IdentityID: "identity-a", Stage: migration.StageTrust,
		Verdict: migration.VerdictVerified,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(projections.MigrationRunRecorded{Run: trustVerified, Actions: issueActions})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{
		ID:   orchestrator.MigrationEventID(tenantA, runID, "trust-receipt"),
		Type: projections.EventMigrationRunRecorded, TenantID: tenantA, Data: payload,
	}); err != nil {
		t.Fatal(err)
	}

	issuedFingerprint := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	updated, err := orch.UpdateMigrationRun(ctx, tenantA, runID,
		orchestrator.MigrationEventID(tenantA, runID, "successor-issued"),
		func(current migration.Run) (migration.Run, []migration.Action, error) {
			next, err := migration.RecordSuccessorIssued(current, "canary", "identity-a", issuedFingerprint)
			return next, nil, err
		})
	if err != nil {
		t.Fatal(err)
	}
	member, ok := migration.Member(updated.Run, "canary", "identity-a")
	if !ok || updated.Run.Waves[0].Phase != migration.PhaseVerifyingLive ||
		member.Binding.SuccessorFingerprint != issuedFingerprint {
		t.Fatalf("caught-up migration = %+v", updated.Run)
	}
	issueKey := "migration:" + runID + ":canary:identity-a:issue_successor"
	if got := countOutbox(t, ctx, st.SystemPool(), tenantA, issueKey); got != 1 {
		t.Fatalf("recovered issue outbox rows = %d, want 1", got)
	}
}
