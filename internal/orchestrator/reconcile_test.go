// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type replayableTransitionSideEffect struct {
	Destination       string `json:"destination"`
	IdempotencyKey    string `json:"idempotency_key"`
	Payload           []byte `json:"payload"`
	RequiredAgentRole string `json:"required_agent_role,omitempty"`
}

func replayableTransitionEvent(t *testing.T, identityID string, from, to orchestrator.State, requestKey string, sideEffect replayableTransitionSideEffect) []byte {
	t.Helper()
	payload, err := json.Marshal(struct {
		IdentityID     string                         `json:"identity_id"`
		From           string                         `json:"from"`
		To             string                         `json:"to"`
		Reason         string                         `json:"reason,omitempty"`
		IdempotencyKey string                         `json:"idempotency_key"`
		SideEffect     replayableTransitionSideEffect `json:"side_effect"`
	}{
		IdentityID: identityID, From: string(from), To: string(to),
		Reason: "pre-upgrade fixture", IdempotencyKey: requestKey, SideEffect: sideEffect,
	})
	if err != nil {
		t.Fatalf("encode replayable transition: %v", err)
	}
	return payload
}

// transitionEvent builds the JSON body of a lifecycle transition event the way
// Orchestrator.Transition does, so the reconciler decodes it identically.
func transitionEvent(t *testing.T, identityID string, from, to orchestrator.State) []byte {
	t.Helper()
	b, err := json.Marshal(struct {
		IdentityID string `json:"identity_id"`
		From       string `json:"from"`
		To         string `json:"to"`
	}{identityID, string(from), string(to)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func transitionEventWithIdempotency(t *testing.T, identityID string, from, to orchestrator.State, idemKey string) []byte {
	t.Helper()
	b, err := json.Marshal(struct {
		IdentityID     string `json:"identity_id"`
		From           string `json:"from"`
		To             string `json:"to"`
		IdempotencyKey string `json:"idempotency_key"`
	}{identityID, string(from), string(to), idemKey})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// countOutbox returns how many outbox rows exist for (tenant, idempotency_key),
// read on the pool (system role) for cross-tenant inspection in a test.
func countOutbox(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, idemKey string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantID, idemKey).Scan(&n); err != nil {
		t.Fatalf("count outbox: %v", err)
	}
	return n
}

// enqueueIfAbsent runs Outbox.EnqueueIfAbsent under the entry's tenant context,
// modelling the inline Transition enqueue.
func enqueueIfAbsent(t *testing.T, s *store.Store, ob *orchestrator.Outbox, e orchestrator.Entry) error {
	t.Helper()
	return s.WithTenant(context.Background(), e.TenantID, func(tx pgx.Tx) error {
		_, err := ob.EnqueueIfAbsent(context.Background(), tx, e)
		return err
	})
}

func outboxPayload(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, idemKey string) []byte {
	t.Helper()
	var payload []byte
	if err := pool.QueryRow(ctx,
		`SELECT payload FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantID, idemKey).Scan(&payload); err != nil {
		t.Fatalf("load outbox payload: %v", err)
	}
	return payload
}

func seedLifecycleIdentity(t *testing.T, s *store.Store, tenantID, identityID string, status orchestrator.State) {
	t.Helper()
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "tenant-" + tenantID[:8]}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	ownerID := "99999999-9999-9999-9999-999999999999"
	if err := s.UpsertOwner(ctx, store.Owner{ID: ownerID, TenantID: tenantID, Kind: store.OwnerService, Name: "svc"}); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	if err := s.UpsertIdentity(ctx, store.Identity{
		ID: identityID, TenantID: tenantID, Kind: store.KindX509Certificate,
		Name: "svc.example.test", OwnerID: ownerID, Status: string(status),
	}); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
}

// TestReconcileOutboxHealsCrashGapExactlyOnce is the SPINE-011 acceptance: a crash
// between Transition's event Append and the separate transaction that projects it
// and enqueues its outbox side effect leaves the event durable but the side effect
// un-enqueued. ReconcileOutbox must re-derive the missing effect from the log and
// enqueue it EXACTLY ONCE — and a second reconcile (or a later inline retry) must
// not duplicate it.
//
// We simulate the crash by appending the lifecycle event directly to the log (the
// append committed) while NOT running the inline projection/outbox tx (the process
// "died" in the gap). The reconciler must then create the ca.issue intent. This
// must FAIL on the pre-fix tree (no reconciler exists) and PASS post-fix.
func TestReconcileOutboxHealsCrashGapExactlyOnce(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)
	orch := orchestrator.NewOrchestrator(log, s, ob)

	const identityID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	// The orphaned event: requested -> issued carries the ca.issue side effect.
	ev, err := log.Append(ctx, events.Event{
		Type:     "identity.issued",
		TenantID: tenantA,
		Data:     transitionEvent(t, identityID, orchestrator.StateRequested, orchestrator.StateIssued),
	})
	if err != nil {
		t.Fatalf("append orphaned transition: %v", err)
	}

	// Pre-condition: no outbox effect yet (the inline tx never ran).
	if got := countOutbox(t, ctx, s.SystemPool(), tenantA, ev.ID); got != 0 {
		t.Fatalf("pre-reconcile outbox rows for the orphaned event = %d, want 0", got)
	}

	// Heal.
	healed, err := orch.ReconcileOutbox(ctx, log)
	if err != nil {
		t.Fatalf("ReconcileOutbox: %v", err)
	}
	if healed != 1 {
		t.Fatalf("ReconcileOutbox healed %d effects, want 1 (the lost ca.issue)", healed)
	}
	if got := countOutbox(t, ctx, s.SystemPool(), tenantA, ev.ID); got != 1 {
		t.Fatalf("post-reconcile outbox rows = %d, want exactly 1 (ca.issue enqueued once)", got)
	}

	// Idempotent: a second reconcile must heal nothing and not duplicate.
	healed2, err := orch.ReconcileOutbox(ctx, log)
	if err != nil {
		t.Fatalf("second ReconcileOutbox: %v", err)
	}
	if healed2 != 0 {
		t.Fatalf("second ReconcileOutbox healed %d, want 0 (already enqueued)", healed2)
	}
	if got := countOutbox(t, ctx, s.SystemPool(), tenantA, ev.ID); got != 1 {
		t.Fatalf("after second reconcile outbox rows = %d, want still exactly 1 (no duplicate)", got)
	}
}

// AUD-97 is the preserved upgrade failure, reduced to its exact contract. A
// semantic request key was retained in the outbox after the first randomly-ID'd
// demo identity, then reused seventeen days later for a different identity. The
// receiver-key guard must keep the old command immutable, while boot recovery
// quarantines the NEW event as tenant-scoped evidence and continues far enough to
// heal another tenant's unrelated command.
func TestReconcileOutboxQuarantinesHistoricalCommandConflictAndContinues(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)
	orch := orchestrator.NewOrchestrator(log, s, ob)
	mustRegisterTenant(t, s, tenantA)
	mustRegisterTenant(t, s, tenantB)

	const (
		requestKey = "demo-seed-v1:identity-warehouse-mtls-deploy"
		outboxKey  = "transition:" + requestKey
		oldID      = "5481474d-7a8b-440a-a7df-fca7c8311dd0"
		newID      = "6ced6b6d-3777-44a8-a60f-40db05af7741"
	)
	oldPayload := transitionEventWithIdempotency(t, oldID, orchestrator.StateIssued, orchestrator.StateDeployed, requestKey)
	oldLane := "connector.deploy:identity:" + oldID
	if err := enqueueIfAbsent(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "connector.deploy", IdempotencyKey: outboxKey,
		EffectLane: oldLane, Payload: oldPayload,
	}); err != nil {
		t.Fatalf("seed retained pre-upgrade outbox command: %v", err)
	}

	// Event 73 in the preserved history is the immutable source for row 15. Its
	// checkpoint has already advanced, exactly like the upgrade reproduction.
	oldEvent, err := log.Append(ctx, events.Event{
		Type: "identity.deployed", TenantID: tenantA,
		SchemaVersion: projections.LifecycleSideEffectEventSchemaVersion,
		Data: replayableTransitionEvent(t, oldID, orchestrator.StateIssued, orchestrator.StateDeployed, requestKey,
			replayableTransitionSideEffect{Destination: "connector.deploy", IdempotencyKey: outboxKey, Payload: oldPayload}),
	})
	if err != nil {
		t.Fatalf("append historical source event: %v", err)
	}
	if err := s.AdvanceOutboxReconciliationCheckpoint(ctx, oldEvent.Sequence); err != nil {
		t.Fatalf("advance pre-upgrade reconciliation checkpoint: %v", err)
	}

	newPayload := transitionEventWithIdempotency(t, newID, orchestrator.StateIssued, orchestrator.StateDeployed, requestKey)
	conflictingEvent, err := log.Append(ctx, events.Event{
		Type: "identity.deployed", TenantID: tenantA,
		SchemaVersion: projections.LifecycleSideEffectEventSchemaVersion,
		Data: replayableTransitionEvent(t, newID, orchestrator.StateIssued, orchestrator.StateDeployed, requestKey,
			replayableTransitionSideEffect{
				Destination: "connector.deploy", IdempotencyKey: outboxKey,
				Payload: newPayload, RequiredAgentRole: "control_plane",
			}),
	})
	if err != nil {
		t.Fatalf("append conflicting current event: %v", err)
	}

	unrelated, err := log.Append(ctx, events.Event{
		Type: "identity.issued", TenantID: tenantB,
		Data: transitionEvent(t, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", orchestrator.StateRequested, orchestrator.StateIssued),
	})
	if err != nil {
		t.Fatalf("append unrelated tenant event: %v", err)
	}

	healed, err := orch.ReconcileOutbox(ctx, log)
	if err != nil {
		t.Fatalf("reconcile historical conflict: %v", err)
	}
	if healed != 1 {
		t.Fatalf("healed effects = %d, want the one unrelated tenant-B effect", healed)
	}
	if got := countOutbox(t, ctx, s.SystemPool(), tenantB, unrelated.ID); got != 1 {
		t.Fatalf("tenant-B command rows = %d, want 1 despite tenant-A conflict", got)
	}
	if got := countOutbox(t, ctx, s.SystemPool(), tenantA, outboxKey); got != 1 {
		t.Fatalf("conflicting key rows = %d, want immutable original only", got)
	}
	if got := outboxPayload(t, ctx, s.SystemPool(), tenantA, outboxKey); !bytes.Equal(got, oldPayload) {
		t.Fatalf("retained command changed from %s to %s", oldPayload, got)
	}

	conflicts, err := s.ListOutboxReconciliationConflicts(ctx, tenantA, 10)
	if err != nil {
		t.Fatalf("list tenant-A recovery incidents: %v", err)
	}
	if len(conflicts) != 1 {
		t.Fatalf("tenant-A recovery incidents = %d, want 1", len(conflicts))
	}
	conflict := conflicts[0]
	if conflict.SourceEventID != conflictingEvent.ID || conflict.SourceEventSequence != conflictingEvent.Sequence ||
		conflict.IdempotencyKey != outboxKey || conflict.ExistingEffectLane != oldLane ||
		conflict.CandidateEffectLane != "connector.deploy:identity:"+newID || conflict.CandidateRequiredAgentRole != "control_plane" ||
		conflict.Status != "quarantined" || conflict.ExistingPayloadSHA256 == conflict.CandidatePayloadSHA256 {
		t.Fatalf("recovery incident does not bind both immutable commands: %+v", conflict)
	}
	otherTenant, err := s.ListOutboxReconciliationConflicts(ctx, tenantB, 10)
	if err != nil || len(otherTenant) != 0 {
		t.Fatalf("tenant-B recovery incidents = %v err=%v, want none", otherTenant, err)
	}

	// The first pass appends one immutable quarantine event after its pinned replay
	// head. A second pass consumes that event and must neither duplicate the
	// incident nor enqueue either receiver command again.
	healed, err = orch.ReconcileOutbox(ctx, log)
	if err != nil || healed != 0 {
		t.Fatalf("second reconcile = (%d, %v), want (0, nil)", healed, err)
	}
	conflicts, err = s.ListOutboxReconciliationConflicts(ctx, tenantA, 10)
	if err != nil || len(conflicts) != 1 {
		t.Fatalf("repeated reconcile incidents = %d err=%v, want exactly 1", len(conflicts), err)
	}
	var conflictEvents int
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type == projections.EventOutboxReconciliationConflictRecorded {
			conflictEvents++
		}
		return nil
	}); err != nil {
		t.Fatalf("replay recovery incidents: %v", err)
	}
	if conflictEvents != 1 {
		t.Fatalf("immutable recovery incident events = %d, want 1", conflictEvents)
	}
}

// AUD-31: the fleet cursor event is also the recovery source for its one
// unpublished command. This simulates a crash after the event append but before
// the PostgreSQL projection/outbox transaction committed, then proves restart
// recreates exactly the current cursor and never duplicates it.
func TestReconcileOutboxHealsFleetCursorCrashGapExactlyOnce(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	orch := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))

	const runID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	const batchIndex = 2
	outboxKey := orchestrator.FleetReissuanceBatchIdempotencyKey(runID, batchIndex)
	payload, err := json.Marshal(projections.IncidentFleetReissuanceRecorded{
		ID: runID, Status: "running", Phase: "batch_2_queued", NextBatchIndex: batchIndex,
		Batches: []projections.FleetReissuanceBatch{
			{Index: 1, Status: "executed"},
			{Index: batchIndex, Status: "queued"},
		},
	})
	if err != nil {
		t.Fatalf("encode fleet cursor event: %v", err)
	}
	if _, err := log.Append(ctx, events.Event{
		Type: projections.EventIncidentFleetReissuanceRecorded, TenantID: tenantA, Data: payload,
	}); err != nil {
		t.Fatalf("append orphaned fleet cursor event: %v", err)
	}
	if got := countOutbox(t, ctx, s.SystemPool(), tenantA, outboxKey); got != 0 {
		t.Fatalf("pre-reconcile fleet cursor rows = %d, want 0", got)
	}

	healed, err := orch.ReconcileOutbox(ctx, log)
	if err != nil {
		t.Fatalf("ReconcileOutbox fleet cursor: %v", err)
	}
	if healed != 1 || countOutbox(t, ctx, s.SystemPool(), tenantA, outboxKey) != 1 {
		t.Fatalf("fleet cursor reconcile healed=%d rows=%d, want 1/1",
			healed, countOutbox(t, ctx, s.SystemPool(), tenantA, outboxKey))
	}
	var command orchestrator.FleetReissuanceBatchCommand
	if err := json.Unmarshal(outboxPayload(t, ctx, s.SystemPool(), tenantA, outboxKey), &command); err != nil {
		t.Fatalf("decode healed fleet command: %v", err)
	}
	if command.RunID != runID || command.BatchIndex != batchIndex {
		t.Fatalf("healed fleet command = %+v, want run=%s batch=%d", command, runID, batchIndex)
	}
	healed, err = orch.ReconcileOutbox(ctx, log)
	if err != nil {
		t.Fatalf("second ReconcileOutbox fleet cursor: %v", err)
	}
	if healed != 0 || countOutbox(t, ctx, s.SystemPool(), tenantA, outboxKey) != 1 {
		t.Fatalf("second fleet reconcile healed=%d rows=%d, want 0/1",
			healed, countOutbox(t, ctx, s.SystemPool(), tenantA, outboxKey))
	}
}

func TestReconcileOutboxHealsCTSubmissionCrashGapExactlyOnce(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)
	orch := orchestrator.NewOrchestrator(log, s, ob)

	const (
		submissionID = "ct-red-004-submission"
		requestKey   = "red-004-ct-submit"
		outboxKey    = "ct.submit:" + requestKey + ":certificate:" + submissionID
	)
	data, err := json.Marshal(struct {
		Capability string `json:"capability"`
		Payloads   []struct {
			Capability            string   `json:"capability"`
			SubmissionID          string   `json:"submission_id"`
			LogURL                string   `json:"log_url"`
			EntryType             string   `json:"entry_type"`
			LeafDER               []byte   `json:"leaf_der"`
			ChainDER              [][]byte `json:"chain_der,omitempty"`
			LeafSHA256Fingerprint string   `json:"leaf_sha256_fingerprint"`
			Subject               string   `json:"subject"`
			SerialNumber          string   `json:"serial_number"`
			IdempotencyKey        string   `json:"idempotency_key"`
			AllowPrivateEndpoint  bool     `json:"allow_private_endpoint,omitempty"`
		} `json:"payloads"`
	}{
		Capability: "CAP-REV-06",
		Payloads: []struct {
			Capability            string   `json:"capability"`
			SubmissionID          string   `json:"submission_id"`
			LogURL                string   `json:"log_url"`
			EntryType             string   `json:"entry_type"`
			LeafDER               []byte   `json:"leaf_der"`
			ChainDER              [][]byte `json:"chain_der,omitempty"`
			LeafSHA256Fingerprint string   `json:"leaf_sha256_fingerprint"`
			Subject               string   `json:"subject"`
			SerialNumber          string   `json:"serial_number"`
			IdempotencyKey        string   `json:"idempotency_key"`
			AllowPrivateEndpoint  bool     `json:"allow_private_endpoint,omitempty"`
		}{{
			Capability: "CAP-REV-06", SubmissionID: submissionID, LogURL: "http://127.0.0.1/ct",
			EntryType: "certificate", LeafDER: []byte("leaf"), LeafSHA256Fingerprint: "fp",
			Subject: "CN=red-004.example", SerialNumber: "01", IdempotencyKey: requestKey,
			AllowPrivateEndpoint: true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{
		Type:     "ct.submission.queued",
		TenantID: tenantA,
		Data:     data,
	}); err != nil {
		t.Fatalf("append orphaned CT submission event: %v", err)
	}
	if got := countOutbox(t, ctx, s.SystemPool(), tenantA, outboxKey); got != 0 {
		t.Fatalf("pre-reconcile CT outbox rows = %d, want 0", got)
	}

	healed, err := orch.ReconcileOutbox(ctx, log)
	if err != nil {
		t.Fatalf("ReconcileOutbox: %v", err)
	}
	if healed != 1 {
		t.Fatalf("ReconcileOutbox healed %d CT submissions, want 1", healed)
	}
	if got := countOutbox(t, ctx, s.SystemPool(), tenantA, outboxKey); got != 1 {
		t.Fatalf("post-reconcile CT outbox rows = %d, want 1", got)
	}
	healed, err = orch.ReconcileOutbox(ctx, log)
	if err != nil {
		t.Fatalf("second ReconcileOutbox: %v", err)
	}
	if healed != 0 || countOutbox(t, ctx, s.SystemPool(), tenantA, outboxKey) != 1 {
		t.Fatalf("second reconcile healed=%d outbox=%d, want healed=0 outbox=1", healed, countOutbox(t, ctx, s.SystemPool(), tenantA, outboxKey))
	}
}

func TestReconcileOutboxHealsLicensedCryptoMigrationCrashGapExactlyOnce(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)
	orch := orchestrator.NewOrchestrator(log, s, ob)

	const (
		runID     = "red-004-licensed-crypto-run"
		assetID   = "red-004-asset"
		outboxKey = "licensed-crypto-migration:" + runID + ":" + assetID
	)
	data, err := json.Marshal(projections.LicensedCryptoMigrationStarted{
		RunID: runID, AssetIDs: []string{assetID}, TargetAlgorithm: "licensed-signature-target",
		EffectiveAlgorithm: "licensed-transition-leaf", Protocol: "acme",
		RollbackOnFailure: true, Queued: 1,
		Reissues: []projections.LicensedCryptoMigrationReissue{{
			RunID: runID, AssetID: assetID, Kind: "certificate-key", Location: "edge.example:443",
			Algorithm: "RSA", KeyBits: 2048, Strength: "weak", QuantumVulnerable: true,
			TargetAlgorithm: "licensed-signature-target", EffectiveAlgorithm: "licensed-transition-leaf",
			Protocol: "acme", RollbackOnFailure: true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{
		Type:     projections.EventLicensedCryptoMigrationStarted,
		TenantID: tenantA,
		Data:     data,
	}); err != nil {
		t.Fatalf("append orphaned licensed crypto migration event: %v", err)
	}
	if got := countOutbox(t, ctx, s.SystemPool(), tenantA, outboxKey); got != 0 {
		t.Fatalf("pre-reconcile licensed crypto outbox rows = %d, want 0", got)
	}

	healed, err := orch.ReconcileOutbox(ctx, log)
	if err != nil {
		t.Fatalf("ReconcileOutbox: %v", err)
	}
	if healed != 1 {
		t.Fatalf("ReconcileOutbox healed %d licensed crypto migration effects, want 1", healed)
	}
	if got := countOutbox(t, ctx, s.SystemPool(), tenantA, outboxKey); got != 1 {
		t.Fatalf("post-reconcile licensed crypto outbox rows = %d, want 1", got)
	}
	healed, err = orch.ReconcileOutbox(ctx, log)
	if err != nil {
		t.Fatalf("second ReconcileOutbox: %v", err)
	}
	if healed != 0 || countOutbox(t, ctx, s.SystemPool(), tenantA, outboxKey) != 1 {
		t.Fatalf("second reconcile healed=%d outbox=%d, want healed=0 outbox=1", healed, countOutbox(t, ctx, s.SystemPool(), tenantA, outboxKey))
	}
}

func TestReconcileOutboxPreservesLifecycleRequestIdempotencyKey(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)
	orch := orchestrator.NewOrchestrator(log, s, ob)

	const (
		identityID = "abababab-abab-abab-abab-abababababab"
		requestKey = "correct-001-reconcile"
		outboxKey  = "transition:" + requestKey
	)
	ev, err := log.Append(ctx, events.Event{
		Type:          "identity.issued",
		TenantID:      tenantA,
		SchemaVersion: projections.LifecycleEventSchemaVersion,
		Data:          transitionEventWithIdempotency(t, identityID, orchestrator.StateRequested, orchestrator.StateIssued, requestKey),
	})
	if err != nil {
		t.Fatalf("append v2 orphaned transition: %v", err)
	}
	if got := countOutbox(t, ctx, s.SystemPool(), tenantA, outboxKey); got != 0 {
		t.Fatalf("pre-reconcile request-keyed outbox rows = %d, want 0", got)
	}

	healed, err := orch.ReconcileOutbox(ctx, log)
	if err != nil {
		t.Fatalf("ReconcileOutbox: %v", err)
	}
	if healed != 1 {
		t.Fatalf("ReconcileOutbox healed %d effects, want 1", healed)
	}
	if got := countOutbox(t, ctx, s.SystemPool(), tenantA, outboxKey); got != 1 {
		t.Fatalf("request-keyed outbox rows = %d, want 1", got)
	}
	if got := countOutbox(t, ctx, s.SystemPool(), tenantA, ev.ID); got != 0 {
		t.Fatalf("event-keyed outbox rows = %d, want 0 for v2 request-keyed transition", got)
	}
}

func TestReconcileOutboxRestoresReplayableLifecycleSideEffectPayload(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)
	orch := orchestrator.NewOrchestrator(log, s, ob)

	const identityID = "fefefefe-fefe-fefe-fefe-fefefefefefe"
	seedLifecycleIdentity(t, s, tenantA, identityID, orchestrator.StateIssued)

	var wantPayload []byte
	err := orch.TransitionWithSideEffectPayloadTransform(
		ctx,
		tenantA,
		identityID,
		orchestrator.StateDeployed,
		"deploy credential",
		[]byte(`{"transient":"credential"}`),
		func(_ context.Context, c orchestrator.SideEffectPayloadContext) ([]byte, error) {
			wantPayload = []byte(`{"sealed_for":"` + c.IdempotencyKey + `","body":"credential"}`)
			return wantPayload, nil
		},
	)
	if err != nil {
		t.Fatalf("transition with side-effect payload: %v", err)
	}

	var eventID string
	if err := log.Replay(ctx, 1, func(ev events.Event) error {
		if ev.Type == "identity.deployed" {
			eventID = ev.ID
		}
		return nil
	}); err != nil {
		t.Fatalf("replay lifecycle event: %v", err)
	}
	if eventID == "" {
		t.Fatal("identity.deployed event was not appended")
	}
	if !bytes.Contains(wantPayload, []byte(eventID)) {
		t.Fatalf("side-effect payload was sealed for %s, want event-derived key %s", wantPayload, eventID)
	}

	// Simulate the append-then-enqueue crash gap after the event is durable but before
	// the outbox row survives. Reconciliation must recreate the exact durable payload
	// carried by the event, not fall back to the lifecycle metadata body.
	if _, err := s.SystemPool().Exec(ctx,
		`DELETE FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantA, eventID); err != nil {
		t.Fatalf("delete inline outbox row: %v", err)
	}
	healed, err := orch.ReconcileOutbox(ctx, log)
	if err != nil {
		t.Fatalf("ReconcileOutbox: %v", err)
	}
	if healed != 1 {
		t.Fatalf("ReconcileOutbox healed %d effects, want 1", healed)
	}
	gotPayload := outboxPayload(t, ctx, s.SystemPool(), tenantA, eventID)
	if !bytes.Equal(gotPayload, wantPayload) {
		t.Fatalf("reconciled payload = %s, want replayable side-effect payload %s", gotPayload, wantPayload)
	}
}

func TestReconcileOutboxRejectsNewLifecycleSideEffectEventWithoutReplayablePayload(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)
	orch := orchestrator.NewOrchestrator(log, s, ob)

	const identityID = "12121212-1212-1212-1212-121212121212"
	ev, err := log.Append(ctx, events.Event{
		Type:          "identity.issued",
		TenantID:      tenantA,
		SchemaVersion: projections.LifecycleSideEffectEventSchemaVersion,
		Data:          transitionEvent(t, identityID, orchestrator.StateRequested, orchestrator.StateIssued),
	})
	if err != nil {
		t.Fatalf("append malformed v3 lifecycle event: %v", err)
	}

	healed, err := orch.ReconcileOutbox(ctx, log)
	if err == nil || !strings.Contains(err.Error(), "replayable side_effect is required") {
		t.Fatalf("ReconcileOutbox err = %v, want missing replayable side_effect error", err)
	}
	if healed != 0 {
		t.Fatalf("ReconcileOutbox healed %d effects before malformed event failure, want 0", healed)
	}
	if got := countOutbox(t, ctx, s.SystemPool(), tenantA, ev.ID); got != 0 {
		t.Fatalf("outbox rows after malformed v3 lifecycle event = %d, want 0", got)
	}
}

// TestReconcileOutboxSkipsEffectlessTransitions proves the reconciler only
// enqueues effects for transitions that HAVE a side effect: issued -> deployed has
// connector.deploy, but a purely internal transition (revoked -> retired) has none,
// so it is left alone.
func TestReconcileOutboxSkipsEffectlessTransitions(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)
	orch := orchestrator.NewOrchestrator(log, s, ob)

	const identityID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	// revoked -> retired: a valid transition with NO side effect.
	if _, err := log.Append(ctx, events.Event{
		Type:     "identity.retired",
		TenantID: tenantA,
		Data:     transitionEvent(t, identityID, orchestrator.StateRevoked, orchestrator.StateRetired),
	}); err != nil {
		t.Fatal(err)
	}
	healed, err := orch.ReconcileOutbox(ctx, log)
	if err != nil {
		t.Fatalf("ReconcileOutbox: %v", err)
	}
	if healed != 0 {
		t.Fatalf("reconcile healed %d for an effectless transition, want 0", healed)
	}
}

// TestReconcileOutboxDoesNotDoubleEnqueueWithInlinePath proves the inline Transition
// path and the reconciler cooperate: when the inline path already enqueued the
// effect (the normal, no-crash case), a subsequent reconcile adds nothing. We model
// the inline enqueue with EnqueueIfAbsent keyed by the event ID (exactly what
// Transition does), then reconcile and assert no duplicate.
func TestReconcileOutboxDoesNotDoubleEnqueueWithInlinePath(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)
	orch := orchestrator.NewOrchestrator(log, s, ob)

	const identityID = "cccccccc-cccc-cccc-cccc-cccccccccccc"
	ev, err := log.Append(ctx, events.Event{
		Type:     "identity.issued",
		TenantID: tenantA,
		Data:     transitionEvent(t, identityID, orchestrator.StateRequested, orchestrator.StateIssued),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Inline path landed the effect.
	if err := enqueueIfAbsent(t, s, ob, orchestrator.Entry{
		TenantID: tenantA, Destination: "ca.issue", IdempotencyKey: ev.ID, Payload: ev.Data,
	}); err != nil {
		t.Fatalf("inline enqueue: %v", err)
	}
	// Reconcile sees the effect already present and heals nothing.
	healed, err := orch.ReconcileOutbox(ctx, log)
	if err != nil {
		t.Fatal(err)
	}
	if healed != 0 {
		t.Fatalf("reconcile healed %d after inline enqueue, want 0", healed)
	}
	if got := countOutbox(t, ctx, s.SystemPool(), tenantA, ev.ID); got != 1 {
		t.Fatalf("outbox rows = %d, want exactly 1 (no double-enqueue)", got)
	}
}

func TestReconcileOutboxResumesFromCheckpointTail(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)
	orch := orchestrator.NewOrchestrator(log, s, ob)

	for i := 0; i < 128; i++ {
		if _, err := log.Append(ctx, events.Event{
			Type:     projections.EventOwnerCreated,
			TenantID: tenantA,
			Data:     []byte(`{"id":"owner-prefix","kind":"team","name":"prefix","email":"prefix@example.test"}`),
		}); err != nil {
			t.Fatalf("append warm-prefix event %d: %v", i, err)
		}
	}

	// This malformed lifecycle event is deliberately behind the reconciliation
	// checkpoint. A lifetime replay would decode it and fail; a checkpointed replay
	// starts after it and only scans the unreconciled tail.
	poison, err := log.Append(ctx, events.Event{
		Type:     "identity.issued",
		TenantID: tenantA,
		Data:     []byte(`{`),
	})
	if err != nil {
		t.Fatalf("append poison prefix event: %v", err)
	}
	if err := s.AdvanceProjectionCheckpoint(ctx, poison.Sequence); err != nil {
		t.Fatalf("advance warm projection checkpoint: %v", err)
	}
	if err := s.AdvanceOutboxReconciliationCheckpoint(ctx, poison.Sequence); err != nil {
		t.Fatalf("advance warm outbox reconciliation checkpoint: %v", err)
	}

	const identityID = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
	tail, err := log.Append(ctx, events.Event{
		Type:     "identity.issued",
		TenantID: tenantA,
		Data:     transitionEvent(t, identityID, orchestrator.StateRequested, orchestrator.StateIssued),
	})
	if err != nil {
		t.Fatalf("append unreconciled tail transition: %v", err)
	}
	if _, err := log.Append(ctx, events.Event{
		Type:     projections.EventOwnerCreated,
		TenantID: tenantA,
		Data:     []byte(`{"id":"owner-tail","kind":"team","name":"tail","email":"tail@example.test"}`),
	}); err != nil {
		t.Fatalf("append non-lifecycle tail event: %v", err)
	}

	if got := countOutbox(t, ctx, s.SystemPool(), tenantA, tail.ID); got != 0 {
		t.Fatalf("pre-reconcile tail outbox rows = %d, want 0", got)
	}

	healed, err := orch.ReconcileOutbox(ctx, log)
	if err != nil {
		t.Fatalf("ReconcileOutbox: %v", err)
	}
	if healed != 1 {
		t.Fatalf("ReconcileOutbox healed %d effects, want 1 tail effect", healed)
	}
	if got := countOutbox(t, ctx, s.SystemPool(), tenantA, tail.ID); got != 1 {
		t.Fatalf("post-reconcile tail outbox rows = %d, want exactly 1", got)
	}
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatalf("last sequence: %v", err)
	}
	checkpoint, err := s.OutboxReconciliationCheckpoint(ctx)
	if err != nil {
		t.Fatalf("read outbox reconciliation checkpoint: %v", err)
	}
	if checkpoint != head {
		t.Fatalf("outbox reconciliation checkpoint = %d, want log head %d", checkpoint, head)
	}
}

func TestReconcileOutboxRejectsUnknownLifecycleSchemaVersion(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)
	orch := orchestrator.NewOrchestrator(log, s, ob)

	const identityID = "dddddddd-dddd-dddd-dddd-dddddddddddd"
	ev, err := log.Append(ctx, events.Event{
		Type:          "identity.issued",
		TenantID:      tenantA,
		SchemaVersion: 99,
		Data:          transitionEvent(t, identityID, orchestrator.StateRequested, orchestrator.StateIssued),
	})
	if err != nil {
		t.Fatalf("append unknown-version transition: %v", err)
	}

	healed, err := orch.ReconcileOutbox(ctx, log)
	if !errors.Is(err, projections.ErrUnknownSchemaVersion) {
		t.Fatalf("ReconcileOutbox err = %v, want ErrUnknownSchemaVersion", err)
	}
	if healed != 0 {
		t.Fatalf("ReconcileOutbox healed %d effects before schema failure, want 0", healed)
	}
	if got := countOutbox(t, ctx, s.SystemPool(), tenantA, ev.ID); got != 0 {
		t.Fatalf("outbox rows after unknown schema reconcile = %d, want 0", got)
	}
}
