package orchestrator_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

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

func TestReconcileOutboxHealsPQCMigrationCrashGapExactlyOnce(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)
	orch := orchestrator.NewOrchestrator(log, s, ob)

	const (
		runID     = "red-004-pqc-run"
		assetID   = "red-004-asset"
		outboxKey = "pqc-migration:" + runID + ":" + assetID
	)
	data, err := json.Marshal(projections.PQCMigrationStarted{
		RunID: runID, AssetIDs: []string{assetID}, TargetAlgorithm: "ML-DSA-65",
		EffectiveAlgorithm: "ML-DSA-44+ECDSA-P256", Protocol: "acme",
		RollbackOnFailure: true, Queued: 1,
		Reissues: []projections.PQCMigrationReissue{{
			RunID: runID, AssetID: assetID, Kind: "certificate-key", Location: "edge.example:443",
			Algorithm: "RSA", KeyBits: 2048, Strength: "weak", QuantumVulnerable: true,
			TargetAlgorithm: "ML-DSA-65", EffectiveAlgorithm: "ML-DSA-44+ECDSA-P256",
			Protocol: "acme", RollbackOnFailure: true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{
		Type:     projections.EventPQCMigrationStarted,
		TenantID: tenantA,
		Data:     data,
	}); err != nil {
		t.Fatalf("append orphaned PQC migration event: %v", err)
	}
	if got := countOutbox(t, ctx, s.SystemPool(), tenantA, outboxKey); got != 0 {
		t.Fatalf("pre-reconcile PQC outbox rows = %d, want 0", got)
	}

	healed, err := orch.ReconcileOutbox(ctx, log)
	if err != nil {
		t.Fatalf("ReconcileOutbox: %v", err)
	}
	if healed != 1 {
		t.Fatalf("ReconcileOutbox healed %d PQC migration effects, want 1", healed)
	}
	if got := countOutbox(t, ctx, s.SystemPool(), tenantA, outboxKey); got != 1 {
		t.Fatalf("post-reconcile PQC outbox rows = %d, want 1", got)
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
