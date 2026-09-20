// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type schedulerPrivacyTestProtector struct{}

func (schedulerPrivacyTestProtector) Protect(
	_ context.Context, tenantID, key, binding string, plaintext []byte,
) (string, []byte, error) {
	prefix := []byte("CSL1scheduler-privacy-test\x00" + tenantID + "\x00" + key + "\x00" + binding + "\x00")
	return orchestrator.ResultCodecSealedRowV1, append(prefix, plaintext...), nil
}

func (schedulerPrivacyTestProtector) Open(
	_ context.Context, tenantID, key, binding, codec string, protected []byte,
) ([]byte, error) {
	if codec != orchestrator.ResultCodecSealedRowV1 {
		return nil, fmt.Errorf("test scheduler privacy codec %q is unsupported", codec)
	}
	prefix := []byte("CSL1scheduler-privacy-test\x00" + tenantID + "\x00" + key + "\x00" + binding + "\x00")
	if !bytes.HasPrefix(protected, prefix) {
		return nil, errors.New("test scheduler privacy envelope AAD differs")
	}
	return append([]byte(nil), protected[len(prefix):]...), nil
}

func TestPreparePrivacySubjectErasureAtomicallyClosesProtectedSchedulerLineage(t *testing.T) {
	ctx := context.Background()
	st := newOperationApprovalStore(t)
	const (
		subject         = "alice"
		rawTickKey      = "scheduler:alice:outer"
		tickBinding     = "sha256:scheduler-privacy-binding"
		scheduleID      = "10610610-6106-4106-8106-106106106106"
		runID           = "20620620-6206-4206-8206-206206206206"
		terminalEventID = "30630630-6306-4306-8306-306306306306"
	)
	dueAt := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	terminalBody := []byte(`{"ran":0,"scanned":0,"runs":[],"deferred":[],"run_limit_reached":false,"scan_limit_reached":false,"complete":true,"partial":false,"system_error":"alice"}`)
	plaintext, err := json.Marshal(struct {
		Status  int             `json:"s"`
		Body    json.RawMessage `json:"b"`
		Binding string          `json:"h,omitempty"`
	}{Status: 200, Body: terminalBody, Binding: tickBinding})
	if err != nil {
		t.Fatal(err)
	}
	protector := schedulerPrivacyTestProtector{}
	codec, protected, err := protector.Protect(
		ctx, tenantA, rawTickKey, tickBinding, plaintext,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SystemPool().Exec(ctx,
		`INSERT INTO idempotency_keys
		        (tenant_id, key, status, request_binding, result_codec, result, completed_at)
		 VALUES ($1, $2, 'completed', $3, $4, $5, clock_timestamp())`,
		tenantA, rawTickKey, tickBinding, codec, protected); err != nil {
		t.Fatalf("seed protected scheduler outer: %v", err)
	}
	if _, err := st.SystemPool().Exec(ctx,
		`INSERT INTO secret_rotation_schedule_scan_cursors (tenant_id) VALUES ($1)`,
		tenantA); err != nil {
		t.Fatalf("seed scheduler cursor: %v", err)
	}
	if _, err := st.SystemPool().Exec(ctx,
		`INSERT INTO secret_rotation_schedule_ticks
		        (tenant_id, idempotency_key, request_binding, due_through,
		         start_schedule_id, after_schedule_id, phase, ran, scanned,
		         snapshot_count, receipt, owner_token, owner_generation,
		         terminal_http_status, terminal_body, created_at, updated_at, completed_at)
		 VALUES ($1, $2, $3, $4, $5, $5, 'terminal', 0, 0, 0,
		         $6::jsonb, '', 1, 200, $7::bytea, $4, $4, $4)`,
		tenantA, rawTickKey, tickBinding, dueAt, scheduleID,
		string(terminalBody), terminalBody); err != nil {
		t.Fatalf("seed terminal scheduler tick: %v", err)
	}
	if _, err := st.SystemPool().Exec(ctx,
		`INSERT INTO secret_rotation_schedule_commands
		        (tenant_id, schedule_id, run_id, due_at, provider, secret_key,
		         old_ref, interval_seconds, config_event_sequence,
		         tick_idempotency_key, tick_ordinal, command_key,
		         request_binding, terminal_event_id, status,
		         created_at, updated_at)
		 VALUES ($1, $2, $3, $4, 'connector:alice', 'vault/alice',
		         'version:1', 60, 1, $5, 1, 'command-scheduler-privacy',
		         'sha256:command-binding', $6, 'claimed', $4, $4)`,
		tenantA, scheduleID, runID, dueAt, rawTickKey, terminalEventID); err != nil {
		t.Fatalf("seed scheduler command: %v", err)
	}

	idem := orchestrator.NewIdempotency(
		st, orchestrator.WithResultProtector(protector),
	)
	subjectRef := privacy.SubjectRef(tenantA, subject)
	candidate := store.PrivacySubjectErasurePreparation{
		PrivacySubjectErasure: store.PrivacySubjectErasure{
			TenantID: tenantA, SubjectRef: subjectRef,
			ErasedAt: dueAt.Add(time.Hour),
		},
		OperationID:        "sha256:" + strings.Repeat("1", 64),
		RequestBinding:     "sha256:scheduler-full-erasure",
		EventID:            "sha256:" + strings.Repeat("2", 64),
		RewriteOperationID: "sha256:" + strings.Repeat("3", 64),
		TargetGeneration:   "scheduler-privacy-generation",
	}
	t.Cleanup(func() {
		if _, err := st.SystemPool().Exec(context.Background(),
			`DELETE FROM privacy_subject_erasure_preparations
			  WHERE tenant_id = $1 AND operation_id = $2`,
			tenantA, candidate.OperationID); err != nil {
			t.Errorf("clean scheduler privacy preparation: %v", err)
		}
	})
	prepared, err := st.PreparePrivacySubjectErasureWithSchedulerResolver(
		ctx, tenantA, subject, candidate,
		idem.ResolveSecretRotationSchedulePrivacyOuter,
	)
	if err != nil {
		t.Fatalf("prepare protected scheduler privacy erasure: %v", err)
	}
	if prepared.Counts["secret_rotation_schedule_ticks"] != 1 ||
		prepared.Counts["secret_rotation_schedule_tick_rows"] != 0 ||
		prepared.Counts["secret_rotation_schedule_commands"] != 1 ||
		prepared.Counts["secret_rotation_schedule_outer_resolutions"] != 1 ||
		len(prepared.SchedulerDispositions) != 2 {
		t.Fatalf("scheduler preparation evidence = counts=%+v dispositions=%+v",
			prepared.Counts, prepared.SchedulerDispositions)
	}
	if err := store.ValidateSecretRotationSchedulePrivacyEvidenceV3(
		prepared.Counts, prepared.SchedulerDispositions,
	); err != nil {
		t.Fatalf("validate scheduler preparation evidence: %v", err)
	}
	var tickAuthorityRef string
	for _, disposition := range prepared.SchedulerDispositions {
		if disposition.Kind == store.SecretRotationSchedulePrivacyDispositionTick {
			tickAuthorityRef = disposition.AuthorityRef
		}
	}
	if tickAuthorityRef == "" {
		t.Fatal("prepared scheduler evidence lacks tick authority")
	}
	replacementKey := "privacy-scheduler:" + tickAuthorityRef
	var outerResult []byte
	var outerCodec, tickPhase, commandStatus string
	var rawExists bool
	if err := st.SystemPool().QueryRow(ctx,
		`SELECT EXISTS (
		          SELECT 1 FROM idempotency_keys WHERE tenant_id = $1 AND key = $2
		        ), resolved.result_codec, resolved.result, tick.phase, cmd.status
		   FROM idempotency_keys resolved
		   JOIN secret_rotation_schedule_ticks tick
		     ON tick.tenant_id = resolved.tenant_id AND tick.idempotency_key = resolved.key
		   JOIN secret_rotation_schedule_commands cmd
		     ON cmd.tenant_id = resolved.tenant_id AND cmd.run_id = $4::uuid
		  WHERE resolved.tenant_id = $1 AND resolved.key = $3`,
		tenantA, rawTickKey, replacementKey, runID).Scan(
		&rawExists, &outerCodec, &outerResult, &tickPhase, &commandStatus); err != nil {
		t.Fatalf("load atomically closed scheduler lineage: %v", err)
	}
	if rawExists || tickPhase != "privacy_erased" || commandStatus != "privacy_erased" {
		t.Fatalf("closed scheduler lineage raw=%t tick=%q command=%q",
			rawExists, tickPhase, commandStatus)
	}
	opened, err := protector.Open(
		ctx, tenantA, replacementKey, tickBinding, outerCodec, outerResult,
	)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(opened, []byte(subject)) || !bytes.Contains(opened, []byte(`"system_error":""`)) {
		t.Fatalf("re-protected scheduler terminal response was not erased: %s", opened)
	}

	resolverCalls := 0
	retried, err := st.PreparePrivacySubjectErasureWithSchedulerResolver(
		ctx, tenantA, subject, candidate,
		func(context.Context, pgx.Tx, string, string,
			store.SecretRotationSchedulePrivacyOuterRequirement,
		) (store.SecretRotationSchedulePrivacyOuterAcknowledgement, error) {
			resolverCalls++
			return store.SecretRotationSchedulePrivacyOuterAcknowledgement{}, errors.New("resolver must not run on retry")
		},
	)
	if err != nil || resolverCalls != 0 || !reflect.DeepEqual(retried, prepared) {
		t.Fatalf("prepared crash retry = %+v calls=%d err=%v, want exact stored evidence",
			retried, resolverCalls, err)
	}
}

func TestPreparePrivacySubjectErasureSnapshotsAuthorityAndRewritesRecoveryFencesAtomically(t *testing.T) {
	ctx := context.Background()
	st := newOperationApprovalStore(t)
	const subject = "alice"
	placeholder := privacy.Placeholder(privacy.SubjectRef(tenantA, subject))
	legacyApprovalResource := "credential/" + subject
	legacyApprovalAction := "rotate/on-behalf-of/" + subject
	legacyCodeSigningKey := "release/" + subject + "/legacy-command"
	legacyCodeSigningOperationID := store.LegacyCodeSigningOperationID(tenantA, legacyCodeSigningKey)
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO issuance_approval_requests
			(tenant_id, resource, action, requester, required)
			VALUES ($1, $2, $3, $4, 1)`,
			tenantA, legacyApprovalResource, legacyApprovalAction, subject); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO issuance_approvals
			(tenant_id, resource, action, approver)
			VALUES ($1, $2, $3, $4)`,
			tenantA, legacyApprovalResource, legacyApprovalAction, subject)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = st.WithTenant(context.Background(), tenantA, func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), `DELETE FROM issuance_approval_requests
				WHERE tenant_id = $1 AND resource = $2 AND action = $3`,
				tenantA, legacyApprovalResource, legacyApprovalAction)
			return err
		})
	})

	payload, request := approveApplicationSecretMutation(t, st, projections.ApplicationSecretMutation{
		Action: "rotate", Name: "secret/" + subject, ExpectedVersion: 1, ResultVersion: 2,
		Sealed: []byte("sealed-v2"), IdempotencyKeyDigest: strings.Repeat("a", 64),
		RequestBinding: strings.Repeat("b", 64), CommandEvidence: strings.Repeat("c", 64), Surface: "rotation",
		Sync: &projections.SecretSyncQueued{
			ID: "sync-alice", SecretName: "secret/" + subject, SecretVersion: 2,
			Target: "target/" + subject, RemoteKey: "remote/" + subject,
			ValueDigest: strings.Repeat("d", 64), IdempotencyKey: "sync-key",
			RequestBinding: strings.Repeat("b", 64), Sealed: []byte("sync-sealed"),
		},
	}, "77952000-0000-4000-8000-000000000001", "sha256:"+strings.Repeat("e", 64),
		"77952000-0000-4000-8000-000000000002")
	use := *payload.Approval
	payload.Approval = nil
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyCodeSigningIntentTx(ctx, tx, store.CodeSigningOperation{
			TenantID: tenantA, OperationID: legacyCodeSigningOperationID,
			IdempotencyKey: legacyCodeSigningKey, Mode: "key",
			RequestHash: strings.Repeat("9", 64), SealedCommand: []byte("legacy-sealed-command"),
			CreatedAt: operationApprovalBaseTime, UpdatedAt: operationApprovalBaseTime,
		}, []byte(`{"operation_id":"`+legacyCodeSigningOperationID+`"}`))
	}); err != nil {
		t.Fatalf("seed warm legacy code-signing row: %v", err)
	}
	fence := store.ApplicationSecretMutationFence{
		TenantID: tenantA, Name: payload.Name, Operation: payload.Action,
		EventID: "77952000-0000-4000-8000-000000000003", EventType: projections.EventApplicationSecretRotated,
		SchemaVersion: projections.ApplicationSecretMutationSchemaVersion, ApprovalRequired: true,
		RequesterSealed: []byte("sealed-alice"), RequesterRef: privacy.SubjectRef(tenantA, subject),
		RequestBinding: payload.RequestBinding, Payload: raw,
		Actor: &events.Actor{
			Subject: subject,
			Roles:   []string{"operator", "scope:" + subject, "auditor", subject + ":delegate"},
		},
	}
	if _, err := st.ClaimApplicationSecretMutationFence(ctx, fence); err != nil {
		t.Fatal(err)
	}
	if _, err := st.FinalizeApplicationSecretMutationFence(ctx, tenantA, fence.Name,
		fence.EventID, &use, operationApprovalBaseTime.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	projector := projections.New(st)
	if written, err := projector.Snapshot(ctx); err != nil || written != 2 {
		t.Fatalf("capture pre-erasure snapshot set = (%d,%v), want (2,nil)", written, err)
	}
	var rawSnapshot []byte
	if err := st.SystemPool().QueryRow(ctx, `SELECT payload FROM read_model_snapshots
		WHERE tenant_id = $1`, tenantA).Scan(&rawSnapshot); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rawSnapshot, []byte(subject)) {
		t.Fatalf("pre-erasure snapshot fixture lacks raw subject %q", subject)
	}

	// The command crosses PostgreSQL and the event log. Exercise the Linux clock
	// case explicitly so canonical replay does not depend on host clock precision.
	preparedAt := time.Date(2026, 9, 1, 5, 23, 1, 586569664, time.UTC)
	canonicalPreparedAt := preparedAt.Truncate(time.Microsecond)
	candidate := store.PrivacySubjectErasurePreparation{
		PrivacySubjectErasure: store.PrivacySubjectErasure{
			TenantID: tenantA, SubjectRef: privacy.SubjectRef(tenantA, subject),
			RequestedByRef: privacy.SubjectRef(tenantA, "privacy-admin"),
			Reason:         "verified erasure", ErasedAt: preparedAt,
		},
		OperationID:        "sha256:" + strings.Repeat("1", 64),
		RequestBinding:     strings.Repeat("2", 64),
		EventID:            "sha256:" + strings.Repeat("3", 64),
		RewriteOperationID: "rewrite-operation-1",
		TargetGeneration:   "rewrite-generation-1",
		EventActor:         &events.Actor{Subject: privacy.Placeholder(privacy.SubjectRef(tenantA, "privacy-admin")), Roles: []string{"privacy-admin"}},
	}
	prepared, err := st.PreparePrivacySubjectErasure(ctx, tenantA, subject, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.OperationID != candidate.OperationID || prepared.EventID != candidate.EventID ||
		prepared.RequestBinding != candidate.RequestBinding ||
		prepared.RewriteOperationID != candidate.RewriteOperationID ||
		prepared.TargetGeneration != candidate.TargetGeneration ||
		!prepared.ErasedAt.Equal(canonicalPreparedAt) {
		t.Fatalf("prepared identity/time = %+v, want %+v", prepared, candidate)
	}
	if prepared.ErasedAt.Location() != time.UTC || prepared.CreatedAt.Location() != time.UTC {
		t.Fatalf("prepared timestamp locations = erased %v created %v, want UTC for canonical replay bytes",
			prepared.ErasedAt.Location(), prepared.CreatedAt.Location())
	}
	if !containsPrivacyReadModelSelector(prepared.Selectors.ReadModels,
		"operation_approval_requests", request.ID) {
		t.Fatalf("pre-rewrite request selector was lost: %+v", prepared.Selectors.ReadModels)
	}
	decisionID := "77952000-0000-4000-8000-000000000002"
	if !containsPrivacyReadModelSelector(prepared.Selectors.ReadModels,
		"operation_approval_decisions", decisionID) {
		t.Fatalf("pre-rewrite decision selector was lost: %+v", prepared.Selectors.ReadModels)
	}
	if len(prepared.RecoveryFences) != 1 ||
		prepared.RecoveryFences[0] != (store.PrivacyRecoveryFenceDisposition{
			Kind:    store.PrivacyRecoveryFenceApplicationSecret,
			EventID: fence.EventID, Disposition: store.PrivacyRecoveryFenceDeleted,
		}) {
		t.Fatalf("recovery dispositions = %+v", prepared.RecoveryFences)
	}
	if prepared.Counts["application_secret_mutation_fences"] != 1 {
		t.Fatalf("prepared counts = %+v", prepared.Counts)
	}
	if prepared.Counts["read_model_snapshots"] != 1 {
		t.Fatalf("snapshot deletion evidence = %+v, want exact count 1", prepared.Counts)
	}
	var targetSnapshots, neighborSnapshots int
	if err := st.SystemPool().QueryRow(ctx, `SELECT count(*) FROM read_model_snapshots
		WHERE tenant_id = $1`, tenantA).Scan(&targetSnapshots); err != nil {
		t.Fatal(err)
	}
	if err := st.SystemPool().QueryRow(ctx, `SELECT count(*) FROM read_model_snapshots
		WHERE tenant_id = $1`, tenantB).Scan(&neighborSnapshots); err != nil {
		t.Fatal(err)
	}
	if targetSnapshots != 0 || neighborSnapshots != 1 {
		t.Fatalf("post-preparation snapshots target=%d neighbor=%d, want 0/1", targetSnapshots, neighborSnapshots)
	}
	if _, err := st.LatestSnapshotOffset(ctx); !errors.Is(err, store.ErrNoSnapshot) {
		t.Fatalf("partial snapshot set offset error = %v, want ErrNoSnapshot", err)
	}
	if err := st.WriteTenantSnapshot(ctx, tenantA, 0); !errors.Is(err, store.ErrPrivacySubjectErasurePreparationActive) {
		t.Fatalf("direct snapshot during active preparation = %v", err)
	}
	if _, err := projector.Snapshot(ctx); !errors.Is(err, store.ErrPrivacySubjectErasurePreparationActive) {
		t.Fatalf("periodic snapshot during active preparation = %v", err)
	}
	restarted, err := store.Open(ctx, testDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.Close)
	if err := restarted.WriteTenantSnapshot(ctx, tenantA, 0); !errors.Is(err, store.ErrPrivacySubjectErasurePreparationActive) {
		t.Fatalf("restarted writer crossed durable preparation marker = %v", err)
	}
	if !reflect.DeepEqual(prepared.Selectors.CodeSigningOperationIDs, []string{legacyCodeSigningOperationID}) ||
		prepared.Counts["code_signing_operations"] != 1 {
		t.Fatalf("legacy code-signing selector/count = %+v / %+v", prepared.Selectors, prepared.Counts)
	}
	legacyOperation, found, err := st.CodeSigningOperationByID(ctx, tenantA, legacyCodeSigningOperationID)
	if err != nil || !found ||
		legacyOperation.IdempotencyKey != store.LegacyCodeSigningStorageKey(legacyCodeSigningOperationID, legacyCodeSigningKey) ||
		strings.Contains(legacyOperation.IdempotencyKey, subject) {
		t.Fatalf("warm legacy code-signing privacy mapping = found %t op=%+v err=%v", found, legacyOperation, err)
	}
	if len(prepared.Selectors.ApprovalRequests) != 1 ||
		prepared.Selectors.ApprovalRequests[0].BindingRef == "" ||
		prepared.Selectors.ApprovalRequests[0].Resource != "" ||
		prepared.Selectors.ApprovalRequests[0].Action != "" ||
		len(prepared.Selectors.Approvals) != 1 ||
		prepared.Selectors.Approvals[0].BindingRef == "" {
		t.Fatalf("arbitrary approval keys were not replaced by one-way bindings: %+v / %+v",
			prepared.Selectors.ApprovalRequests, prepared.Selectors.Approvals)
	}
	completionPayload, err := json.Marshal(projections.PrivacySubjectErased{
		OperationID: prepared.OperationID, RequestBinding: prepared.RequestBinding,
		SubjectRef: prepared.SubjectRef, RequestedByRef: prepared.RequestedByRef,
		Reason: prepared.Reason, Selectors: prepared.Selectors, Counts: prepared.Counts,
		RecoveryFences:        prepared.RecoveryFences,
		SchedulerDispositions: prepared.SchedulerDispositions,
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(completionPayload, []byte(subject)) {
		t.Fatalf("durable preparation/final payload contains raw subject %q: %s", subject, completionPayload)
	}

	// Name, target, and remote key are AAD/external-authority coordinates. A
	// privacy rewrite cannot rename those fields while retaining their sealed
	// bytes, so preparation deletes the pre-finalization recovery copy and the
	// replacement history carries the explicit v3 authority disposition.
	if _, err := st.GetApplicationSecretMutationFence(ctx, tenantA, fence.Name); !store.IsNotFound(err) {
		t.Fatalf("raw AAD-bound application-secret fence remains after preparation: %v", err)
	}
	fencesAfterPreparation, err := st.ListApplicationSecretMutationFences(ctx, tenantA)
	if err != nil || len(fencesAfterPreparation) != 0 {
		t.Fatalf("restart scan retained AAD-bound recovery authority = %+v err=%v", fencesAfterPreparation, err)
	}
	authority, err := st.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if authority.Requester != placeholder || strings.Contains(authority.ResourceID, subject) ||
		strings.Contains(authority.ResourceName, subject) || authority.Reason != "" ||
		len(authority.EvidenceRefs) != 0 || authority.Status != store.ApprovalStatusConsumed {
		t.Fatalf("warm approval authority retained raw/drifted state: %+v", authority)
	}
	var retainedApprover string
	if err := st.SystemPool().QueryRow(ctx, `SELECT approver
		FROM operation_approval_decisions
		WHERE tenant_id = $1 AND event_id = $2::uuid`,
		tenantA, decisionID).Scan(&retainedApprover); err != nil {
		t.Fatal(err)
	}
	if retainedApprover != "bob" {
		t.Fatalf("parent-selected decision approver = %q, want unrelated identity bob", retainedApprover)
	}

	if err := st.WithApplicationSecretMutationPrivacyBarrier(ctx, tenantA, func(context.Context) error {
		return errors.New("must not run")
	}); !errors.Is(err, store.ErrPrivacySubjectErasurePreparationActive) {
		t.Fatalf("recovery barrier error = %v, want active-preparation error", err)
	}
	if err := st.WithApplicationSecretMutationPrivacyBarrier(ctx, tenantB, func(context.Context) error {
		return nil
	}); err != nil {
		t.Fatalf("tenant B was blocked by tenant A preparation: %v", err)
	}

	// An exact retry after a pre- or post-cutover crash must reuse the snapshot;
	// it must not reselect the already-pseudonymized PostgreSQL rows.
	retried, err := st.PreparePrivacySubjectErasure(ctx, tenantA, subject, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(retried, prepared) {
		t.Fatalf("preparation retry changed canonical snapshot:\nfirst=%+v\nretry=%+v", prepared, retried)
	}

	op := store.PrivacySubjectErasureOperation{
		PrivacySubjectErasure: prepared.PrivacySubjectErasure,
		OperationID:           prepared.OperationID, RequestBinding: prepared.RequestBinding,
		EventID: prepared.EventID, EventSequence: 99,
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyPrivacySubjectErasureOperationTx(ctx, tx, op)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetPrivacySubjectErasurePreparation(ctx, tenantA, candidate.OperationID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("projected event did not atomically retire preparation: %v", err)
	}
	legacyOperation, found, err = st.CodeSigningOperationByID(ctx, tenantA, legacyCodeSigningOperationID)
	if err != nil || !found || legacyOperation.IdempotencyKey != store.LegacyCodeSigningStorageKey(legacyCodeSigningOperationID, legacyCodeSigningKey) {
		t.Fatalf("completed privacy projection changed legacy mapping = found %t op=%+v err=%v", found, legacyOperation, err)
	}
	if err := st.AdvanceProjectionCheckpoint(ctx, op.EventSequence); err != nil {
		t.Fatal(err)
	}
	if written, err := projector.Snapshot(ctx); err != nil || written != 2 {
		t.Fatalf("capture privacy-safe snapshot set = (%d,%v), want (2,nil)", written, err)
	}
	var snapshotPayload []byte
	if err := st.SystemPool().QueryRow(ctx, `SELECT payload FROM read_model_snapshots
		WHERE tenant_id = $1`, tenantA).Scan(&snapshotPayload); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(snapshotPayload, []byte(subject)) ||
		bytes.Contains(snapshotPayload, []byte(legacyCodeSigningKey)) ||
		!bytes.Contains(snapshotPayload, []byte(store.LegacyCodeSigningStorageKey(legacyCodeSigningOperationID, legacyCodeSigningKey))) {
		t.Fatalf("snapshot did not converge on legacy privacy mapping: %s", snapshotPayload)
	}
}

func TestLegacyApprovedCodeSigningPrivacySemanticConvergesHotSnapshotRedeliveryAndCold(t *testing.T) {
	ctx := context.Background()
	st := newOperationApprovalStore(t)
	const (
		subject        = "legacy-key-owner@example.com"
		idempotencyKey = "release/legacy-key-owner@example.com/approved-command"
		requestID      = "77952300-0000-4000-8000-000000000001"
		decisionID     = "77952300-0000-4000-8000-000000000002"
		requestHash    = "abababababababababababababababababababababababababababababababab"
	)
	operationID := store.LegacyCodeSigningOperationID(tenantA, idempotencyKey)
	eventTime := operationApprovalBaseTime.Add(20*time.Minute + 789*time.Nanosecond)
	request := store.OperationApprovalRequest{
		ID: requestID, TenantID: tenantA, IntentDigest: "sha256:" + strings.Repeat("c", 64),
		ResourceKind: "code_signing",
		ResourceID:   store.CodeSigningApprovalResourceID(requestHash, idempotencyKey),
		ResourceName: "release-key", Action: "sign", Requester: "release-bot",
		RequiredApprovals: 1, CreatedAt: operationApprovalBaseTime,
		ExpiresAt: operationApprovalBaseTime.Add(time.Hour),
	}
	if err := applyOperationApprovalRequest(ctx, st, request); err != nil {
		t.Fatal(err)
	}
	if err := applyOperationApprovalDecision(ctx, st, store.OperationApprovalDecision{
		TenantID: tenantA, RequestID: request.ID, IntentDigest: request.IntentDigest,
		Approver: "security-approver", Decision: store.ApprovalDecisionApprove,
		EventID: decisionID, DecidedAt: operationApprovalBaseTime.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	approved, err := st.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	use, err := store.OperationApprovalUseFromRequest(approved)
	if err != nil {
		t.Fatal(err)
	}
	payload := projections.CodeSigningCommanded{
		OperationID: operationID, IdempotencyKey: idempotencyKey, Mode: "key",
		RequestHash: requestHash, SealedCommand: []byte("legacy-approved-sealed-command"),
		Approval: &use,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{
		ID:   projections.CodeSigningApprovalEventID(tenantA, operationID),
		Type: projections.EventCodeSigningCommanded, TenantID: tenantA,
		Time: eventTime, SchemaVersion: projections.CodeSigningApprovalEventSchemaVersion,
		Data: raw, Actor: &events.Actor{Subject: "release-controller", Roles: []string{"release"}},
	}
	historicalSemantic, err := projections.LegacyCodeSigningHistoricalSemanticDigest(event, payload)
	if err != nil {
		t.Fatal(err)
	}
	canonicalSemantic, err := projections.CodeSigningCommandSemanticDigest(event, payload)
	if err != nil {
		t.Fatal(err)
	}
	if historicalSemantic == canonicalSemantic {
		t.Fatal("historical and privacy-stable schema-v2 semantic formats unexpectedly match")
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyCodeSigningIntentTx(ctx, tx, store.CodeSigningOperation{
			TenantID: tenantA, OperationID: operationID, IdempotencyKey: idempotencyKey,
			Mode: payload.Mode, RequestHash: payload.RequestHash,
			SealedCommand: payload.SealedCommand, CreatedAt: event.Time, UpdatedAt: event.Time,
			Approval: &use, SourceEventID: event.ID, SemanticDigest: historicalSemantic,
		}, []byte(`{"operation_id":"`+operationID+`"}`))
	}); err != nil {
		t.Fatalf("seed historical warm schema-v2 operation: %v", err)
	}

	candidate := store.PrivacySubjectErasurePreparation{
		PrivacySubjectErasure: store.PrivacySubjectErasure{
			TenantID: tenantA, SubjectRef: privacy.SubjectRef(tenantA, subject),
			Reason: "erase legacy code-signing key", ErasedAt: operationApprovalBaseTime.Add(30 * time.Minute),
		},
		OperationID:    "sha256:" + strings.Repeat("d", 64),
		RequestBinding: strings.Repeat("e", 64), EventID: "sha256:" + strings.Repeat("f", 64),
		RewriteOperationID: "rewrite-approved-legacy-code-signing",
		TargetGeneration:   "generation-approved-legacy-code-signing",
	}
	prepared, err := st.PreparePrivacySubjectErasure(ctx, tenantA, subject, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(prepared.Selectors.CodeSigningOperationIDs, []string{operationID}) {
		t.Fatalf("approved legacy selector = %+v", prepared.Selectors.CodeSigningOperationIDs)
	}
	rewrittenData, changed, err := events.PseudonymizeEventDataForSubject(
		event.Data, tenantA, subject, event.Type, event.SchemaVersion,
	)
	if err != nil || !changed || bytes.Contains(rewrittenData, []byte(idempotencyKey)) {
		t.Fatalf("rewrite approved legacy event changed=%t err=%v payload=%s", changed, err, rewrittenData)
	}
	rewrittenEvent := event
	rewrittenEvent.Data = rewrittenData
	var rewrittenPayload projections.CodeSigningCommanded
	if err := json.Unmarshal(rewrittenData, &rewrittenPayload); err != nil {
		t.Fatal(err)
	}
	if rewrittenPayload.IdempotencyKey != store.LegacyCodeSigningStorageKey(operationID, idempotencyKey) {
		t.Fatalf("rewritten key = %q", rewrittenPayload.IdempotencyKey)
	}
	rewrittenSemantic, err := projections.CodeSigningCommandSemanticDigest(rewrittenEvent, rewrittenPayload)
	if err != nil || rewrittenSemantic != canonicalSemantic {
		t.Fatalf("privacy-stable semantic = %q err=%v, want %q", rewrittenSemantic, err, canonicalSemantic)
	}
	warm, found, err := st.CodeSigningOperationByID(ctx, tenantA, operationID)
	if err != nil || !found || warm.IdempotencyKey != rewrittenPayload.IdempotencyKey ||
		warm.SemanticDigest != canonicalSemantic ||
		!warm.CreatedAt.Equal(event.Time.UTC().Truncate(time.Microsecond)) ||
		!warm.UpdatedAt.Equal(event.Time.UTC().Truncate(time.Microsecond)) {
		t.Fatalf("privacy-canonical warm operation = found %t op=%+v err=%v", found, warm, err)
	}

	hostilePayload := rewrittenPayload
	hostilePayload.SealedCommand = []byte("different-sealed-command")
	hostile := rewrittenEvent
	hostile.Data, err = json.Marshal(hostilePayload)
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).Apply(ctx, hostile); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("non-privacy command drift = %v, want ErrIdempotencyConflict", err)
	}
	if err := projections.New(st).Apply(ctx, rewrittenEvent); err != nil {
		t.Fatalf("privacy event redelivery: %v", err)
	}

	op := store.PrivacySubjectErasureOperation{
		PrivacySubjectErasure: prepared.PrivacySubjectErasure,
		OperationID:           prepared.OperationID, RequestBinding: prepared.RequestBinding,
		EventID: prepared.EventID, EventSequence: 101,
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyPrivacySubjectErasureOperationTx(ctx, tx, op)
	}); err != nil {
		t.Fatal(err)
	}
	snapshotHead, err := st.ProjectionCheckpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WriteTenantSnapshot(ctx, tenantA, snapshotHead); err != nil {
		t.Fatal(err)
	}
	var snapshot []byte
	if err := st.SystemPool().QueryRow(ctx, `SELECT payload FROM read_model_snapshots
		WHERE tenant_id = $1`, tenantA).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(snapshot, []byte(idempotencyKey)) ||
		!bytes.Contains(snapshot, []byte(rewrittenPayload.IdempotencyKey)) ||
		!bytes.Contains(snapshot, []byte(canonicalSemantic)) {
		t.Fatalf("privacy snapshot lacks canonical legacy operation: %s", snapshot)
	}

	if _, err := st.SystemPool().Exec(ctx,
		`TRUNCATE code_signing_operations, outbox RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).Apply(ctx, rewrittenEvent); err != nil {
		t.Fatalf("cold project privacy-mapped schema-v2 command: %v", err)
	}
	cold, found, err := st.CodeSigningOperationByID(ctx, tenantA, operationID)
	if err != nil || !found || cold.IdempotencyKey != warm.IdempotencyKey ||
		cold.SemanticDigest != warm.SemanticDigest || cold.Mode != warm.Mode ||
		cold.RequestHash != warm.RequestHash || !bytes.Equal(cold.SealedCommand, warm.SealedCommand) ||
		!cold.CreatedAt.Equal(warm.CreatedAt) || !cold.UpdatedAt.Equal(warm.UpdatedAt) ||
		cold.SourceEventID != warm.SourceEventID || cold.ApprovalRequestID != warm.ApprovalRequestID ||
		cold.ApprovalIntentDigest != warm.ApprovalIntentDigest {
		t.Fatalf("cold schema-v2 operation diverged: warm=%+v cold=%+v found=%t err=%v", warm, cold, found, err)
	}
}

func TestPreparePrivacySubjectErasureRejectsRawSubjectInDurableActorRoles(t *testing.T) {
	ctx := context.Background()
	st := newOperationApprovalStore(t)
	const subject = "role-only-subject@example.com"
	candidate := store.PrivacySubjectErasurePreparation{
		PrivacySubjectErasure: store.PrivacySubjectErasure{
			TenantID: tenantA, SubjectRef: privacy.SubjectRef(tenantA, subject),
			Reason: "role validation", ErasedAt: time.Now().UTC().Round(0),
		},
		OperationID:        "sha256:" + strings.Repeat("7", 64),
		RequestBinding:     strings.Repeat("8", 64),
		EventID:            "sha256:" + strings.Repeat("9", 64),
		RewriteOperationID: "rewrite-operation-role-validation",
		TargetGeneration:   "rewrite-generation-role-validation",
		EventActor: &events.Actor{
			Subject: "privacy-admin",
			Roles:   []string{"privacy-admin", "delegate:" + subject, "auditor"},
		},
	}

	if _, err := st.PreparePrivacySubjectErasure(ctx, tenantA, subject, candidate); err == nil ||
		!strings.Contains(err.Error(), "actor contains raw subject") {
		t.Fatalf("raw subject in durable actor role error = %v", err)
	}
	if _, err := st.GetPrivacySubjectErasurePreparation(
		ctx, tenantA, candidate.OperationID,
	); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("invalid durable actor created a preparation: %v", err)
	}
}

func TestPreparePrivacySubjectErasurePreservesLegacyCodeSigningFenceWithMappedKey(t *testing.T) {
	ctx := context.Background()
	st := newOperationApprovalStore(t)
	const (
		subject        = "legacy-key-owner@example.com"
		idempotencyKey = "release/legacy-key-owner@example.com/command"
		requestID      = "77952500-0000-4000-8000-000000000001"
		decisionID     = "77952500-0000-4000-8000-000000000002"
		requestHash    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	)
	operationID := store.LegacyCodeSigningOperationID(tenantA, idempotencyKey)
	request := store.OperationApprovalRequest{
		ID: requestID, TenantID: tenantA, IntentDigest: "sha256:" + strings.Repeat("b", 64),
		ResourceKind: "code_signing",
		ResourceID:   store.CodeSigningApprovalResourceID(requestHash, idempotencyKey),
		ResourceName: "release-key", Action: "sign", Requester: "release-bot",
		RequiredApprovals: 1, CreatedAt: operationApprovalBaseTime,
		ExpiresAt: operationApprovalBaseTime.Add(time.Hour),
	}
	if err := applyOperationApprovalRequest(ctx, st, request); err != nil {
		t.Fatal(err)
	}
	if err := applyOperationApprovalDecision(ctx, st, store.OperationApprovalDecision{
		TenantID: tenantA, RequestID: request.ID, IntentDigest: request.IntentDigest,
		Approver: "security-approver", Decision: store.ApprovalDecisionApprove,
		EventID: decisionID, DecidedAt: operationApprovalBaseTime.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	approved, err := st.GetOperationApproval(ctx, tenantA, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	use, err := store.OperationApprovalUseFromRequest(approved)
	if err != nil {
		t.Fatal(err)
	}
	payload := projections.CodeSigningCommanded{
		OperationID: operationID, IdempotencyKey: idempotencyKey,
		Mode: "key", RequestHash: requestHash,
		SealedCommand: []byte("legacy-sealed-command"), Approval: &use,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{
		ID:   projections.CodeSigningApprovalEventID(tenantA, operationID),
		Type: projections.EventCodeSigningCommanded, TenantID: tenantA,
		Time:          operationApprovalBaseTime.Add(2*time.Minute + 719*time.Nanosecond),
		SchemaVersion: projections.CodeSigningApprovalEventSchemaVersion, Data: raw,
	}
	semantic, err := projections.LegacyCodeSigningHistoricalSemanticDigest(event, payload)
	if err != nil {
		t.Fatal(err)
	}
	fence, created, err := st.ClaimApprovedTargetFence(ctx, store.ApprovedTargetFence{
		TenantID: tenantA, TargetKind: store.ApprovedTargetCodeSigningCommand,
		CommandKey: operationID, RequestBinding: projections.CodeSigningRequestBinding(requestHash, idempotencyKey),
		EventID: event.ID, EventType: event.Type, SchemaVersion: event.SchemaVersion,
		EventTime: event.Time, Payload: event.Data, SemanticDigest: semantic,
	}, use)
	if err != nil || !created {
		t.Fatalf("claim legacy code-signing fence = created %t err=%v", created, err)
	}
	candidate := store.PrivacySubjectErasurePreparation{
		PrivacySubjectErasure: store.PrivacySubjectErasure{
			TenantID: tenantA, SubjectRef: privacy.SubjectRef(tenantA, subject),
			Reason: "erase legacy command key", ErasedAt: time.Now().UTC().Round(0),
		},
		OperationID:        "sha256:" + strings.Repeat("c", 64),
		RequestBinding:     strings.Repeat("d", 64),
		EventID:            "sha256:" + strings.Repeat("e", 64),
		RewriteOperationID: "rewrite-legacy-code-signing-key",
		TargetGeneration:   "generation-legacy-code-signing-key",
	}
	prepared, err := st.PreparePrivacySubjectErasure(ctx, tenantA, subject, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(prepared.RecoveryFences, []store.PrivacyRecoveryFenceDisposition{{
		Kind: store.PrivacyRecoveryFenceApprovedTarget, EventID: event.ID,
		Disposition: store.PrivacyRecoveryFencePseudonymized,
	}}) {
		t.Fatalf("legacy code-signing fence disposition = %+v", prepared.RecoveryFences)
	}
	rewritten, changed, err := events.PseudonymizeEventDataForSubject(
		event.Data, tenantA, subject, event.Type, event.SchemaVersion,
	)
	if err != nil || !changed || bytes.Contains(rewritten, []byte(idempotencyKey)) ||
		!bytes.Contains(rewritten, []byte(store.LegacyCodeSigningStorageKey(operationID, idempotencyKey))) {
		t.Fatalf("legacy event privacy mapping changed=%t err=%v payload=%s", changed, err, rewritten)
	}
	rewrittenEvent := event
	rewrittenEvent.Data = rewritten
	var rewrittenPayload projections.CodeSigningCommanded
	if err := json.Unmarshal(rewritten, &rewrittenPayload); err != nil {
		t.Fatal(err)
	}
	rewrittenHistorical, err := projections.LegacyCodeSigningHistoricalSemanticDigest(
		rewrittenEvent, rewrittenPayload,
	)
	if err != nil {
		t.Fatal(err)
	}
	rewrittenFence, err := st.GetApprovedTargetFence(
		ctx, tenantA, fence.TargetKind, fence.CommandKey,
	)
	if err != nil || rewrittenFence.SemanticDigest != rewrittenHistorical ||
		!bytes.Equal(rewrittenFence.Payload, rewritten) ||
		bytes.Contains(rewrittenFence.Payload, []byte(idempotencyKey)) {
		t.Fatalf("mapped legacy code-signing fence = %+v err=%v", rewrittenFence, err)
	}
}

func TestPrivacySubjectErasurePreparationIsTenantRLSScopedAndBlocksReadModelReplacement(t *testing.T) {
	ctx := context.Background()
	st := newOperationApprovalStore(t)
	const subject = "tenant-a-only@example.com"
	candidate := store.PrivacySubjectErasurePreparation{
		PrivacySubjectErasure: store.PrivacySubjectErasure{
			TenantID: tenantA, SubjectRef: privacy.SubjectRef(tenantA, subject),
			Reason: "tenant scoped", ErasedAt: time.Now().UTC().Round(0),
		},
		OperationID: "sha256:" + strings.Repeat("4", 64), RequestBinding: strings.Repeat("5", 64),
		EventID:            "sha256:" + strings.Repeat("6", 64),
		RewriteOperationID: "rewrite-operation-2", TargetGeneration: "rewrite-generation-2",
	}
	if _, err := st.PreparePrivacySubjectErasure(ctx, tenantA, subject, candidate); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetPrivacySubjectErasurePreparation(ctx, tenantB, candidate.OperationID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("tenant B read tenant A preparation = %v, want pgx.ErrNoRows", err)
	}
	if active, err := st.PrivacySubjectErasurePreparationActiveForGeneration(
		ctx, tenantA, candidate.TargetGeneration,
	); err != nil || !active {
		t.Fatalf("tenant A generation marker = %v, err %v, want true", active, err)
	}
	if active, err := st.PrivacySubjectErasurePreparationActiveForGeneration(
		ctx, tenantB, candidate.TargetGeneration,
	); err != nil || active {
		t.Fatalf("tenant B generation marker = %v, err %v, want false", active, err)
	}
	if err := st.TruncateReadModel(ctx); !errors.Is(err, store.ErrPrivacySubjectErasurePreparationActive) {
		t.Fatalf("read-model replacement error = %v, want active-preparation error", err)
	}
	if err := st.RebuildReadModelTx(ctx, func(pgx.Tx) error { return nil }); !errors.Is(err, store.ErrPrivacySubjectErasurePreparationActive) {
		t.Fatalf("atomic rebuild error = %v, want active-preparation error", err)
	}
}

func TestSnapshotWriterUsesHistoryThenProjectionOrderAndReusesOuterBarrier(t *testing.T) {
	ctx := context.Background()
	st := newOperationApprovalStore(t)
	snapshotHead, err := st.ProjectionCheckpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// The direct public writer enters its own privacy barrier, but must also be
	// safe when a higher-level public operation already granted the exact Store a
	// shared barrier context. This would deadlock a one-connection deployment if
	// the nested call tried to acquire another session grant.
	if err := st.WithPrivacyReadModelReplacementBarrier(ctx, func(barrierCtx context.Context) error {
		return st.WriteTenantSnapshot(barrierCtx, tenantA, snapshotHead)
	}); err != nil {
		t.Fatalf("re-entrant direct snapshot writer: %v", err)
	}
	if written, err := projections.New(st).Snapshot(ctx); err != nil || written != 2 {
		t.Fatalf("replace direct partial set = (%d,%v), want (2,nil)", written, err)
	}

	const subject = "snapshot-lock-order@example.test"
	candidate := store.PrivacySubjectErasurePreparation{
		PrivacySubjectErasure: store.PrivacySubjectErasure{
			TenantID: tenantA, SubjectRef: privacy.SubjectRef(tenantA, subject),
			Reason: "snapshot lock order", ErasedAt: time.Now().UTC().Round(0),
		},
		OperationID:        "sha256:" + strings.Repeat("a", 64),
		RequestBinding:     strings.Repeat("b", 64),
		EventID:            "sha256:" + strings.Repeat("c", 64),
		RewriteOperationID: "snapshot-lock-order-operation",
		TargetGeneration:   "snapshot-lock-order-generation",
	}
	t.Cleanup(func() {
		_, _ = st.SystemPool().Exec(context.Background(),
			`DELETE FROM privacy_subject_erasure_preparations
			 WHERE tenant_id = $1 AND operation_id = $2`, tenantA, candidate.OperationID)
	})

	operationEntered := make(chan struct{})
	prepareNow := make(chan struct{})
	operationDone := make(chan error, 1)
	go func() {
		operationDone <- store.NewHistoryRewriteCoordinator(st).WithRewriteOperation(
			ctx,
			func(operationCtx context.Context) error {
				close(operationEntered)
				<-prepareNow
				_, err := st.PreparePrivacySubjectErasure(
					operationCtx, tenantA, subject, candidate,
				)
				return err
			},
		)
	}()
	<-operationEntered

	writerStarted := make(chan struct{})
	writerDone := make(chan error, 1)
	go func() {
		close(writerStarted)
		writerDone <- st.WriteTenantSnapshot(ctx, tenantA, snapshotHead)
	}()
	<-writerStarted
	select {
	case err := <-writerDone:
		t.Fatalf("snapshot writer crossed live exclusive history operation: %v", err)
	case <-time.After(200 * time.Millisecond):
		// Expected: the writer has not reached the projection lock or database.
	}

	close(prepareNow)
	select {
	case err := <-operationDone:
		if err != nil {
			t.Fatalf("exclusive privacy preparation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exclusive privacy preparation did not complete")
	}
	prepared, err := st.GetPrivacySubjectErasurePreparation(ctx, tenantA, candidate.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Counts["read_model_snapshots"] != 1 {
		t.Fatalf("exclusive preparation snapshot evidence = %+v, want exact count 1", prepared.Counts)
	}
	var targetSnapshots int
	if err := st.SystemPool().QueryRow(ctx, `SELECT count(*) FROM read_model_snapshots
		WHERE tenant_id = $1`, tenantA).Scan(&targetSnapshots); err != nil {
		t.Fatal(err)
	}
	if targetSnapshots != 0 {
		t.Fatalf("exclusive preparation left %d physical target snapshots, want 0", targetSnapshots)
	}
	select {
	case err := <-writerDone:
		if !errors.Is(err, store.ErrPrivacySubjectErasurePreparationActive) {
			t.Fatalf("writer after prepared marker = %v, want active-preparation refusal", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("snapshot writer did not resume after history operation released")
	}
}

func containsPrivacyReadModelSelector(selectors []store.PrivacyReadModelSelector, table, id string) bool {
	for _, selector := range selectors {
		if selector.Table == table && selector.ID == id {
			return true
		}
	}
	return false
}
