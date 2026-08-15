// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func openCodeSigningPrivacyFullDRLog(t *testing.T, st *store.Store) *events.Log {
	t.Helper()
	log, err := events.Open(
		context.Background(),
		config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		events.WithHistoryRewriteCoordinator(store.NewHistoryRewriteCoordinator(st)),
		events.WithHistoryRewriteContinuityVerifier(codeSigningPrivacyFullDRContinuityVerifier),
	)
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log
}

func codeSigningPrivacyFullDRProofOptions(
	st *store.Store,
	observePrepared func(context.Context, events.TenantDataRewriteReport) error,
) []events.TenantDataRewriteOption {
	return []events.TenantDataRewriteOption{
		events.WithTenantDataPairValidator(func(_ string, _ int, before, after []byte) error {
			if bytes.Equal(before, after) {
				return errors.New("code-signing privacy rewrite pair is unchanged")
			}
			return nil
		}),
		events.WithTenantDataCutoverPreparation(func(
			ctx context.Context,
			report events.TenantDataRewriteReport,
			proceed func(context.Context) error,
		) error {
			return st.PrepareTenantDataCutover(ctx, report, func(fenceCtx context.Context) error {
				if err := proceed(fenceCtx); err != nil {
					return err
				}
				if observePrepared != nil {
					return observePrepared(fenceCtx, report)
				}
				return nil
			})
		}),
		events.WithTenantDataAuditContinuity(func(
			context.Context,
			events.TenantDataAuditView,
		) (events.TenantDataAuditCheckpoint, error) {
			return events.TenantDataAuditCheckpoint{
				IdentityDigest: crypto.SHA256Hex([]byte("code-signing-privacy-full-dr-genesis")),
			}, nil
		}),
		events.WithTenantDataContinuity(func(
			_ context.Context,
			report events.TenantDataRewriteReport,
		) (events.Event, error) {
			data, err := json.Marshal(report)
			if err != nil {
				return events.Event{}, err
			}
			return events.Event{
				ID:            "code-signing-privacy-full-dr-receipt-" + report.OperationID,
				Type:          "tenant.data.rewrite.receipt",
				TenantID:      report.TenantID,
				Time:          report.CompletedAt,
				SchemaVersion: events.DefaultSchemaVersion,
				Data:          data,
			}, nil
		}),
	}
}

func codeSigningPrivacyFullDRContinuityVerifier(
	_ context.Context,
	evidence events.TenantDataContinuityEvidence,
) error {
	if evidence.OperationID == "" || evidence.TenantID == "" ||
		evidence.ReceiptSequence == 0 || evidence.Receipt.ID == "" ||
		evidence.Receipt.Type != "tenant.data.rewrite.receipt" ||
		len(evidence.Receipt.Data) == 0 {
		return errors.New("incomplete code-signing privacy rewrite continuity evidence")
	}
	if evidence.Report.OperationID != evidence.OperationID ||
		evidence.Report.TenantID != evidence.TenantID ||
		evidence.Report.SourceStream != evidence.SourceStream ||
		evidence.Report.TargetStream != evidence.TargetStream ||
		evidence.Report.ReceiptSequence != evidence.ReceiptSequence ||
		evidence.Report.TargetContentDigest == "" ||
		evidence.Report.SourceConfigDigest == "" ||
		evidence.Report.TargetConfigDigest == "" ||
		evidence.Report.ArchiveExposure != events.TenantDataArchiveExposureExternalCopiesMayRetainSourceBytes {
		return errors.New("code-signing privacy rewrite report is not bound to continuity evidence")
	}
	reportData, err := json.Marshal(evidence.Report)
	if err != nil {
		return err
	}
	if !bytes.Equal(reportData, evidence.Receipt.Data) {
		return errors.New("code-signing privacy receipt does not bind the exact rewrite report")
	}
	return nil
}

func appendCodeSigningPrivacyFullDRApproval(
	t *testing.T,
	ctx context.Context,
	st *store.Store,
	log *events.Log,
	projector *projections.Projector,
	tenantID, subject, requestID, decisionID, intentDigest, resourceID string,
	createdAt time.Time,
) store.OperationApprovalUse {
	t.Helper()
	requestData, err := json.Marshal(projections.ApprovalRequested{
		ID: requestID, IntentDigest: intentDigest,
		ResourceKind: "code_signing", ResourceID: resourceID, ResourceName: "release-key",
		Action: "sign", Requester: subject, Reason: "release requested by " + subject,
		EvidenceRefs: []string{"ticket:" + subject}, RequiredApprovals: 1,
		CreatedAt: createdAt, ExpiresAt: createdAt.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{
		ID: requestID, Type: projections.EventApprovalRequested, TenantID: tenantID,
		Time: createdAt, Data: requestData,
		Actor: &events.Actor{Subject: subject, Roles: []string{"release-requester"}},
	}); err != nil {
		t.Fatalf("append approval request: %v", err)
	}
	decisionData, err := json.Marshal(projections.ApprovalDecisionRecorded{
		RequestID: requestID, IntentDigest: intentDigest,
		Approver: "security-approver", Decision: store.ApprovalDecisionApprove,
		DecidedAt:            createdAt.Add(time.Minute),
		ExpectedResourceKind: "code_signing", ExpectedResourceID: resourceID,
		ExpectedAction: "sign",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{
		ID: decisionID, Type: projections.EventApprovalDecisionRecorded, TenantID: tenantID,
		Time: createdAt.Add(time.Minute), Data: decisionData,
		Actor: &events.Actor{Subject: "security-approver", Roles: []string{"approver"}},
	}); err != nil {
		t.Fatalf("append approval decision: %v", err)
	}
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("project approval authority: %v", err)
	}
	approved, err := st.GetOperationApproval(ctx, tenantID, requestID)
	if err != nil {
		t.Fatalf("read approved request: %v", err)
	}
	use, err := store.OperationApprovalUseFromRequest(approved)
	if err != nil {
		t.Fatalf("create approval use: %v", err)
	}
	return use
}

// TestLegacyApprovedCodeSigningPrivacyFullBackupRestoreConverges proves both
// artifacts in a full backup. One legacy command exercises the raw-key privacy
// mapping; a second retains the independent pre-projection fence so restore also
// runs the real startup recovery path over reconstructed approval authority.
func TestLegacyApprovedCodeSigningPrivacyFullBackupRestoreConverges(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	ctx := context.Background()
	const (
		tenantID           = servedTestTenant
		neighborTenant     = "22222222-2222-2222-2222-222222222222"
		subject            = "legacy-release-owner@example.com"
		subjectKey         = "release/legacy-release-owner@example.com/full-dr-command"
		fencedKey          = "fenced/legacy-release-owner@example.com/full-dr-command"
		subjectRequestID   = "77953100-0000-4000-8000-000000000001"
		subjectDecisionID  = "77953100-0000-4000-8000-000000000002"
		fencedRequestID    = "77953100-0000-4000-8000-000000000011"
		fencedDecisionID   = "77953100-0000-4000-8000-000000000012"
		subjectRequestHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		fencedRequestHash  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	base := time.Date(2026, 8, 11, 14, 0, 0, 0, time.UTC)
	sourceLog := openCodeSigningPrivacyFullDRLog(t, h.store)
	projector := projections.New(h.store)
	if _, err := sourceLog.Append(ctx, events.Event{
		ID:   "77953100-0000-4000-8000-000000000000",
		Type: projections.EventTenantRegistered, TenantID: tenantID,
		Time: base, Data: []byte(`{"name":"code-signing-privacy-full-dr"}`),
	}); err != nil {
		t.Fatalf("append tenant: %v", err)
	}
	if _, err := sourceLog.Append(ctx, events.Event{
		ID:   "77953100-0000-4000-8000-000000000099",
		Type: projections.EventTenantRegistered, TenantID: neighborTenant,
		Time: base, Data: []byte(`{"name":"code-signing-privacy-full-dr-neighbor"}`),
	}); err != nil {
		t.Fatalf("append neighbor tenant: %v", err)
	}
	if err := projector.ProjectCatchUp(ctx, sourceLog); err != nil {
		t.Fatalf("project tenant: %v", err)
	}

	subjectOperationID := projections.LegacyCodeSigningOperationID(tenantID, subjectKey)
	subjectResourceID := store.CodeSigningApprovalResourceID(subjectRequestHash, subjectKey)
	subjectUse := appendCodeSigningPrivacyFullDRApproval(
		t, ctx, h.store, sourceLog, projector, tenantID, subject,
		subjectRequestID, subjectDecisionID, "sha256:"+strings.Repeat("c", 64),
		subjectResourceID, base.Add(10*time.Minute),
	)
	subjectPayload := projections.CodeSigningCommanded{
		OperationID: subjectOperationID, IdempotencyKey: subjectKey,
		Mode: "key", RequestHash: subjectRequestHash,
		SealedCommand: []byte("tenant-sealed-subject-key-command"), Approval: &subjectUse,
	}
	subjectData, err := json.Marshal(subjectPayload)
	if err != nil {
		t.Fatal(err)
	}
	subjectEvent := events.Event{
		ID:   projections.CodeSigningApprovalEventID(tenantID, subjectOperationID),
		Type: projections.EventCodeSigningCommanded, TenantID: tenantID,
		Time:          base.Add(12*time.Minute + 317*time.Nanosecond),
		SchemaVersion: projections.CodeSigningApprovalEventSchemaVersion,
		Data:          subjectData,
		Actor:         &events.Actor{Subject: subject, Roles: []string{"release"}},
	}
	subjectHistorical, err := projections.LegacyCodeSigningHistoricalSemanticDigest(subjectEvent, subjectPayload)
	if err != nil {
		t.Fatal(err)
	}
	subjectCanonical, err := projections.CodeSigningCommandSemanticDigest(subjectEvent, subjectPayload)
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := h.store.ClaimApprovedTargetFence(ctx, store.ApprovedTargetFence{
		TenantID: tenantID, TargetKind: store.ApprovedTargetCodeSigningCommand,
		CommandKey:     subjectOperationID,
		RequestBinding: projections.CodeSigningRequestBinding(subjectRequestHash, subjectKey),
		EventID:        subjectEvent.ID, EventType: subjectEvent.Type,
		SchemaVersion: subjectEvent.SchemaVersion, EventTime: subjectEvent.Time,
		Actor: subjectEvent.Actor, Payload: subjectEvent.Data, SemanticDigest: subjectHistorical,
	}, subjectUse); err != nil || !created {
		t.Fatalf("claim subject-key legacy fence = created %t err=%v", created, err)
	}
	if _, err := sourceLog.Append(ctx, subjectEvent); err != nil {
		t.Fatalf("append subject-key command: %v", err)
	}
	if err := projector.ProjectCatchUp(ctx, sourceLog); err != nil {
		t.Fatalf("project subject-key command: %v", err)
	}

	fencedOperationID := projections.LegacyCodeSigningOperationID(tenantID, fencedKey)
	fencedResourceID := store.CodeSigningApprovalResourceID(fencedRequestHash, fencedKey)
	fencedUse := appendCodeSigningPrivacyFullDRApproval(
		t, ctx, h.store, sourceLog, projector, tenantID, subject,
		fencedRequestID, fencedDecisionID, "sha256:"+strings.Repeat("d", 64),
		fencedResourceID, base.Add(20*time.Minute),
	)
	fencedPayload := projections.CodeSigningCommanded{
		OperationID: fencedOperationID, IdempotencyKey: fencedKey,
		Mode: "key", RequestHash: fencedRequestHash,
		SealedCommand: []byte("tenant-sealed-fenced-command"), Approval: &fencedUse,
	}
	fencedData, err := json.Marshal(fencedPayload)
	if err != nil {
		t.Fatal(err)
	}
	fencedEvent := events.Event{
		ID:   projections.CodeSigningApprovalEventID(tenantID, fencedOperationID),
		Type: projections.EventCodeSigningCommanded, TenantID: tenantID,
		Time:          base.Add(22*time.Minute + 613*time.Nanosecond),
		SchemaVersion: projections.CodeSigningApprovalEventSchemaVersion,
		Data:          fencedData,
		Actor:         &events.Actor{Subject: subject, Roles: []string{"release"}},
	}
	fencedHistorical, err := projections.LegacyCodeSigningHistoricalSemanticDigest(fencedEvent, fencedPayload)
	if err != nil {
		t.Fatal(err)
	}
	fencedCanonical, err := projections.CodeSigningCommandSemanticDigest(fencedEvent, fencedPayload)
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := h.store.ClaimApprovedTargetFence(ctx, store.ApprovedTargetFence{
		TenantID: tenantID, TargetKind: store.ApprovedTargetCodeSigningCommand,
		CommandKey:     fencedOperationID,
		RequestBinding: projections.CodeSigningRequestBinding(fencedRequestHash, fencedKey),
		EventID:        fencedEvent.ID, EventType: fencedEvent.Type,
		SchemaVersion: fencedEvent.SchemaVersion, EventTime: fencedEvent.Time,
		Actor: fencedEvent.Actor, Payload: fencedEvent.Data, SemanticDigest: fencedHistorical,
	}, fencedUse); err != nil || !created {
		t.Fatalf("claim retained legacy fence = created %t err=%v", created, err)
	}
	if _, err := sourceLog.Append(ctx, fencedEvent); err != nil {
		t.Fatalf("append retained fenced command: %v", err)
	}
	if _, found, err := h.store.CodeSigningOperationByID(ctx, tenantID, fencedOperationID); err != nil || found {
		t.Fatalf("pre-backup crash-shaped fenced operation = found %t err=%v", found, err)
	}
	if written, err := projector.Snapshot(ctx); err != nil || written != 2 {
		t.Fatalf("capture raw pre-erasure snapshot set = (%d,%v), want (2,nil)", written, err)
	}
	var rawPreErasureSnapshot []byte
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT payload FROM read_model_snapshots
		WHERE tenant_id = $1`, tenantID).Scan(&rawPreErasureSnapshot); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rawPreErasureSnapshot, []byte(subject)) {
		t.Fatalf("pre-erasure snapshot does not contain the raw privacy fixture")
	}

	const privacyIdempotencyKey = "code-signing-privacy-full-dr-erasure"
	privacyRequestBinding := strings.Repeat("e", 64)
	privacyIdentity := orchestrator.PrivacySubjectErasureIdentityFor(
		tenantID, privacyIdempotencyKey, privacyRequestBinding,
	)
	sawActivePreparation := false
	privacyOrchestrator := orchestrator.NewOrchestrator(
		sourceLog, h.store, orchestrator.NewOutbox(h.store),
		orchestrator.WithTenantDataRewriteOptions(
			codeSigningPrivacyFullDRProofOptions(h.store, func(
				observeCtx context.Context,
				report events.TenantDataRewriteReport,
			) error {
				keys, err := h.store.ListPrivacySubjectErasurePreparationKeysSystem(observeCtx)
				if err != nil {
					return err
				}
				if len(keys) != 1 || keys[0].TenantID != tenantID ||
					keys[0].OperationID != privacyIdentity.OperationID {
					return errors.New("coordinated privacy cutover lacks its exact active SQL preparation")
				}
				prepared, err := h.store.GetPrivacySubjectErasurePreparation(
					observeCtx, tenantID, privacyIdentity.OperationID,
				)
				if err != nil {
					return err
				}
				if prepared.TargetGeneration != report.TargetGeneration {
					return errors.New("coordinated privacy preparation names another event generation")
				}
				if prepared.Counts["read_model_snapshots"] != 1 {
					return errors.New("coordinated privacy preparation did not record one deleted target snapshot")
				}
				var targetSnapshots, neighborSnapshots int
				if err := h.store.SystemPool().QueryRow(observeCtx,
					`SELECT count(*) FROM read_model_snapshots WHERE tenant_id = $1`,
					tenantID,
				).Scan(&targetSnapshots); err != nil {
					return err
				}
				if err := h.store.SystemPool().QueryRow(observeCtx,
					`SELECT count(*) FROM read_model_snapshots WHERE tenant_id = $1`,
					neighborTenant,
				).Scan(&neighborSnapshots); err != nil {
					return err
				}
				if targetSnapshots != 0 || neighborSnapshots != 1 {
					return errors.New("coordinated privacy preparation did not physically remove only the target snapshot")
				}
				if _, err := h.store.LatestSnapshotOffset(observeCtx); !errors.Is(err, store.ErrNoSnapshot) {
					return errors.New("surviving neighbor snapshot still supplied an unsafe restore offset")
				}
				activeGeneration, err := sourceLog.ActiveGeneration(observeCtx)
				if err != nil {
					return err
				}
				if activeGeneration != report.TargetGeneration {
					return errors.New("coordinated privacy preparation was observed before target activation")
				}
				if _, found, err := sourceLog.EventByID(observeCtx, privacyIdentity.EventID); err != nil {
					return err
				} else if found {
					return errors.New("coordinated privacy completion event existed during the preparation pause")
				}
				if _, err := h.store.GetPrivacySubjectErasureOperationByEventID(
					observeCtx, tenantID, privacyIdentity.EventID,
				); !errors.Is(err, pgx.ErrNoRows) {
					return errors.New("coordinated privacy operation existed during the preparation pause")
				}
				sawActivePreparation = true
				return nil
			})...,
		),
	)
	erased, err := privacyOrchestrator.ErasePrivacySubjectBound(
		ctx, tenantID, subject, "paired full-backup privacy rewrite",
		privacyIdempotencyKey, privacyRequestBinding,
	)
	if err != nil {
		t.Fatalf("run coordinated code-signing privacy erasure: %v", err)
	}
	if !sawActivePreparation {
		t.Fatal("coordinated privacy rewrite never exposed its active SQL preparation before completion")
	}
	wantSubjectRef := privacy.SubjectRef(tenantID, subject)
	if erased.SubjectRef != wantSubjectRef || erased.Counts["approved_target_event_fences"] != 1 ||
		erased.Counts["read_model_snapshots"] != 1 {
		t.Fatalf("coordinated privacy result=%+v, want one rewritten fence and one deleted snapshot", erased)
	}
	preparations, err := h.store.ListPrivacySubjectErasurePreparationKeysSystem(ctx)
	if err != nil || len(preparations) != 0 {
		t.Fatalf("completed privacy rewrite left active preparation=%+v err=%v", preparations, err)
	}
	completionEvent, found, err := sourceLog.EventByID(ctx, privacyIdentity.EventID)
	if err != nil || !found {
		t.Fatalf("privacy completion event = found %t err=%v", found, err)
	}
	var completion projections.PrivacySubjectErased
	if err := json.Unmarshal(completionEvent.Data, &completion); err != nil {
		t.Fatal(err)
	}
	if err := projections.ValidatePrivacySubjectErasedPayload(completionEvent, completion); err != nil {
		t.Fatalf("validate privacy completion event: %v", err)
	}
	if completionEvent.SchemaVersion != projections.PrivacySubjectErasedEventSchemaVersion ||
		completion.OperationID != privacyIdentity.OperationID || completion.SubjectRef != wantSubjectRef ||
		len(completion.RecoveryFences) != 1 ||
		completion.RecoveryFences[0] != (store.PrivacyRecoveryFenceDisposition{
			Kind: store.PrivacyRecoveryFenceApprovedTarget, EventID: fencedEvent.ID,
			Disposition: store.PrivacyRecoveryFencePseudonymized,
		}) {
		t.Fatalf("privacy completion did not bind rewritten fence: %+v", completion)
	}
	durableErasure, err := h.store.GetPrivacySubjectErasureOperationByEventID(
		ctx, tenantID, privacyIdentity.EventID,
	)
	if err != nil || durableErasure.OperationID != privacyIdentity.OperationID ||
		durableErasure.RequestBinding != privacyRequestBinding ||
		durableErasure.EventID != completionEvent.ID ||
		durableErasure.EventSequence != completionEvent.Sequence ||
		durableErasure.SubjectRef != wantSubjectRef {
		t.Fatalf("durable privacy completion=%+v err=%v", durableErasure, err)
	}
	for _, requestID := range []string{subjectRequestID, fencedRequestID} {
		approval, err := h.store.GetOperationApproval(ctx, tenantID, requestID)
		if err != nil || approval.Requester != privacy.Placeholder(wantSubjectRef) ||
			approval.Reason != "" || len(approval.EvidenceRefs) != 0 {
			t.Fatalf("coordinated privacy SQL approval=%+v err=%v", approval, err)
		}
	}
	warmSubjectOperation, found, err := h.store.CodeSigningOperationByID(
		ctx, tenantID, subjectOperationID,
	)
	if err != nil || !found ||
		warmSubjectOperation.IdempotencyKey != store.LegacyCodeSigningStorageKey(subjectOperationID, subjectKey) ||
		warmSubjectOperation.SemanticDigest != subjectCanonical {
		t.Fatalf("coordinated privacy SQL code-signing operation = found %t op=%+v err=%v",
			found, warmSubjectOperation, err)
	}

	canonicalSubjectEvent, found, err := sourceLog.EventByID(ctx, subjectEvent.ID)
	if err != nil || !found {
		t.Fatalf("read rewritten subject-key event = found %t err=%v", found, err)
	}
	var canonicalSubjectPayload projections.CodeSigningCommanded
	if err := json.Unmarshal(canonicalSubjectEvent.Data, &canonicalSubjectPayload); err != nil {
		t.Fatal(err)
	}
	wantSubjectKey := store.LegacyCodeSigningStorageKey(subjectOperationID, subjectKey)
	wantFencedKey := store.LegacyCodeSigningStorageKey(fencedOperationID, fencedKey)
	if canonicalSubjectPayload.IdempotencyKey != wantSubjectKey {
		t.Fatalf("rewritten subject-key identity=%q, want %q", canonicalSubjectPayload.IdempotencyKey, wantSubjectKey)
	}
	if got, err := projections.CodeSigningCommandSemanticDigest(canonicalSubjectEvent, canonicalSubjectPayload); err != nil || got != subjectCanonical {
		t.Fatalf("rewritten subject-key semantic=%q err=%v, want %q", got, err, subjectCanonical)
	}
	canonicalFencedEvent, found, err := sourceLog.EventByID(ctx, fencedEvent.ID)
	if err != nil || !found {
		t.Fatalf("read rewritten fenced event = found %t err=%v", found, err)
	}
	var canonicalFencedPayload projections.CodeSigningCommanded
	if err := json.Unmarshal(canonicalFencedEvent.Data, &canonicalFencedPayload); err != nil {
		t.Fatal(err)
	}
	if got, err := projections.CodeSigningCommandSemanticDigest(canonicalFencedEvent, canonicalFencedPayload); err != nil || got != fencedCanonical {
		t.Fatalf("rewritten fenced semantic=%q err=%v, want %q", got, err, fencedCanonical)
	}
	rewrittenFencedHistorical, err := projections.LegacyCodeSigningHistoricalSemanticDigest(
		canonicalFencedEvent, canonicalFencedPayload,
	)
	if err != nil || rewrittenFencedHistorical == fencedHistorical {
		t.Fatalf("rewritten fenced historical semantic=%q err=%v, want a new mapped-payload digest", rewrittenFencedHistorical, err)
	}
	sourceFence, err := h.store.GetApprovedTargetFence(
		ctx, tenantID, store.ApprovedTargetCodeSigningCommand, fencedOperationID,
	)
	if err != nil || sourceFence.SemanticDigest != rewrittenFencedHistorical ||
		bytes.Contains(sourceFence.Payload, []byte(subject)) ||
		sourceFence.Actor == nil || sourceFence.Actor.Subject != privacy.Placeholder(wantSubjectRef) {
		t.Fatalf("coordinated privacy SQL recovery fence=%+v err=%v", sourceFence, err)
	}

	// Inspect the complete authoritative rows, not only their typed projections.
	// BYTEA fields are rendered with PostgreSQL's escape encoding so printable
	// legacy identity bytes remain searchable instead of disappearing into hex.
	var authoritativeRows string
	var authoritativeApprovalCount int
	if err := h.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT jsonb_build_object(
				'approvals', COALESCE((
					SELECT jsonb_agg(to_jsonb(r) ORDER BY r.id)
					FROM operation_approval_requests r
					WHERE r.tenant_id = $1 AND r.id IN ($2::uuid, $3::uuid)
				), '[]'::jsonb),
				'operation', COALESCE((
					SELECT to_jsonb(o) || jsonb_build_object(
						'sealed_command_clear', encode(o.sealed_command, 'escape'),
						'response_clear', encode(o.response, 'escape'))
					FROM code_signing_operations o
					WHERE o.tenant_id = $1 AND o.operation_id = $4
				), '{}'::jsonb),
				'fence', COALESCE((
					SELECT to_jsonb(f) || jsonb_build_object(
						'event_payload_clear', encode(f.event_payload, 'escape'))
					FROM approved_target_event_fences f
					WHERE f.tenant_id = $1 AND f.command_key = $5
				), '{}'::jsonb)
			)::text,
			(SELECT count(*) FROM operation_approval_requests r
			 WHERE r.tenant_id = $1 AND r.id IN ($2::uuid, $3::uuid))
		`, tenantID, subjectRequestID, fencedRequestID, subjectOperationID, fencedOperationID).
			Scan(&authoritativeRows, &authoritativeApprovalCount)
	}); err != nil {
		t.Fatalf("inspect authoritative privacy-rewritten SQL rows: %v", err)
	}
	authoritativeBytes := []byte(authoritativeRows)
	if authoritativeApprovalCount != 2 ||
		!bytes.Contains(authoritativeBytes, []byte(subjectRequestID)) ||
		!bytes.Contains(authoritativeBytes, []byte(fencedRequestID)) ||
		!bytes.Contains(authoritativeBytes, []byte(privacy.Placeholder(wantSubjectRef))) ||
		!bytes.Contains(authoritativeBytes, []byte(wantSubjectKey)) ||
		!bytes.Contains(authoritativeBytes, []byte(wantFencedKey)) ||
		!bytes.Contains(authoritativeBytes, []byte(fencedEvent.ID)) {
		t.Fatalf("authoritative privacy-rewritten SQL rows are incomplete: approvals=%d rows=%s",
			authoritativeApprovalCount, authoritativeRows)
	}
	for _, raw := range []string{subject, subjectKey, fencedKey} {
		if bytes.Contains(authoritativeBytes, []byte(raw)) {
			t.Fatalf("authoritative approval/fence/operation rows retained raw privacy bytes %q", raw)
		}
	}

	// This is the full-backup convergence gate: the SQL preparation has retired,
	// and the final v3 event and durable operation bind the same completed result.
	preparations, err = h.store.ListPrivacySubjectErasurePreparationKeysSystem(ctx)
	if err != nil || len(preparations) != 0 ||
		completionEvent.SchemaVersion != projections.PrivacySubjectErasedEventSchemaVersion ||
		durableErasure.EventID != completionEvent.ID ||
		durableErasure.EventSequence != completionEvent.Sequence {
		t.Fatalf("privacy state had not converged before export: preparations=%+v event=%+v operation=%+v err=%v",
			preparations, completionEvent, durableErasure, err)
	}

	cut, err := sourceLog.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var eventArtifact bytes.Buffer
	if _, err := backup.WriteLogThrough(ctx, sourceLog, &eventArtifact, cut); err != nil {
		t.Fatalf("write full-backup event artifact: %v", err)
	}
	var postgresArtifact bytes.Buffer
	postgresSummary, err := backup.WritePostgresStateAtCut(ctx, h.store, &postgresArtifact, cut)
	if err != nil {
		t.Fatalf("write full-backup PostgreSQL artifact: %v", err)
	}
	if postgresSummary.EventCutSequence != cut || postgresSummary.Tables["approved_target_event_fences"] != 1 {
		t.Fatalf("PostgreSQL artifact summary=%+v, want one fence at cut %d", postgresSummary, cut)
	}
	for name, artifact := range map[string][]byte{
		"event-log": eventArtifact.Bytes(), "postgres-state": postgresArtifact.Bytes(),
	} {
		for _, raw := range []string{subject, subjectKey, fencedKey} {
			if bytes.Contains(artifact, []byte(raw)) {
				t.Fatalf("%s artifact retained raw legacy code-signing privacy identity %q", name, raw)
			}
		}
	}
	if !bytes.Contains(eventArtifact.Bytes(), []byte(wantSubjectKey)) ||
		!bytes.Contains(postgresArtifact.Bytes(), []byte(fencedEvent.ID)) {
		t.Fatal("paired artifacts omitted the mapped operation or durable recovery fence")
	}
	if err := verifyFullRestoreArtifactPair(
		bytes.NewReader(eventArtifact.Bytes()),
		bytes.NewReader(postgresArtifact.Bytes()),
		backup.PostgresStateIdentity{},
	); err != nil {
		t.Fatalf("full-restore pair preflight rejected matching privacy-safe artifacts: %v", err)
	}

	resetServerTestStore(t, h.store)
	restoredLog := openCodeSigningPrivacyFullDRLog(t, h.store)
	if _, err := backup.RestoreLog(ctx, restoredLog, bytes.NewReader(eventArtifact.Bytes())); err != nil {
		t.Fatalf("restore event artifact: %v", err)
	}
	if err := projections.New(h.store).Rebuild(ctx, restoredLog); err != nil {
		t.Fatalf("preliminary rebuild from restored history: %v", err)
	}
	if _, err := backup.RestorePostgresState(ctx, h.store, bytes.NewReader(postgresArtifact.Bytes())); err != nil {
		t.Fatalf("restore PostgreSQL artifact: %v", err)
	}
	restoredFence, err := h.store.GetApprovedTargetFence(
		ctx, tenantID, store.ApprovedTargetCodeSigningCommand, fencedOperationID,
	)
	if err != nil || restoredFence.SemanticDigest != rewrittenFencedHistorical ||
		bytes.Contains(restoredFence.Payload, []byte(subject)) ||
		restoredFence.Actor == nil || strings.Contains(restoredFence.Actor.Subject, subject) {
		t.Fatalf("restored privacy-safe legacy fence=%+v err=%v", restoredFence, err)
	}

	// Match runFullRestore exactly: pair preflight above, restored history with a
	// preliminary rebuild, PostgreSQL import, then the final read-model rebuild.
	// The latter consumes the crash-shaped fence only after the imported state is
	// in place; startup assembly must then accept that recovered state unchanged.
	if err := projections.New(h.store).Rebuild(ctx, restoredLog); err != nil {
		t.Fatalf("final read-model rebuild after postgres state restore: %v", err)
	}
	if _, err := h.store.GetApprovedTargetFence(
		ctx, tenantID, store.ApprovedTargetCodeSigningCommand, fencedOperationID,
	); !store.IsNotFound(err) {
		t.Fatalf("final full-restore rebuild left restored legacy fence: %v", err)
	}

	recoveredServer, err := Build(ctx, Deps{
		Store: h.store, Log: restoredLog, Signer: h.signer,
		SignAuthorizer: h.authz, CACertFile: h.caFile,
	})
	if err != nil {
		t.Fatalf("startup recovery over restored full backup: %v", err)
	}
	t.Cleanup(func() { _ = recoveredServer.Shutdown(context.Background()) })
	if _, err := h.store.GetApprovedTargetFence(
		ctx, tenantID, store.ApprovedTargetCodeSigningCommand, fencedOperationID,
	); !store.IsNotFound(err) {
		t.Fatalf("startup recovery reintroduced restored legacy fence: %v", err)
	}

	for _, want := range []struct {
		operationID string
		storedKey   string
		semantic    string
		eventID     string
		requestID   string
	}{
		{subjectOperationID, wantSubjectKey, subjectCanonical, subjectEvent.ID, subjectRequestID},
		{fencedOperationID, wantFencedKey, fencedCanonical, fencedEvent.ID, fencedRequestID},
	} {
		op, found, err := h.store.CodeSigningOperationByID(ctx, tenantID, want.operationID)
		if err != nil || !found || op.IdempotencyKey != want.storedKey ||
			op.SemanticDigest != want.semantic || op.SourceEventID != want.eventID ||
			op.ApprovalRequestID != want.requestID {
			t.Fatalf("restored legacy operation = found %t op=%+v err=%v want=%+v", found, op, err, want)
		}
		approval, err := h.store.GetOperationApproval(ctx, tenantID, want.requestID)
		if err != nil || approval.Status != store.ApprovalStatusConsumed ||
			approval.ConsumedEventID != want.eventID {
			t.Fatalf("restored approval authority=%+v err=%v", approval, err)
		}
		approvalJSON, err := json.Marshal(approval)
		if err != nil || bytes.Contains(approvalJSON, []byte(subject)) {
			t.Fatalf("restored approval retained raw subject: %s err=%v", approvalJSON, err)
		}
	}
	if written, err := projections.New(h.store).Snapshot(ctx); err != nil || written != 2 {
		t.Fatalf("snapshot restored read model = (%d,%v), want complete two-tenant set", written, err)
	}
	var restoredState []byte
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT payload FROM read_model_snapshots
		WHERE tenant_id = $1`, tenantID).Scan(&restoredState); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(restoredState, []byte(subject)) || bytes.Contains(restoredState, []byte(subjectKey)) ||
		!bytes.Contains(restoredState, []byte(wantSubjectKey)) ||
		!bytes.Contains(restoredState, []byte(subjectCanonical)) {
		t.Fatalf("restored read model did not converge on privacy-safe legacy identity")
	}

	var restoredPostgresArtifact bytes.Buffer
	if _, err := backup.WritePostgresStateAtCut(ctx, h.store, &restoredPostgresArtifact, cut); err != nil {
		t.Fatalf("re-export restored PostgreSQL state: %v", err)
	}
	if bytes.Contains(restoredPostgresArtifact.Bytes(), []byte(subject)) ||
		bytes.Contains(restoredPostgresArtifact.Bytes(), []byte(subjectKey)) ||
		bytes.Contains(restoredPostgresArtifact.Bytes(), []byte(fencedKey)) {
		t.Fatal("restored PostgreSQL state reintroduced raw code-signing privacy identity")
	}

	// The restored operation is tenant scoped; another tenant cannot use its
	// operation UUID or one-way key as an oracle.
	var tenantBCount int
	if err := h.store.WithTenant(ctx, "22222222-2222-2222-2222-222222222222", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM code_signing_operations
			WHERE tenant_id = $1 AND operation_id = $2`, tenantID, subjectOperationID).Scan(&tenantBCount)
	}); err != nil {
		t.Fatalf("tenant isolation probe: %v", err)
	}
	if tenantBCount != 0 {
		t.Fatalf("tenant isolation probe exposed %d foreign operation row(s), want 0", tenantBCount)
	}
}
