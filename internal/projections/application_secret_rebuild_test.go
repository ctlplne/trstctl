// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func appendApprovedApplicationSecretMutation(
	t *testing.T,
	s *store.Store,
	log *events.Log,
	payload projections.ApplicationSecretMutation,
	requestID, decisionID, targetID, intentDigest, eventType string,
	createdAt time.Time,
) {
	t.Helper()
	if payload.TenantEpoch == "" {
		epoch, err := s.ApplicationSecretTenantEpoch(context.Background(), tenantA)
		if err != nil {
			t.Fatalf("application-secret test tenant epoch: %v", err)
		}
		payload.TenantEpoch = epoch
	}
	if payload.RequestBinding == "" {
		payload.RequestBinding = hex64('9')
	}
	from, to, evidence, err := projections.ApplicationSecretApprovalBinding(payload)
	if err != nil {
		t.Fatalf("bind application-secret approval: %v", err)
	}
	request := projections.ApprovalRequested{
		ID: requestID, IntentDigest: intentDigest,
		ResourceKind: "secret", ResourceID: "secret:" + payload.Name, ResourceName: payload.Name,
		Action: payload.Action, Requester: "alice", FromState: from, ToState: to,
		TargetVersion:     uint64(payload.ExpectedVersion), // #nosec G115 -- the binding validator proved this fixture version is positive (CWE-190).
		EvidenceRefs:      evidence,
		RequiredApprovals: 1, CreatedAt: createdAt, ExpiresAt: createdAt.Add(time.Hour),
	}
	if _, err := log.Append(context.Background(), events.Event{
		ID: requestID, Type: projections.EventApprovalRequested, TenantID: tenantA,
		Time: createdAt, Data: operationApprovalJSON(t, request),
	}); err != nil {
		t.Fatalf("append secret approval request: %v", err)
	}
	decidedAt := createdAt.Add(time.Minute)
	if _, err := log.Append(context.Background(), events.Event{
		ID: decisionID, Type: projections.EventApprovalDecisionRecorded, TenantID: tenantA,
		Time: decidedAt, Data: operationApprovalJSON(t, projections.ApprovalDecisionRecorded{
			RequestID: requestID, IntentDigest: intentDigest, Approver: "bob",
			Decision: store.ApprovalDecisionApprove, DecidedAt: decidedAt,
			ExpectedResourceKind: "secret", ExpectedResourceID: "secret:" + payload.Name,
			ExpectedAction: payload.Action,
		}),
	}); err != nil {
		t.Fatalf("append secret approval decision: %v", err)
	}
	payload.Approval = &store.OperationApprovalUse{
		RequestID: requestID, IntentDigest: intentDigest, Requester: "alice",
		ResourceKind: "secret", ResourceID: "secret:" + payload.Name,
		Action: payload.Action, FromState: from, ToState: to,
		TargetVersion:     uint64(payload.ExpectedVersion), // #nosec G115 -- the binding validator proved this fixture version is positive (CWE-190).
		RequiredApprovals: 1,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(context.Background(), events.Event{
		ID: targetID, Type: eventType, TenantID: tenantA,
		Time:          createdAt.Add(2 * time.Minute),
		SchemaVersion: projections.ApplicationSecretMutationSchemaVersion, Data: raw,
	}); err != nil {
		t.Fatalf("append approved secret target event: %v", err)
	}
}

func appendApplicationSecretCreate(
	t *testing.T,
	s *store.Store,
	log *events.Log,
	id, name, ownerID string,
	sealed []byte,
	keyDigest, binding, evidence, surface string,
	at time.Time,
) {
	t.Helper()
	epoch, err := s.ApplicationSecretTenantEpoch(context.Background(), tenantA)
	if err != nil {
		t.Fatalf("application-secret test tenant epoch: %v", err)
	}
	payload := projections.ApplicationSecretMutation{
		TenantEpoch: epoch, Action: "create", Name: name, OwnerID: ownerID, ResultVersion: 1, Sealed: sealed,
		IdempotencyKeyDigest: keyDigest, RequestBinding: binding,
		CommandEvidence: evidence, Surface: surface,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(context.Background(), events.Event{
		ID: id, Type: projections.EventApplicationSecretCreated, TenantID: tenantA,
		Time: at, SchemaVersion: projections.ApplicationSecretMutationSchemaVersion, Data: raw,
	}); err != nil {
		t.Fatalf("append application-secret create: %v", err)
	}
}

func seedApplicationSecretFixture(
	t *testing.T,
	s *store.Store,
	name string,
	sealed []byte,
) store.Secret {
	t.Helper()
	ctx := context.Background()
	var out store.Secret
	err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			INSERT INTO secret_store (tenant_id, name, sealed, version)
			VALUES ($1, $2, $3, 1)
			RETURNING id::text, tenant_id::text, name, version, created_at, updated_at`,
			tenantA, name, sealed).Scan(
			&out.ID, &out.TenantID, &out.Name, &out.Version, &out.CreatedAt, &out.UpdatedAt); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO secret_store_versions (tenant_id, name, version, sealed, written_at)
			VALUES ($1, $2, 1, $3, $4)`, tenantA, name, sealed, out.UpdatedAt)
		return err
	})
	if err != nil {
		t.Fatalf("seed application-secret fixture %s: %v", name, err)
	}
	out.Sealed = append([]byte(nil), sealed...)
	return out
}

func openApplicationSecretRewriteLog(t *testing.T) *events.Log {
	t.Helper()
	log, err := events.Open(context.Background(), config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	}, events.WithHistoryRewriteContinuityVerifier(func(_ context.Context, evidence events.TenantDataContinuityEvidence) error {
		if evidence.OperationID == "" || evidence.TenantID == "" ||
			evidence.ReceiptSequence == 0 || evidence.Receipt.ID == "" {
			return errors.New("incomplete rewrite continuity evidence")
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log
}

func applicationSecretRewriteProofOptions() []events.TenantDataRewriteOption {
	return []events.TenantDataRewriteOption{
		events.WithTenantDataCutoverPreparation(func(
			ctx context.Context,
			_ events.TenantDataRewriteReport,
			proceed func(context.Context) error,
		) error {
			return proceed(ctx)
		}),
		events.WithTenantDataAuditContinuity(func(
			context.Context,
			events.TenantDataAuditView,
		) (events.TenantDataAuditCheckpoint, error) {
			return events.TenantDataAuditCheckpoint{IdentityDigest: hex64('d')}, nil
		}),
		events.WithTenantDataContinuity(func(_ context.Context, report events.TenantDataRewriteReport) (events.Event, error) {
			data, err := json.Marshal(report)
			if err != nil {
				return events.Event{}, err
			}
			return events.Event{
				ID:   "rewrite-receipt-" + report.OperationID,
				Type: "tenant.data.rewrite.receipt", TenantID: report.TenantID,
				Time: report.CompletedAt, SchemaVersion: events.DefaultSchemaVersion, Data: data,
			}, nil
		}),
	}
}

func TestApplicationSecretReceiptsMakeFullApprovalRebuildNonMutating(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	reset := func() {
		if _, err := s.SystemPool().Exec(ctx,
			`TRUNCATE application_secret_mutation_receipts, secret_store_versions,
			          secret_store, operation_approval_decisions, operation_approval_requests CASCADE`); err != nil {
			t.Fatalf("reset application-secret rebuild state: %v", err)
		}
	}
	reset()
	t.Cleanup(reset)
	log := openLog(t)
	registered, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Data: tenantRegistered("application-secret-rebuild"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(s).Apply(ctx, registered); err != nil {
		t.Fatalf("project application-secret tenant lifecycle root: %v", err)
	}
	seedApplicationSecretFixture(t, s, "app/config", []byte("sealed-v1"))
	source, err := s.GetSecretVersion(ctx, tenantA, "app/config", 1)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC()
	appendApprovedApplicationSecretMutation(t, s, log, projections.ApplicationSecretMutation{
		Action: "rotate", Name: "app/config", ExpectedVersion: 1, ResultVersion: 2,
		Sealed: []byte("sealed-native-v2"), IdempotencyKeyDigest: hex64('1'),
		CommandEvidence: hex64('2'), Surface: "native",
	}, "77200000-0000-4000-8000-000000000001", "77200000-0000-4000-8000-000000000002",
		"77200000-0000-4000-8000-000000000003", "sha256:native-rotate", projections.EventApplicationSecretRotated, base)
	appendApprovedApplicationSecretMutation(t, s, log, projections.ApplicationSecretMutation{
		Action: "recover", Name: "app/config", ExpectedVersion: 2, ResultVersion: 3,
		Sealed: source.Sealed, SourceVersion: source.Version, SourceWrittenAt: source.WrittenAt,
		IdempotencyKeyDigest: hex64('3'), CommandEvidence: hex64('4'), Surface: "native",
	}, "77200000-0000-4000-8000-000000000011", "77200000-0000-4000-8000-000000000012",
		"77200000-0000-4000-8000-000000000013", "sha256:native-recover", projections.EventApplicationSecretRecovered, base.Add(3*time.Minute))
	appendApprovedApplicationSecretMutation(t, s, log, projections.ApplicationSecretMutation{
		Action: "rotate", Name: "app/config", ExpectedVersion: 3, ResultVersion: 4,
		Sealed: []byte("sealed-vault-v4"), IdempotencyKeyDigest: hex64('5'),
		CommandEvidence: hex64('6'), Surface: "vault",
	}, "77200000-0000-4000-8000-000000000021", "77200000-0000-4000-8000-000000000022",
		"77200000-0000-4000-8000-000000000023", "sha256:vault-overwrite", projections.EventApplicationSecretRotated, base.Add(6*time.Minute))
	appendApprovedApplicationSecretMutation(t, s, log, projections.ApplicationSecretMutation{
		Action: "delete", Name: "app/config", ExpectedVersion: 4,
		IdempotencyKeyDigest: hex64('7'), CommandEvidence: hex64('8'), Surface: "native",
	}, "77200000-0000-4000-8000-000000000031", "77200000-0000-4000-8000-000000000032",
		"77200000-0000-4000-8000-000000000033", "sha256:native-delete", projections.EventApplicationSecretDeleted, base.Add(9*time.Minute))

	projector := projections.New(s)
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("initial application-secret projection: %v", err)
	}
	if _, err := s.GetSecret(ctx, tenantA, "app/config"); err != store.ErrSecretNotFound {
		t.Fatalf("warm delete result = %v, want ErrSecretNotFound", err)
	}
	var receiptCount int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM application_secret_mutation_receipts WHERE tenant_id = $1`, tenantA).Scan(&receiptCount); err != nil || receiptCount != 4 {
		t.Fatalf("warm receipts=%d err=%v, want 4", receiptCount, err)
	}

	// Recreate the same logical name after deletion. Without the durable delete
	// receipt, replaying the old v2 delete during Rebuild would erase this new
	// lineage. Every old target event must now be approval-only replay.
	seedApplicationSecretFixture(t, s, "app/config", []byte("sealed-recreated-v1"))
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("full rebuild with materialized secret receipts: %v", err)
	}
	recreated, err := s.GetSecret(ctx, tenantA, "app/config")
	if err != nil || recreated.Version != 1 || !bytes.Equal(recreated.Sealed, []byte("sealed-recreated-v1")) {
		t.Fatalf("rebuild reapplied old secret mutation: %+v err=%v", recreated, err)
	}
	for _, requestID := range []string{
		"77200000-0000-4000-8000-000000000001",
		"77200000-0000-4000-8000-000000000011",
		"77200000-0000-4000-8000-000000000021",
		"77200000-0000-4000-8000-000000000031",
	} {
		approval, err := s.GetOperationApproval(ctx, tenantA, requestID)
		if err != nil || approval.Status != store.ApprovalStatusConsumed || approval.ConsumedEventID == "" {
			t.Fatalf("rebuilt exact authority %s = %+v err=%v", requestID, approval, err)
		}
	}
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM application_secret_mutation_receipts WHERE tenant_id = $1`, tenantA).Scan(&receiptCount); err != nil || receiptCount != 4 {
		t.Fatalf("rebuild changed independent receipts=%d err=%v", receiptCount, err)
	}
}

func TestApplicationSecretRebuildTracksOffboardLifecycleEpochs(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, err := s.SystemPool().Exec(ctx,
		`TRUNCATE application_secret_mutation_fences, application_secret_mutation_receipts,
		          application_secret_tenant_epochs, secret_store_versions, secret_store, operation_approval_decisions,
		          operation_approval_requests, tenants CASCADE`); err != nil {
		t.Fatal(err)
	}
	log := openLog(t)
	base := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	const (
		oldEpoch = "77400000-aaaa-4aaa-8aaa-000000000001"
		newEpoch = "77400000-bbbb-4bbb-8bbb-000000000002"
	)
	appendCreate := func(id, epoch, name string, sealed []byte, keyDigest, binding, evidence, surface string, at time.Time) {
		t.Helper()
		raw, err := json.Marshal(projections.ApplicationSecretMutation{
			TenantEpoch: epoch, Action: "create", Name: name, ResultVersion: 1, Sealed: sealed,
			IdempotencyKeyDigest: keyDigest, RequestBinding: binding,
			CommandEvidence: evidence, Surface: surface,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(ctx, events.Event{
			ID: id, Type: projections.EventApplicationSecretCreated, TenantID: tenantA,
			Time: at, SchemaVersion: projections.ApplicationSecretMutationSchemaVersion, Data: raw,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Time: base, Data: tenantRegistered("old-epoch"),
	}); err != nil {
		t.Fatal(err)
	}
	appendCreate(
		"77400000-0000-4000-8000-000000000001", oldEpoch, "old/secret", []byte("sealed-old-v1"),
		hex64('1'), hex64('2'), hex64('3'), "native", base.Add(time.Minute))
	appendApprovedApplicationSecretMutation(t, s, log, projections.ApplicationSecretMutation{
		TenantEpoch: oldEpoch, Action: "rotate", Name: "old/secret", ExpectedVersion: 1, ResultVersion: 2,
		Sealed: []byte("sealed-old-v2"), IdempotencyKeyDigest: hex64('4'),
		RequestBinding: hex64('5'), CommandEvidence: hex64('6'), Surface: "native",
	}, "77400000-0000-4000-8000-000000000011", "77400000-0000-4000-8000-000000000012",
		"77400000-0000-4000-8000-000000000013", "sha256:old-epoch", projections.EventApplicationSecretRotated,
		base.Add(2*time.Minute))
	offboard, _ := json.Marshal(map[string]any{"rows_deleted": 6})
	if _, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantOffboarded, TenantID: tenantA,
		Time: base.Add(5 * time.Minute), Data: offboard,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Time: base.Add(6 * time.Minute), Data: tenantRegistered("new-epoch"),
	}); err != nil {
		t.Fatal(err)
	}
	appendCreate(
		"77400000-0000-4000-8000-000000000021", newEpoch, "new/secret", []byte("sealed-new-v1"),
		hex64('7'), hex64('8'), hex64('9'), "vault", base.Add(7*time.Minute))
	appendApprovedApplicationSecretMutation(t, s, log, projections.ApplicationSecretMutation{
		TenantEpoch: newEpoch, Action: "rotate", Name: "new/secret", ExpectedVersion: 1, ResultVersion: 2,
		Sealed: []byte("sealed-new-v2"), IdempotencyKeyDigest: hex64('a'),
		RequestBinding: hex64('b'), CommandEvidence: hex64('c'), Surface: "vault",
	}, "77400000-0000-4000-8000-000000000031", "77400000-0000-4000-8000-000000000032",
		"77400000-0000-4000-8000-000000000033", "sha256:new-epoch", projections.EventApplicationSecretRotated,
		base.Add(8*time.Minute))

	if _, err := s.SystemPool().Exec(ctx, `
		INSERT INTO application_secret_tenant_epochs (tenant_id, epoch_id)
		VALUES ($1, $2)`, tenantA, newEpoch); err != nil {
		t.Fatal(err)
	}
	projector := projections.New(s)
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("cold lifecycle-epoch rebuild: %v", err)
	}
	assertEpochState := func(stage string) {
		t.Helper()
		if _, err := s.GetSecret(ctx, tenantA, "old/secret"); !errors.Is(err, store.ErrSecretNotFound) {
			t.Fatalf("%s resurrected old-epoch secret: %v", stage, err)
		}
		current, err := s.GetSecret(ctx, tenantA, "new/secret")
		if err != nil || current.Version != 2 || !bytes.Equal(current.Sealed, []byte("sealed-new-v2")) {
			t.Fatalf("%s lost new-epoch secret: %+v err=%v", stage, current, err)
		}
		if _, err := s.GetOperationApproval(ctx, tenantA, "77400000-0000-4000-8000-000000000011"); !errors.Is(err, store.ErrApprovalRequestNotFound) {
			t.Fatalf("%s resurrected old-epoch authority: %v", stage, err)
		}
		approval, err := s.GetOperationApproval(ctx, tenantA, "77400000-0000-4000-8000-000000000031")
		if err != nil || approval.Status != store.ApprovalStatusConsumed ||
			approval.ConsumedEventID != "77400000-0000-4000-8000-000000000033" {
			t.Fatalf("%s new-epoch authority is not exact/consumed: %+v err=%v", stage, approval, err)
		}
	}
	assertEpochState("cold rebuild")
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("repeat cold lifecycle-epoch rebuild: %v", err)
	}
	assertEpochState("repeat cold rebuild")
}

func TestApplicationSecretDelayedPriorEpochIsInertAndAdvancesWarmAndColdSequence(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, err := s.SystemPool().Exec(ctx,
		`TRUNCATE application_secret_mutation_fences, application_secret_mutation_receipts,
		          application_secret_tenant_epochs, secret_store_versions, secret_store,
		          operation_approval_decisions, operation_approval_requests, tenants CASCADE`); err != nil {
		t.Fatal(err)
	}
	log := openLog(t)
	projector := projections.New(s)
	base := time.Date(2026, 8, 10, 17, 0, 0, 0, time.UTC)
	appendEvent := func(event events.Event) events.Event {
		t.Helper()
		appended, err := log.Append(ctx, event)
		if err != nil {
			t.Fatal(err)
		}
		return appended
	}
	appendCreate := func(id, epoch, name string, sealed []byte, at time.Time) events.Event {
		t.Helper()
		payload := projections.ApplicationSecretMutation{
			TenantEpoch: epoch, Action: "create", Name: name, ResultVersion: 1,
			Sealed: sealed, IdempotencyKeyDigest: hex64('1'), RequestBinding: hex64('2'),
			CommandEvidence: hex64('3'), Surface: "native",
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		return appendEvent(events.Event{
			ID: id, Type: projections.EventApplicationSecretCreated, TenantID: tenantA,
			Time: at, SchemaVersion: projections.ApplicationSecretMutationSchemaVersion, Data: raw,
		})
	}

	appendEvent(events.Event{
		ID:   "77930000-0000-4000-8000-000000000001",
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Time: base, Data: tenantRegistered("old-lifecycle"),
	})
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("project old tenant registration: %v", err)
	}
	oldEpoch, err := s.ApplicationSecretTenantEpoch(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}

	appendEvent(events.Event{
		ID:   "77930000-0000-4000-8000-000000000002",
		Type: projections.EventTenantOffboarded, TenantID: tenantA,
		Time: base.Add(time.Minute), Data: []byte(`{"rows_deleted":0}`),
	})
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("project tenant offboard: %v", err)
	}
	appendEvent(events.Event{
		ID:   "77930000-0000-4000-8000-000000000003",
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Time: base.Add(2 * time.Minute), Data: tenantRegistered("new-lifecycle"),
	})
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("project new tenant registration: %v", err)
	}
	newEpoch, err := s.ApplicationSecretTenantEpoch(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if newEpoch == oldEpoch {
		t.Fatal("offboard/re-registration reused the old application-secret epoch")
	}

	appendCreate("77930000-0000-4000-8000-000000000004", newEpoch,
		"new-lifecycle/secret", []byte("sealed-new-lifecycle"), base.Add(3*time.Minute))
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("project new-lifecycle secret: %v", err)
	}
	if current, getErr := s.GetSecret(ctx, tenantA, "new-lifecycle/secret"); getErr != nil {
		var storedEpoch string
		_ = s.SystemPool().QueryRow(ctx,
			`SELECT epoch_id::text FROM application_secret_tenant_epochs WHERE tenant_id = $1`, tenantA).Scan(&storedEpoch)
		checkpoint, _ := s.ProjectionCheckpoint(ctx)
		t.Fatalf("new-lifecycle event was not applied before delayed append: event_epoch=%q stored_epoch=%q checkpoint=%d err=%v current=%+v",
			newEpoch, storedEpoch, checkpoint, getErr, current)
	}
	// This simulates Append succeeding long after its old finalized fence was
	// created, after the same tenant UUID has already started a new lifecycle.
	delayed := appendCreate("77930000-0000-4000-8000-000000000005", oldEpoch,
		"old-lifecycle/delayed", []byte("sealed-old-delayed"), base.Add(4*time.Minute))
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("warm projection was poisoned by delayed old-lifecycle event: %v", err)
	}
	if _, err := s.GetSecret(ctx, tenantA, "old-lifecycle/delayed"); !errors.Is(err, store.ErrSecretNotFound) {
		t.Fatalf("warm projection applied delayed old-lifecycle event: %v", err)
	}
	current, err := s.GetSecret(ctx, tenantA, "new-lifecycle/secret")
	if err != nil || !bytes.Equal(current.Sealed, []byte("sealed-new-lifecycle")) {
		t.Fatalf("warm projection lost new lifecycle secret: %+v err=%v", current, err)
	}
	checkpoint, err := s.ProjectionCheckpoint(ctx)
	if err != nil || checkpoint != delayed.Sequence {
		t.Fatalf("warm checkpoint=%d err=%v, want delayed sequence %d", checkpoint, err, delayed.Sequence)
	}

	// Remove both the primary state and its receipt so cold rebuild must execute
	// the new-epoch event while independently rejecting the delayed old epoch.
	if _, err := s.SystemPool().Exec(ctx,
		`TRUNCATE application_secret_mutation_receipts, secret_store_versions, secret_store CASCADE`); err != nil {
		t.Fatal(err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("cold rebuild was poisoned by delayed old-lifecycle event: %v", err)
	}
	if _, err := s.GetSecret(ctx, tenantA, "old-lifecycle/delayed"); !errors.Is(err, store.ErrSecretNotFound) {
		t.Fatalf("cold rebuild applied delayed old-lifecycle event: %v", err)
	}
	current, err = s.GetSecret(ctx, tenantA, "new-lifecycle/secret")
	if err != nil || current.Version != 1 || !bytes.Equal(current.Sealed, []byte("sealed-new-lifecycle")) {
		t.Fatalf("cold rebuild did not restore new lifecycle secret: %+v err=%v", current, err)
	}
	checkpoint, err = s.ProjectionCheckpoint(ctx)
	if err != nil || checkpoint != delayed.Sequence {
		t.Fatalf("cold checkpoint=%d err=%v, want delayed sequence %d", checkpoint, err, delayed.Sequence)
	}
}

func TestApplicationSecretCreateColdRebuildsNativeAndVaultFromZeroPrimary(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, err := s.SystemPool().Exec(ctx,
		`TRUNCATE application_secret_mutation_fences, application_secret_mutation_receipts,
		          secret_store_versions, secret_store, operation_approval_decisions,
		          operation_approval_requests, tenants CASCADE`); err != nil {
		t.Fatal(err)
	}
	log := openLog(t)
	base := time.Date(2026, 8, 10, 15, 0, 0, 0, time.UTC)
	registered, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Time: base, Data: tenantRegistered("cold-create"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(s).Apply(ctx, registered); err != nil {
		t.Fatalf("project application-secret tenant lifecycle root: %v", err)
	}
	const ownerID = "77600000-0000-4000-8000-000000000099"
	if _, err := log.Append(ctx, events.Event{
		Type: projections.EventOwnerCreated, TenantID: tenantA, Time: base.Add(30 * time.Second),
		Data: ownerCreated(ownerID, "Cold rebuild owner"),
	}); err != nil {
		t.Fatalf("append cold rebuild owner: %v", err)
	}
	appendApplicationSecretCreate(t, s, log,
		"77600000-0000-4000-8000-000000000001", "cold/native", ownerID, []byte("sealed-native-v1"),
		hex64('1'), hex64('2'), hex64('3'), "native", base.Add(time.Minute))
	appendApplicationSecretCreate(t, s, log,
		"77600000-0000-4000-8000-000000000002", "cold/vault", "", []byte("sealed-vault-v1"),
		hex64('4'), hex64('5'), hex64('6'), "vault", base.Add(2*time.Minute))
	projector := projections.New(s)
	if err := projector.Project(ctx, log); err != nil {
		t.Fatalf("warm create projection: %v", err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`TRUNCATE application_secret_mutation_fences, application_secret_mutation_receipts,
		          secret_store_versions, secret_store CASCADE`); err != nil {
		t.Fatal(err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("zero-primary/zero-receipt cold rebuild: %v", err)
	}
	for name, want := range map[string]struct {
		sealed  []byte
		ownerID string
	}{
		"cold/native": {sealed: []byte("sealed-native-v1"), ownerID: ownerID},
		"cold/vault":  {sealed: []byte("sealed-vault-v1")},
	} {
		current, err := s.GetSecret(ctx, tenantA, name)
		if err != nil || current.Version != 1 || current.OwnerID != want.ownerID || !bytes.Equal(current.Sealed, want.sealed) {
			t.Fatalf("cold rebuild %s=%+v err=%v", name, current, err)
		}
	}
	var receipts int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM application_secret_mutation_receipts WHERE tenant_id = $1`, tenantA).
		Scan(&receipts); err != nil || receipts != 2 {
		t.Fatalf("cold create receipts=%d err=%v, want 2", receipts, err)
	}
}

func TestApplicationSecretPrivacyRewritePreservesExactReceiptAndAuthority(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, err := s.SystemPool().Exec(ctx,
		`TRUNCATE application_secret_mutation_fences, application_secret_mutation_receipts,
		          secret_store_versions, secret_store, operation_approval_decisions,
		          operation_approval_requests, tenants CASCADE`); err != nil {
		t.Fatal(err)
	}
	log := openApplicationSecretRewriteLog(t)
	base := time.Date(2026, 8, 10, 16, 0, 0, 0, time.UTC)
	registered, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Time: base, Data: tenantRegistered("privacy-secret"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(s).Apply(ctx, registered); err != nil {
		t.Fatalf("project application-secret tenant lifecycle root: %v", err)
	}
	appendApplicationSecretCreate(t, s, log,
		"77700000-0000-4000-8000-000000000001", "privacy/secret", "", []byte("sealed-privacy-v1"),
		hex64('1'), hex64('2'), hex64('3'), "native", base.Add(time.Minute))
	appendApprovedApplicationSecretMutation(t, s, log, projections.ApplicationSecretMutation{
		Action: "rotate", Name: "privacy/secret", ExpectedVersion: 1, ResultVersion: 2,
		Sealed: []byte("sealed-privacy-v2"), IdempotencyKeyDigest: hex64('4'),
		RequestBinding: hex64('5'), CommandEvidence: hex64('6'), Surface: "native",
	}, "77700000-0000-4000-8000-000000000011", "77700000-0000-4000-8000-000000000012",
		"77700000-0000-4000-8000-000000000013", "sha256:privacy-rewrite",
		projections.EventApplicationSecretRotated, base.Add(2*time.Minute))
	projector := projections.New(s)
	if err := projector.Project(ctx, log); err != nil {
		t.Fatalf("warm privacy projection: %v", err)
	}
	beforeReceipt, err := s.GetApplicationSecretMutationReceipt(ctx, tenantA,
		"77700000-0000-4000-8000-000000000013")
	if err != nil {
		t.Fatal(err)
	}
	var beforeTarget projections.ApplicationSecretMutation
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.ID == "77700000-0000-4000-8000-000000000013" {
			return json.Unmarshal(event.Data, &beforeTarget)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if beforeTarget.Approval == nil || beforeTarget.Approval.Requester != "alice" {
		t.Fatalf("privacy target precondition=%+v", beforeTarget.Approval)
	}
	if err := log.PseudonymizeSubject(ctx, tenantA, "alice", applicationSecretRewriteProofOptions()...); err != nil {
		t.Fatalf("actual subject history rewrite: %v", err)
	}
	var afterTarget projections.ApplicationSecretMutation
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if bytes.Contains(event.Data, []byte(`"alice"`)) {
			return errors.New("rewritten history retains requester")
		}
		if event.ID == "77700000-0000-4000-8000-000000000013" {
			return json.Unmarshal(event.Data, &afterTarget)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if afterTarget.Approval == nil || afterTarget.Approval.Requester == "alice" ||
		afterTarget.RequestBinding != beforeTarget.RequestBinding ||
		afterTarget.CommandEvidence != beforeTarget.CommandEvidence ||
		!bytes.Equal(afterTarget.Sealed, beforeTarget.Sealed) {
		t.Fatalf("history rewrite changed command binding/ciphertext or retained requester: before=%+v after=%+v",
			beforeTarget, afterTarget)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("zero-state rebuild after requester rewrite: %v", err)
	}
	afterReceipt, err := s.GetApplicationSecretMutationReceipt(ctx, tenantA,
		"77700000-0000-4000-8000-000000000013")
	if err != nil || afterReceipt.SemanticDigest != beforeReceipt.SemanticDigest {
		t.Fatalf("privacy rewrite changed exact semantic receipt: before=%+v after=%+v err=%v",
			beforeReceipt, afterReceipt, err)
	}
	current, err := s.GetSecret(ctx, tenantA, "privacy/secret")
	if err != nil || current.Version != 2 || !bytes.Equal(current.Sealed, []byte("sealed-privacy-v2")) {
		t.Fatalf("privacy rebuild changed ciphertext result: %+v err=%v", current, err)
	}
	authority, err := s.GetOperationApproval(ctx, tenantA, "77700000-0000-4000-8000-000000000011")
	if err != nil || authority.Requester == "alice" || authority.Status != store.ApprovalStatusConsumed ||
		authority.ConsumedEventID != "77700000-0000-4000-8000-000000000013" {
		t.Fatalf("rewritten exact authority=%+v err=%v", authority, err)
	}
}

func hex64(ch byte) string { return string(bytes.Repeat([]byte{ch}, 64)) }

func TestApplicationSecretSemanticDigestNormalizesOnlyRequester(t *testing.T) {
	event := events.Event{
		ID: "77300000-0000-4000-8000-000000000001", Type: projections.EventApplicationSecretRotated,
		TenantID: tenantA, Time: time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
		SchemaVersion: projections.ApplicationSecretMutationSchemaVersion,
	}
	payload := projections.ApplicationSecretMutation{
		Action: "rotate", Name: "privacy/exact", ExpectedVersion: 1, ResultVersion: 2,
		Sealed: []byte("sealed-ciphertext"), IdempotencyKeyDigest: hex64('1'),
		RequestBinding: hex64('2'), CommandEvidence: hex64('3'), Surface: "native",
		Approval: &store.OperationApprovalUse{
			RequestID: "77300000-0000-4000-8000-000000000002", IntentDigest: "sha256:privacy-exact",
			Requester: "alice@example.test", ResourceKind: "secret", ResourceID: "secret:privacy/exact",
			Action: "rotate", FromState: "version:1", ToState: "version:2:command-hmac-sha256:" + hex64('3'),
			TargetVersion: 1, RequiredApprovals: 1,
		},
	}
	want, err := projections.ApplicationSecretMutationSemanticDigest(event, payload)
	if err != nil {
		t.Fatal(err)
	}

	requesterRewrite := payload
	requesterApproval := *payload.Approval
	requesterApproval.Requester = "anon:7f6d"
	requesterRewrite.Approval = &requesterApproval
	got, err := projections.ApplicationSecretMutationSemanticDigest(event, requesterRewrite)
	if err != nil || got != want {
		t.Fatalf("requester-only privacy rewrite changed semantic digest: got=%q want=%q err=%v", got, want, err)
	}

	for name, mutate := range map[string]func(*projections.ApplicationSecretMutation){
		"sealed":   func(p *projections.ApplicationSecretMutation) { p.Sealed = []byte("different-ciphertext") },
		"owner":    func(p *projections.ApplicationSecretMutation) { p.OwnerID = "77300000-0000-4000-8000-000000000099" },
		"resource": func(p *projections.ApplicationSecretMutation) { p.Approval.ResourceID = "secret:other" },
		"action":   func(p *projections.ApplicationSecretMutation) { p.Action = "recover" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := payload
			approval := *payload.Approval
			changed.Approval = &approval
			mutate(&changed)
			digest, err := projections.ApplicationSecretMutationSemanticDigest(event, changed)
			if err != nil {
				t.Fatal(err)
			}
			if digest == want {
				t.Fatalf("%s drift was normalized out of the semantic digest", name)
			}
		})
	}
}

func TestApplicationSecretPendingFenceActorSurvivesReadModelRebuild(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, err := s.SystemPool().Exec(ctx, `TRUNCATE application_secret_mutation_fences`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.SystemPool().Exec(context.Background(), `TRUNCATE application_secret_mutation_fences`)
	})
	log := openLog(t)
	if _, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Data: tenantRegistered("pending-fence-actor-rebuild"),
	}); err != nil {
		t.Fatal(err)
	}
	wantActor := &events.Actor{Subject: "rebuild-alice", Roles: []string{"auditor", "operator"}}
	claimed, err := s.ClaimApplicationSecretMutationFence(ctx, store.ApplicationSecretMutationFence{
		TenantID: tenantA, Name: "rebuild/pending", Operation: "create",
		EventID:        "77970000-0000-4000-8000-000000000001",
		EventType:      projections.EventApplicationSecretCreated,
		SchemaVersion:  projections.ApplicationSecretMutationSchemaVersion,
		RequestBinding: hex64('b'), Payload: []byte(`{"action":"create"}`),
		Actor: &events.Actor{Subject: wantActor.Subject, Roles: []string{"operator", "auditor"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(claimed.Actor, wantActor) {
		t.Fatalf("fixture actor was not canonical: %+v", claimed.Actor)
	}
	if err := projections.New(s).Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := s.GetApplicationSecretMutationFence(ctx, tenantA, "rebuild/pending")
	if err != nil || !reflect.DeepEqual(rebuilt.Actor, wantActor) ||
		rebuilt.ActorSubjectRef != privacy.SubjectRef(tenantA, wantActor.Subject) {
		t.Fatalf("read-model rebuild changed independent pending actor fence: %+v err=%v", rebuilt, err)
	}
}
