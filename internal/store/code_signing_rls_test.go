// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestCodeSigningOperationsUseProductTenantGUC(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	var outboxB int64
	if err := s.SystemPool().QueryRow(ctx,
		`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key)
		 VALUES ($1,'codesign.command','{}','codesign-b') RETURNING id`, tenantB).Scan(&outboxB); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`INSERT INTO code_signing_operations
		 (tenant_id,operation_id,idempotency_key,mode,request_hash,sealed_command,
		  status,cleanup_status,command_outbox_id,created_at,updated_at)
		 VALUES ($1,'op-b','idem-b','key','hash-b',$2,'queued','not_required',$3,now(),now())`,
		tenantB, []byte("ciphertext-b"), outboxB); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		var visible int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM code_signing_operations WHERE tenant_id = $1`, tenantB).Scan(&visible); err != nil {
			return err
		}
		if visible != 0 {
			t.Fatalf("tenant A saw %d tenant-B code-signing rows", visible)
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO code_signing_operations
			 (tenant_id,operation_id,idempotency_key,mode,request_hash,sealed_command,
			  status,cleanup_status,command_outbox_id,created_at,updated_at)
			 VALUES ($1,'cross-op','cross-idem','key','cross-hash',$2,'queued','not_required',$3,now(),now())`,
			tenantB, []byte("cross-ciphertext"), outboxB)
		return err
	}); err == nil || !isRLSViolation(err) {
		t.Fatalf("cross-tenant code_signing_operations insert = %v, want RLS denial", err)
	}
}

func TestCodeSigningOperationIdentityDomainsSeparateLegacyRawKeyEqualToV3Reference(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	const (
		keyK        = "release-key-k"
		requestHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	)
	keyJ := store.CodeSigningIdempotencyKeyRef(keyK)
	v3OperationK := store.CodeSigningOperationID(tenantA, keyK)
	legacyOperationJ := store.LegacyCodeSigningOperationID(tenantA, keyJ)
	if v3OperationK == legacyOperationJ {
		t.Fatalf("v3 K and legacy J operation identities alias: %q", v3OperationK)
	}
	legacy := store.CodeSigningOperation{
		TenantID: tenantA, OperationID: legacyOperationJ, IdempotencyKey: keyJ,
		Mode: "key", RequestHash: requestHash, SealedCommand: []byte("legacy-j-ciphertext"),
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyCodeSigningIntentTx(ctx, tx, legacy,
			[]byte(`{"operation_id":"`+legacyOperationJ+`"}`))
	}); err != nil {
		t.Fatalf("seed warm legacy J: %v", err)
	}
	v3 := store.CodeSigningOperation{
		TenantID: tenantA, OperationID: v3OperationK,
		IdempotencyKey: keyJ, Mode: "key", RequestHash: requestHash,
		SealedCommand: []byte("v3-k-ciphertext"), CreatedAt: legacy.CreatedAt.Add(time.Second),
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyCodeSigningIntentTx(ctx, tx, v3,
			[]byte(`{"operation_id":"`+v3OperationK+`"}`))
	}); err != nil {
		t.Fatalf("project v3 K beside warm legacy J: %v", err)
	}

	gotK, found, err := s.CodeSigningOperationByIdempotency(ctx, tenantA, keyK)
	if err != nil || !found || gotK.OperationID != v3OperationK ||
		gotK.IdempotencyKey != keyJ {
		t.Fatalf("lookup K = found %t op=%+v err=%v", found, gotK, err)
	}
	gotJ, found, err := s.CodeSigningOperationByIdempotency(ctx, tenantA, keyJ)
	wantLegacyStorage := store.LegacyCodeSigningStorageKey(legacyOperationJ, keyJ)
	if err != nil || !found || gotJ.OperationID != legacyOperationJ ||
		gotJ.IdempotencyKey != wantLegacyStorage {
		t.Fatalf("lookup J = found %t op=%+v err=%v", found, gotJ, err)
	}

	v3Resource := store.CodeSigningApprovalResourceID(requestHash, keyK)
	legacyResource := store.CodeSigningApprovalResourceID(requestHash, keyJ)
	if v3Resource == legacyResource {
		t.Fatalf("v3 K and legacy J approval resources alias: %q", v3Resource)
	}
	if got, err := store.CodeSigningApprovalResourceIDForOperation(
		tenantA, v3OperationK, requestHash, keyJ, v3Resource,
	); err != nil || got != v3Resource {
		t.Fatalf("v3 K approval binding = %q err=%v", got, err)
	}
	if got, err := store.CodeSigningApprovalResourceIDForOperation(
		tenantA, legacyOperationJ, requestHash, wantLegacyStorage, legacyResource,
	); err != nil || got != legacyResource {
		t.Fatalf("legacy J approval binding = %q err=%v", got, err)
	}
	if _, err := store.CodeSigningApprovalResourceIDForOperation(
		tenantA, legacyOperationJ, requestHash, wantLegacyStorage, v3Resource,
	); !errors.Is(err, store.ErrApprovalDrifted) {
		t.Fatalf("legacy J accepted v3 K authority: %v", err)
	}
}

func TestCodeSigningIntentConcurrentProjectionCreatesOneCommand(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	op := store.CodeSigningOperation{
		TenantID: tenantA, OperationID: "codesign-concurrent-projection",
		IdempotencyKey: "codesign-concurrent-idem", Mode: "key",
		RequestHash: "request-hash", SealedCommand: []byte("sealed-command"),
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	const workers = 8
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errs <- s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
				return s.ApplyCodeSigningIntentTx(ctx, tx, op,
					[]byte(`{"operation_id":"codesign-concurrent-projection"}`))
			})
		}()
	}
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent code-signing projection: %v", err)
		}
	}
	var outboxRows, operationRows int
	var effectLane string
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantA, "codesign.command:"+op.OperationID).Scan(&outboxRows); err != nil {
		t.Fatal(err)
	}
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM code_signing_operations WHERE tenant_id = $1 AND operation_id = $2`,
		tenantA, op.OperationID).Scan(&operationRows); err != nil {
		t.Fatal(err)
	}
	if outboxRows != 1 || operationRows != 1 {
		t.Fatalf("concurrent fold persisted outbox/operation rows = %d/%d, want 1/1", outboxRows, operationRows)
	}
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT effect_lane FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantA, "codesign.command:"+op.OperationID).Scan(&effectLane); err != nil {
		t.Fatal(err)
	}
	if effectLane != "codesign.command:"+op.OperationID {
		t.Fatalf("code-signing command effect lane = %q", effectLane)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE outbox SET effect_lane = '' WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantA, "codesign.command:"+op.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyCodeSigningIntentTx(ctx, tx, op,
			[]byte(`{"operation_id":"codesign-concurrent-projection"}`))
	}); err != nil {
		t.Fatalf("replay code-signing intent with legacy empty lane: %v", err)
	}
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT effect_lane FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantA, "codesign.command:"+op.OperationID).Scan(&effectLane); err != nil {
		t.Fatal(err)
	}
	if effectLane != "codesign.command:"+op.OperationID {
		t.Fatalf("replayed code-signing command did not heal empty effect lane: %q", effectLane)
	}
}

func TestCodeSigningIdentitiesJoinTransparencyByOutboxIdentity(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	op := store.CodeSigningOperation{
		TenantID: tenantA, OperationID: "codesign-history-transparency",
		IdempotencyKey: store.CodeSigningIdempotencyKeyRef("history-request"),
		Mode:           "key", RequestHash: strings.Repeat("a", 64),
		SealedCommand: []byte("sealed-command"), CreatedAt: now, UpdatedAt: now,
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyCodeSigningIntentTx(ctx, tx, op,
			[]byte(`{"operation_id":"codesign-history-transparency"}`))
	}); err != nil {
		t.Fatalf("apply code-signing intent: %v", err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyCodeSigningCompletedTx(ctx, tx, tenantA, op.OperationID,
			op.RequestHash, []byte(`{"status":"signed"}`), "transparency.rekor",
			[]byte(`{"operation_id":"codesign-history-transparency"}`), "", now.Add(time.Second))
	}); err != nil {
		t.Fatalf("apply code-signing completion: %v", err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE outbox SET status = 'delivered', delivered_at = now(), payload = $4
		  WHERE tenant_id = $1 AND destination = $2 AND idempotency_key = $3`,
		tenantA, "transparency.rekor", "codesign.rekor:"+op.OperationID,
		[]byte(`{"payload":"does-not-contain-the-operation-id"}`)); err != nil {
		t.Fatalf("mark transparency intent delivered: %v", err)
	}

	rows, err := s.ListCodeSigningIdentities(ctx, tenantA, "transparency.rekor", 10)
	if err != nil {
		t.Fatalf("list code-signing identities: %v", err)
	}
	if len(rows) != 1 || rows[0].OperationID != op.OperationID || rows[0].Mode != "managed" || rows[0].Transparency != "verified" {
		t.Fatalf("code-signing history = %+v, want managed public mode joined to its delivered Rekor intent", rows)
	}
}

func TestCodeSigningIntentConsumesExactApprovalInOperationOutboxTransaction(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	const (
		requestID    = "8bfcf6f1-a05c-4b38-97c0-ec959631c754"
		decisionID   = "c6cc8f37-578b-4502-b81a-8c9b98e624df"
		commandEvent = "f4441395-8963-5a9d-91d1-41fdf57a8e23"
		requestHash  = "5c87767f674107a10f277690a7d8e3bf8b48841b13aeca5ef0b1b563775d473d"
		requestKey   = "codesign-exact-approval"
	)
	resourceID := store.CodeSigningApprovalResourceID(requestHash, requestKey)
	operationID := store.CodeSigningOperationID(tenantA, requestKey)
	keyRef := store.CodeSigningIdempotencyKeyRef(requestKey)
	request := store.OperationApprovalRequest{
		ID: requestID, TenantID: tenantA, IntentDigest: "sha256:" + strings.Repeat("a", 64),
		ResourceKind: "code_signing", ResourceID: resourceID,
		ResourceName: "release-key", Action: "sign", Requester: "release-bot",
		EvidenceRefs: []string{"request-sha256:" + requestHash}, RequiredApprovals: 1,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), UpdatedAt: now,
	}
	use := store.OperationApprovalUse{
		RequestID: request.ID, IntentDigest: request.IntentDigest,
		Requester: request.Requester, ResourceKind: request.ResourceKind,
		ResourceID: request.ResourceID, Action: request.Action,
		TargetVersion: request.TargetVersion, RequiredApprovals: request.RequiredApprovals,
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := s.ApplyOperationApprovalRequestedTx(ctx, tx, request); err != nil {
			return err
		}
		return s.ApplyOperationApprovalDecisionTx(ctx, tx, store.OperationApprovalDecision{
			TenantID: tenantA, RequestID: request.ID, IntentDigest: request.IntentDigest,
			Approver: "security-approver", Decision: store.ApprovalDecisionApprove,
			EventID: decisionID, DecidedAt: now.Add(time.Minute),
		})
	}); err != nil {
		t.Fatalf("seed approved code-signing request: %v", err)
	}

	op := store.CodeSigningOperation{
		TenantID: tenantA, OperationID: operationID,
		IdempotencyKey: keyRef, Mode: "key", RequestHash: requestHash,
		SealedCommand: []byte("sealed-command"), CreatedAt: now.Add(2 * time.Minute),
		UpdatedAt: now.Add(2 * time.Minute), Approval: &use, SourceEventID: commandEvent,
		SemanticDigest: strings.Repeat("c", 64),
	}
	drifted := op
	drifted.RequestHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyCodeSigningIntentTx(ctx, tx, drifted,
			[]byte(`{"operation_id":"`+operationID+`"}`))
	}); !errors.Is(err, store.ErrApprovalDrifted) {
		t.Fatalf("drifted approval binding = %v, want ErrApprovalDrifted", err)
	}
	assertCodeSigningIntentCounts(t, s, requestID, op.OperationID, 0, 0, store.ApprovalStatusApproved, "")

	commandPayload := []byte(`{"operation_id":"` + operationID + `"}`)
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyCodeSigningIntentTx(ctx, tx, op, commandPayload)
	}); err != nil {
		t.Fatalf("apply approved code-signing intent: %v", err)
	}
	assertCodeSigningIntentCounts(t, s, requestID, op.OperationID, 1, 1, store.ApprovalStatusConsumed, commandEvent)

	// The ordered projector may see the same immutable event again. That replay
	// heals/checks the same outbox row and does not spend authority twice.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyCodeSigningIntentTx(ctx, tx, op, commandPayload)
	}); err != nil {
		t.Fatalf("replay approved code-signing event: %v", err)
	}
	assertCodeSigningIntentCounts(t, s, requestID, op.OperationID, 1, 1, store.ApprovalStatusConsumed, commandEvent)

	// A retained event can reuse the same API Idempotency-Key while carrying a
	// different immutable command and a different, still-valid approval. The
	// first operation remains authoritative, and the colliding event must fail
	// before it consumes B's otherwise usable grant.
	conflictingHash := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	conflictingRequest := store.OperationApprovalRequest{
		ID: "f1a6773b-4f13-44e6-89db-70faef0fd6a1", TenantID: tenantA,
		IntentDigest: "sha256:" + strings.Repeat("b", 64), ResourceKind: "code_signing",
		ResourceID:   store.CodeSigningApprovalResourceID(conflictingHash, requestKey),
		ResourceName: "other-release-key", Action: "sign", Requester: "other-release-bot",
		EvidenceRefs: []string{"request-sha256:" + conflictingHash}, RequiredApprovals: 1,
		CreatedAt: now.Add(3 * time.Minute), ExpiresAt: now.Add(time.Hour), UpdatedAt: now.Add(3 * time.Minute),
	}
	conflictingUse := store.OperationApprovalUse{
		RequestID: conflictingRequest.ID, IntentDigest: conflictingRequest.IntentDigest,
		Requester: conflictingRequest.Requester, ResourceKind: conflictingRequest.ResourceKind,
		ResourceID: conflictingRequest.ResourceID, Action: conflictingRequest.Action,
		TargetVersion: conflictingRequest.TargetVersion, RequiredApprovals: conflictingRequest.RequiredApprovals,
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := s.ApplyOperationApprovalRequestedTx(ctx, tx, conflictingRequest); err != nil {
			return err
		}
		return s.ApplyOperationApprovalDecisionTx(ctx, tx, store.OperationApprovalDecision{
			TenantID: tenantA, RequestID: conflictingRequest.ID, IntentDigest: conflictingRequest.IntentDigest,
			Approver: "other-security-approver", Decision: store.ApprovalDecisionApprove,
			EventID: "b7a70be9-39d3-4d96-a486-77e38eaf04e0", DecidedAt: now.Add(4 * time.Minute),
		})
	}); err != nil {
		t.Fatalf("seed conflicting approved code-signing request: %v", err)
	}
	conflictingOperation := store.CodeSigningOperation{
		TenantID: tenantA, OperationID: "codesign-conflicting-operation", IdempotencyKey: keyRef,
		Mode: "keyless", RequestHash: conflictingHash, SealedCommand: []byte("different-sealed-command"),
		CreatedAt: now.Add(5 * time.Minute), UpdatedAt: now.Add(5 * time.Minute),
		Approval: &conflictingUse, SourceEventID: "ca6e2503-c899-513c-a681-128f372a50f0",
		SemanticDigest: strings.Repeat("d", 64),
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyCodeSigningIntentTx(ctx, tx, conflictingOperation,
			[]byte(`{"operation_id":"codesign-conflicting-operation"}`))
	}); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("same-key conflicting code-signing event = %v, want ErrIdempotencyConflict", err)
	}
	assertCodeSigningIntentCounts(t, s, conflictingRequest.ID, conflictingOperation.OperationID,
		0, 0, store.ApprovalStatusApproved, "")
	assertCodeSigningIntentCounts(t, s, requestID, op.OperationID,
		1, 1, store.ApprovalStatusConsumed, commandEvent)

	// A different target event cannot reuse the first command's idempotency
	// identity. The command collision is detected before the already-consumed
	// capability is consulted; either fence is fail-closed, and the original
	// operation/external-call intent remain unchanged.
	reuse := op
	reuse.SourceEventID = "ea52f7d0-6888-57a8-9c46-563020570367"
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyCodeSigningIntentTx(ctx, tx, reuse, commandPayload)
	}); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed source event under the same command identity = %v, want ErrIdempotencyConflict", err)
	}
	assertCodeSigningIntentCounts(t, s, requestID, op.OperationID, 1, 1, store.ApprovalStatusConsumed, commandEvent)
}

func assertCodeSigningIntentCounts(t *testing.T, s *store.Store, requestID, operationID string, operations, commands int, status, consumedEvent string) {
	t.Helper()
	ctx := context.Background()
	var operationRows, commandRows int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM code_signing_operations WHERE tenant_id = $1 AND operation_id = $2`,
		tenantA, operationID).Scan(&operationRows); err != nil {
		t.Fatal(err)
	}
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2 AND idempotency_key = $3`,
		tenantA, store.CodeSigningCommandDestination, "codesign.command:"+operationID).Scan(&commandRows); err != nil {
		t.Fatal(err)
	}
	if operationRows != operations || commandRows != commands {
		t.Fatalf("code-signing operation/outbox counts = %d/%d, want %d/%d",
			operationRows, commandRows, operations, commands)
	}
	approval, err := s.GetOperationApproval(ctx, tenantA, requestID)
	if err != nil {
		t.Fatal(err)
	}
	if approval.Status != status || approval.ConsumedEventID != consumedEvent {
		t.Fatalf("approval state = %q/%q, want %q/%q", approval.Status,
			approval.ConsumedEventID, status, consumedEvent)
	}
}
