// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func resetSecretIntegrationTables(t *testing.T, s *store.Store) {
	t.Helper()
	if _, err := s.SystemPool().Exec(context.Background(),
		`TRUNCATE dynamic_secret_operations, dynamic_secret_leases, secret_sync_jobs`); err != nil {
		t.Fatalf("truncate secret integration projections: %v", err)
	}
}

func TestSecretSyncEventOnlyRecoveryFenceIsDurableAndNotApplicationWritableAUD109(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.AuthorizeSecretSyncReceiverRecovery(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.FenceSecretSyncReceiverRecovery(ctx, "event_only_restore_test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.AuthorizeSecretSyncReceiverRecovery(context.Background()); err != nil {
			t.Errorf("restore secret-sync recovery authority after test: %v", err)
		}
	})
	if err := s.RequireSecretSyncReceiverRecoveryAuthorized(ctx); !errors.Is(err, store.ErrSecretSyncReceiverRecoveryFenced) {
		t.Fatalf("fenced recovery authority = %v, want durable receiver refusal", err)
	}

	// WithTenant runs as trstctl_app. A forged tenant GUC therefore cannot turn
	// the deployment-wide restore light green or even read its non-tenant row.
	err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE secret_sync_recovery_authority
			   SET receiver_io_authorized = true, reason = ''
			 WHERE singleton`)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("application-role recovery-authority update = %v, want permission refusal", err)
	}
	if err := s.RequireSecretSyncReceiverRecoveryAuthorized(ctx); !errors.Is(err, store.ErrSecretSyncReceiverRecoveryFenced) {
		t.Fatalf("application-role attempt changed recovery fence: %v", err)
	}

	// The light is a PostgreSQL fact, not process memory. A separately opened
	// Store sees the same red state after the original caller could have crashed.
	reopened, err := store.Open(ctx, testDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.RequireSecretSyncReceiverRecoveryAuthorized(ctx); !errors.Is(err, store.ErrSecretSyncReceiverRecoveryFenced) {
		t.Fatalf("reopened store recovery authority = %v, want durable receiver refusal", err)
	}
}

func TestDynamicSecretOperationClaimIsConcurrentExactAndRejectsDrift(t *testing.T) {
	s := newStore(t)
	resetSecretIntegrationTables(t, s)
	seedTwoTenants(t, s)
	ctx := context.Background()
	now := time.Date(2026, 7, 11, 18, 0, 0, 0, time.UTC)
	op := store.DynamicSecretOperation{
		TenantID: tenantA, OperationID: "dynsecret-op-concurrent", IdempotencyKey: "same-raw-key",
		RequestBinding: "sha256:principal-a-renew-lease-a-60", Action: "renew", LeaseID: "lease-a",
		Response:  []byte(`{"lease_id":"lease-a","state":"active","expires_at":"2026-07-11T19:00:00Z"}`),
		CreatedAt: now, UpdatedAt: now,
	}
	apply := func(candidate store.DynamicSecretOperation) error {
		return s.WithTenant(ctx, candidate.TenantID, func(tx pgx.Tx) error {
			return s.ApplyDynamicSecretOperationRequestedTx(ctx, tx, candidate)
		})
	}

	const callers = 12
	errs := make(chan error, callers)
	var start sync.WaitGroup
	start.Add(1)
	for range callers {
		go func() {
			start.Wait()
			errs <- apply(op)
		}()
	}
	start.Done()
	for range callers {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent exact operation claim: %v", err)
		}
	}
	stored, err := s.GetDynamicSecretOperationByIdempotencyKey(ctx, tenantA, op.IdempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	if stored.OperationID != op.OperationID || stored.RequestBinding != op.RequestBinding || stored.Status != store.DynamicSecretOperationPending {
		t.Fatalf("canonical operation = %+v", stored)
	}
	var rows int
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM dynamic_secret_operations WHERE tenant_id = $1 AND idempotency_key = $2`,
			tenantA, op.IdempotencyKey).Scan(&rows)
	}); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("concurrent operation rows=%d, want one", rows)
	}

	for name, mutate := range map[string]func(*store.DynamicSecretOperation){
		"caller": func(candidate *store.DynamicSecretOperation) {
			candidate.RequestBinding = "sha256:principal-b-renew-lease-a-60"
		},
		"action": func(candidate *store.DynamicSecretOperation) { candidate.Action = "revoke" },
		"lease":  func(candidate *store.DynamicSecretOperation) { candidate.LeaseID = "lease-b" },
		"result": func(candidate *store.DynamicSecretOperation) {
			candidate.Response = []byte(`{"lease_id":"lease-a","state":"active","expires_at":"2026-07-11T20:00:00Z"}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := op
			mutate(&candidate)
			if err := apply(candidate); !errors.Is(err, store.ErrIdempotencyConflict) {
				t.Fatalf("drift error=%v, want ErrIdempotencyConflict", err)
			}
		})
	}

	otherTenant := op
	otherTenant.TenantID = tenantB
	otherTenant.OperationID = "tenant-b-only-operation"
	if err := apply(otherTenant); err != nil {
		t.Fatalf("same raw key in another tenant: %v", err)
	}
	if _, err := s.GetDynamicSecretOperation(ctx, tenantA, "tenant-b-only-operation"); !store.IsNotFound(err) {
		t.Fatalf("tenant A operation isolation err=%v, want not found", err)
	}
}

func projectPendingDynamicSecretLease(t *testing.T, s *store.Store, tenantID string, lease store.DynamicSecretLease) {
	t.Helper()
	err := s.WithTenant(context.Background(), tenantID, func(tx pgx.Tx) error {
		return s.ApplyDynamicSecretLeasePendingTx(context.Background(), tx, lease)
	})
	if err != nil {
		t.Fatalf("ApplyDynamicSecretLeasePendingTx(%s/%s): %v", tenantID, lease.ID, err)
	}
}

func projectIssuedDynamicSecretLease(t *testing.T, s *store.Store, tenantID string, lease store.DynamicSecretLease) {
	t.Helper()
	err := s.WithTenant(context.Background(), tenantID, func(tx pgx.Tx) error {
		return s.ApplyDynamicSecretLeaseIssuedTx(context.Background(), tx, lease)
	})
	if err != nil {
		t.Fatalf("ApplyDynamicSecretLeaseIssuedTx(%s/%s): %v", tenantID, lease.ID, err)
	}
}

func projectDynamicSecretLease(t *testing.T, s *store.Store, tenantID string, lease store.DynamicSecretLease) {
	t.Helper()
	projectPendingDynamicSecretLease(t, s, tenantID, lease)
	projectIssuedDynamicSecretLease(t, s, tenantID, lease)
}

func projectSecretSyncJob(t *testing.T, s *store.Store, tenantID string, job store.SecretSyncJob) {
	t.Helper()
	if job.TenantEpoch == "" {
		epoch, err := s.ApplicationSecretTenantEpoch(context.Background(), tenantID)
		if err != nil {
			t.Fatalf("resolve secret-sync tenant epoch: %v", err)
		}
		job.TenantEpoch = epoch
	}
	if job.TargetOrder == 0 {
		job.TargetOrder = job.OutboxID
	}
	err := s.WithTenant(context.Background(), tenantID, func(tx pgx.Tx) error {
		return s.ApplySecretSyncJobQueuedTx(context.Background(), tx, job)
	})
	if err != nil {
		t.Fatalf("ApplySecretSyncJobQueuedTx(%s/%s): %v", tenantID, job.ID, err)
	}
}

func mustSecretSyncTenantEpoch(t *testing.T, s *store.Store, tenantID string) string {
	t.Helper()
	epoch, err := s.ApplicationSecretTenantEpoch(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("resolve secret-sync tenant epoch: %v", err)
	}
	return epoch
}

func applySecretSyncIntentFixture(t *testing.T, s *store.Store, job store.SecretSyncJob, payload []byte) store.SecretSyncJob {
	t.Helper()
	ctx := context.Background()
	if job.TenantEpoch == "" {
		epoch, err := s.ApplicationSecretTenantEpoch(ctx, job.TenantID)
		if err != nil {
			t.Fatalf("resolve secret-sync tenant epoch: %v", err)
		}
		job.TenantEpoch = epoch
	}
	if err := s.WithTenant(ctx, job.TenantID, func(tx pgx.Tx) error {
		return s.ApplySecretSyncIntentTx(ctx, tx, job, "secret.sync."+job.Target, payload)
	}); err != nil {
		t.Fatalf("ApplySecretSyncIntentTx(%s/%s): %v", job.TenantID, job.ID, err)
	}
	got, err := s.GetSecretSyncJob(ctx, job.TenantID, job.ID)
	if err != nil {
		t.Fatalf("GetSecretSyncJob(%s/%s): %v", job.TenantID, job.ID, err)
	}
	return got
}

func applySecretSyncTerminalFixture(
	t *testing.T,
	s *store.Store,
	tenantID, jobID string,
	status store.SecretSyncJobStatus,
	attempts int,
	remoteVersion, lastError string,
	at time.Time,
) error {
	t.Helper()
	job, err := s.GetSecretSyncJob(context.Background(), tenantID, jobID)
	if err != nil {
		return err
	}
	eventType := "secret.sync.delivered"
	eventID := store.SecretSyncDeliveredEventID(tenantID, jobID)
	if status == store.SecretSyncJobFailed {
		eventType = "secret.sync.failed"
		eventID = store.SecretSyncFailedEventID(tenantID, jobID)
	}
	return s.WithTenantProjection(context.Background(), tenantID, func(tx pgx.Tx) error {
		return s.ApplySecretSyncTerminalEventTx(context.Background(), tx, store.SecretSyncTerminalEvent{
			TenantID: tenantID, TenantEpoch: job.TenantEpoch, JobID: jobID,
			Status: status, Attempts: attempts, RemoteVersion: remoteVersion, LastError: lastError,
			OccurredAt: at, EventID: eventID, EventType: eventType,
			EventSequence: job.TargetOrder + 1000000, PayloadDigest: strings.Repeat("a", 64),
			FailureDefinitelyNoEffect: status == store.SecretSyncJobFailed,
		})
	})
}

func TestSecretSyncOlderNonterminalFenceUsesOutboxOrderAndTenantTargetScope(t *testing.T) {
	s := newStore(t)
	resetSecretIntegrationTables(t, s)
	seedTwoTenants(t, s)
	ctx := context.Background()
	base := time.Date(2026, 8, 10, 13, 0, 0, 0, time.UTC)
	nextOrder := int64(100)
	enqueue := func(tenantID, id, remoteKey string, requestedAt time.Time) store.SecretSyncJob {
		order := nextOrder
		nextOrder++
		job := store.SecretSyncJob{
			ID: id, TenantID: tenantID, SecretName: "production/database",
			SecretVersion: 1, Target: "github-actions", RemoteKey: remoteKey,
			ValueDigest: strings.Repeat("b", 64), IdempotencyKey: "secret.sync.github-actions:" + id,
			TargetOrder: order,
			RequestedAt: requestedAt, UpdatedAt: requestedAt,
		}
		payload := []byte(fmt.Sprintf(`{"id":%q,"key":%q,"target":"github-actions","sealed":"c2VhbGVk"}`, id, remoteKey))
		return applySecretSyncIntentFixture(t, s, job, payload)
	}

	// Timestamps deliberately disagree with AN-2 event order. The immutable event
	// sequence, not a mutable clock field or outbox id, defines which is older.
	older := enqueue(tenantA, "sync-order-older", "DATABASE_URL", base.Add(time.Hour))
	newer := enqueue(tenantA, "sync-order-newer", "DATABASE_URL", base)
	unrelatedKey := enqueue(tenantA, "sync-order-unrelated", "ANOTHER_URL", base)
	otherTenant := enqueue(tenantB, "sync-order-other-tenant", "DATABASE_URL", base)
	if older.TargetOrder <= 0 || older.TargetOrder >= newer.TargetOrder {
		t.Fatalf("fixture target order older=%d newer=%d", older.TargetOrder, newer.TargetOrder)
	}

	assertBlocked := func(job store.SecretSyncJob, want bool) {
		t.Helper()
		got, err := s.SecretSyncHasOlderNonterminal(ctx, job.TenantID, job.Target, job.OutboxID)
		if err != nil || got != want {
			t.Fatalf("older nonterminal fence for %s=(%t,%v), want %t", job.ID, got, err, want)
		}
	}
	assertBlocked(newer, true)
	assertBlocked(unrelatedKey, true)
	assertBlocked(otherTenant, false)

	// A far-future retry remains a barrier, and an actively leased row remains a
	// barrier too. Neither state permits a newer value to overtake it.
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE outbox SET next_attempt_at = $3 WHERE tenant_id = $1 AND id = $2`,
		tenantA, older.OutboxID, base.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	assertBlocked(newer, true)
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE projection_checkpoint SET applied_seq = $1, updated_at = now() WHERE id = 1`,
		nextOrder); err != nil {
		t.Fatal(err)
	}
	if tag, err := s.SystemPool().Exec(ctx,
		`UPDATE outbox SET status = 'processing', worker_id = 'older-worker', lease_until = $3
		  WHERE tenant_id = $1 AND id = $2`,
		tenantA, older.OutboxID, base.Add(time.Hour)); err != nil {
		t.Fatal(err)
	} else if tag.RowsAffected() != 1 {
		t.Fatalf("claim older secret-sync fixture rows=%d, want 1", tag.RowsAffected())
	}
	assertBlocked(newer, true)

	if err := applySecretSyncTerminalFixture(t, s, tenantA, older.ID, store.SecretSyncJobFailed,
		1, "", "terminal fixture", base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE outbox
		    SET status = 'failed', worker_id = NULL, lease_until = NULL
		  WHERE tenant_id = $1 AND id = $2`, tenantA, older.OutboxID); err != nil {
		t.Fatal(err)
	}
	assertBlocked(newer, false)
	deleteTx, err := s.SystemPool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deleteTx.Exec(ctx,
		`DELETE FROM outbox WHERE tenant_id = $1 AND id = $2`, tenantA, older.OutboxID); err != nil {
		_ = deleteTx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := deleteTx.Commit(ctx); err == nil {
		t.Fatal("failed secret-sync outbox deletion erased retained FIFO/history evidence")
	}
	for _, changedStatus := range []string{"pending", "processing", "delivered"} {
		if _, err := s.SystemPool().Exec(ctx,
			`UPDATE outbox SET status = $3 WHERE tenant_id = $1 AND id = $2`,
			tenantA, older.OutboxID, changedStatus); err == nil {
			t.Fatalf("terminal secret-sync outbox status change to %s was accepted", changedStatus)
		}
	}
}

func TestSecretSyncJobDirectDeleteCannotEraseActiveFIFOBarrierAUD109(t *testing.T) {
	s := newStore(t)
	resetSecretIntegrationTables(t, s)
	seedTwoTenants(t, s)
	ctx := context.Background()
	job := applySecretSyncIntentFixture(t, s, store.SecretSyncJob{
		ID: "sync-delete-attack", TenantID: tenantA, SecretName: "production/database",
		SecretVersion: 1, Target: "github-actions", RemoteKey: "DATABASE_URL",
		ValueDigest: strings.Repeat("e", 64), IdempotencyKey: "secret.sync.github-actions:sync-delete-attack",
		TargetOrder: 109, RequestedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}, []byte(`{"id":"sync-delete-attack","key":"DATABASE_URL","target":"github-actions","sealed":"c2VhbGVk"}`))

	attempt := func(name string, appRole bool) {
		t.Helper()
		tx, err := s.SystemPool().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if appRole {
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE trstctl_app`); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id', $1, true)`, tenantA); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal(err)
			}
		}
		_, deleteErr := tx.Exec(ctx, `DELETE FROM secret_sync_jobs WHERE tenant_id = $1 AND id = $2`, tenantA, job.ID)
		if deleteErr == nil {
			deleteErr = tx.Commit(ctx)
		} else {
			_ = tx.Rollback(ctx)
		}
		if deleteErr == nil {
			t.Fatalf("%s direct job delete committed and erased the FIFO barrier", name)
		}
		if _, err := s.GetSecretSyncJob(ctx, tenantA, job.ID); err != nil {
			t.Fatalf("%s delete attack removed job despite rejection: %v", name, err)
		}
		var retainedOutbox int
		if err := s.SystemPool().QueryRow(ctx,
			`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND id = $2`,
			tenantA, job.OutboxID).Scan(&retainedOutbox); err != nil {
			t.Fatal(err)
		}
		if retainedOutbox != 1 {
			t.Fatalf("%s delete attack changed predecessor outbox count=%d, want one", name, retainedOutbox)
		}
	}
	attempt("owner", false)
	attempt("application role", true)
}

func TestSecretSyncEventOrderDoesNotDependOnDatabaseCommitSerialization(t *testing.T) {
	s := newStore(t)
	resetSecretIntegrationTables(t, s)
	seedTwoTenants(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	now := time.Date(2026, 8, 10, 14, 0, 0, 0, time.UTC)
	command := func(tenantID, id, target, remoteKey string, targetOrder int64) (store.SecretSyncJob, []byte) {
		job := store.SecretSyncJob{
			ID: id, TenantID: tenantID, TenantEpoch: mustSecretSyncTenantEpoch(t, s, tenantID), SecretName: "production/database",
			SecretVersion: 1, Target: target, RemoteKey: remoteKey,
			ValueDigest: strings.Repeat("c", 64), IdempotencyKey: "secret.sync." + target + ":" + id,
			TargetOrder: targetOrder,
			RequestedAt: now, UpdatedAt: now,
		}
		payload := []byte(fmt.Sprintf(`{"id":%q,"key":%q,"target":%q,"sealed":"c2VhbGVk"}`, id, remoteKey, target))
		return job, payload
	}
	first, firstPayload := command(tenantA, "sync-serialized-first", "github-actions", "DATABASE_URL", 200)
	second, secondPayload := command(tenantA, "sync-serialized-second", "github-actions", "ANOTHER_URL", 201)
	unrelated, unrelatedPayload := command(tenantA, "sync-serialized-unrelated", "gitlab-ci", "DATABASE_URL", 202)
	otherTenant, otherTenantPayload := command(tenantB, "sync-serialized-other-tenant", "github-actions", "DATABASE_URL", 200)

	firstReady := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			if err := s.ApplySecretSyncIntentTx(ctx, tx, first, "secret.sync.github-actions", firstPayload); err != nil {
				return err
			}
			close(firstReady)
			select {
			case <-releaseFirst:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-firstReady:
	case <-ctx.Done():
		t.Fatalf("first receiver-order transaction did not reach hold point: %v", ctx.Err())
	}

	secondDone := make(chan error, 1)
	go func() {
		secondDone <- s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplySecretSyncIntentTx(ctx, tx, second, "secret.sync.github-actions", secondPayload)
		})
	}()
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("commit same-target successor first: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("same-target successor incorrectly waited for DB commit order: %v", ctx.Err())
	}

	// Event order is data, not a target-wide transaction lock. Different targets
	// and tenants remain independent too.
	for _, candidate := range []struct {
		job     store.SecretSyncJob
		payload []byte
	}{{unrelated, unrelatedPayload}, {otherTenant, otherTenantPayload}} {
		if err := s.WithTenant(ctx, candidate.job.TenantID, func(tx pgx.Tx) error {
			return s.ApplySecretSyncIntentTx(ctx, tx, candidate.job, "secret.sync."+candidate.job.Target, candidate.payload)
		}); err != nil {
			t.Fatalf("independent receiver scope was blocked: %v", err)
		}
	}

	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatalf("commit first receiver command: %v", err)
	}
	firstStored, err := s.GetSecretSyncJob(ctx, tenantA, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	secondStored, err := s.GetSecretSyncJob(ctx, tenantA, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if firstStored.TargetOrder <= 0 || firstStored.TargetOrder >= secondStored.TargetOrder {
		t.Fatalf("immutable event target order first=%d second=%d", firstStored.TargetOrder, secondStored.TargetOrder)
	}
}

// The live projection tail and a replay can project the same immutable event at
// the same instant. Both transactions must converge on one outbox row and the
// same outbox id; READ COMMITTED NOT EXISTS alone permits two inserts.
func TestSecretIntegrationOutboxIsAtomicAcrossConcurrentTransactions(t *testing.T) {
	s := newStore(t)
	resetSecretIntegrationTables(t, s)
	seedTwoTenants(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	now := time.Date(2026, 7, 11, 15, 0, 0, 0, time.UTC)
	job := store.SecretSyncJob{
		ID:             "sync-concurrent",
		TenantID:       tenantA,
		TenantEpoch:    mustSecretSyncTenantEpoch(t, s, tenantA),
		SecretName:     "production/database",
		SecretVersion:  9,
		Target:         "github-actions",
		RemoteKey:      "DATABASE_URL",
		ValueDigest:    strings.Repeat("c", 64),
		IdempotencyKey: "sync-concurrent-key",
		TargetOrder:    300,
		RequestedAt:    now,
		UpdatedAt:      now,
	}
	payload := []byte(`{"id":"sync-concurrent","key":"DATABASE_URL","target":"github-actions","sealed":"c2VhbGVkLXN5bmMtY29tbWFuZA=="}`)

	const workers = 2
	ready := make(chan struct{}, workers)
	release := make(chan struct{})
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			errs <- s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
				ready <- struct{}{}
				<-release
				return s.ApplySecretSyncIntentTx(ctx, tx, job, "secret.sync.github-actions", payload)
			})
		}()
	}
	for range workers {
		<-ready
	}
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent secret-sync projection: %v", err)
		}
	}

	var rows int
	var minID, maxID int64
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*), COALESCE(min(id), 0), COALESCE(max(id), 0)
		   FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantA, job.IdempotencyKey).Scan(&rows, &minID, &maxID); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || minID != maxID || minID == 0 {
		t.Fatalf("outbox rows=%d ids=%d..%d, want one shared non-zero id", rows, minID, maxID)
	}
	var projectedOutboxID int64
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT outbox_id FROM secret_sync_jobs WHERE tenant_id = $1 AND id = $2`,
			tenantA, job.ID).Scan(&projectedOutboxID)
	}); err != nil {
		t.Fatal(err)
	}
	if projectedOutboxID != minID {
		t.Fatalf("projected outbox id=%d, durable shared id=%d", projectedOutboxID, minID)
	}
}

func TestSecretSyncIntentRejectsConcurrentChangedCommandWithoutSecondOutbox(t *testing.T) {
	s := newStore(t)
	resetSecretIntegrationTables(t, s)
	seedTwoTenants(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	now := time.Date(2026, 7, 11, 16, 0, 0, 0, time.UTC)
	first := store.SecretSyncJob{
		ID: "sync-collision", TenantID: tenantA, TenantEpoch: mustSecretSyncTenantEpoch(t, s, tenantA), SecretName: "production/database",
		SecretVersion: 4, Target: "github-actions", RemoteKey: "DATABASE_URL",
		ValueDigest: strings.Repeat("a", 64), IdempotencyKey: "secret.sync.github-actions:raw-collision",
		TargetOrder: 400,
		RequestedAt: now, UpdatedAt: now,
	}
	changed := first
	changed.Target = "gitlab-ci"
	changed.RemoteKey = "CHANGED_DATABASE_URL"
	changed.ValueDigest = strings.Repeat("b", 64)
	changed.IdempotencyKey = "secret.sync.gitlab-ci:raw-collision"
	changed.TargetOrder = 401
	firstPayload := []byte(`{"id":"sync-collision","key":"DATABASE_URL","target":"github-actions","sealed":"Zmlyc3QtY2lwaGVydGV4dA=="}`)
	changedPayload := []byte(`{"id":"sync-collision","key":"CHANGED_DATABASE_URL","target":"gitlab-ci","sealed":"Y2hhbmdlZC1jaXBoZXJ0ZXh0"}`)

	type attempt struct {
		job         store.SecretSyncJob
		destination string
		payload     []byte
	}
	attempts := []attempt{
		{job: first, destination: "secret.sync.github-actions", payload: firstPayload},
		{job: changed, destination: "secret.sync.gitlab-ci", payload: changedPayload},
	}
	ready := make(chan struct{}, len(attempts))
	release := make(chan struct{})
	errs := make(chan error, len(attempts))
	for _, candidate := range attempts {
		candidate := candidate
		go func() {
			errs <- s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
				ready <- struct{}{}
				<-release
				return s.ApplySecretSyncIntentTx(ctx, tx, candidate.job, candidate.destination, candidate.payload)
			})
		}()
	}
	for range attempts {
		<-ready
	}
	close(release)
	var succeeded, conflicted int
	for range attempts {
		err := <-errs
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, store.ErrIdempotencyConflict):
			conflicted++
		default:
			t.Fatalf("concurrent secret-sync collision: %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("secret-sync attempts succeeded=%d conflicted=%d, want 1/1", succeeded, conflicted)
	}

	var jobs, outboxes int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT (SELECT count(*) FROM secret_sync_jobs WHERE tenant_id = $1 AND id = $2),
		        (SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key IN ($3, $4))`,
		tenantA, first.ID, first.IdempotencyKey, changed.IdempotencyKey).Scan(&jobs, &outboxes); err != nil {
		t.Fatal(err)
	}
	if jobs != 1 || outboxes != 1 {
		t.Fatalf("durable collision rows jobs=%d outboxes=%d, want exactly one matching pair", jobs, outboxes)
	}
}

func TestSecretSyncIntentExactReplayKeepsOriginalPayloadAndRejectsDrift(t *testing.T) {
	s := newStore(t)
	resetSecretIntegrationTables(t, s)
	seedTwoTenants(t, s)
	ctx := context.Background()
	now := time.Date(2026, 7, 11, 17, 0, 0, 0, time.UTC)
	job := store.SecretSyncJob{
		ID: "sync-replay-binding", TenantID: tenantA, TenantEpoch: mustSecretSyncTenantEpoch(t, s, tenantA), SecretName: "production/api",
		SecretVersion: 8, Target: "github-actions", RemoteKey: "API_TOKEN",
		ValueDigest: strings.Repeat("d", 64), IdempotencyKey: "secret.sync.github-actions:replay-binding",
		TargetOrder: 500,
		RequestedAt: now, UpdatedAt: now,
	}
	firstPayload := []byte(`{"id":"sync-replay-binding","key":"API_TOKEN","target":"github-actions","sealed":"Zmlyc3QtY2lwaGVydGV4dA=="}`)
	resealedPayload := []byte(`{"id":"sync-replay-binding","key":"API_TOKEN","target":"github-actions","sealed":"c2FtZS1jb21tYW5kLW5ldy1ub25jZQ=="}`)
	apply := func(candidate store.SecretSyncJob, payload []byte) error {
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplySecretSyncIntentTx(ctx, tx, candidate, "secret.sync.github-actions", payload)
		})
	}
	if err := apply(job, firstPayload); err != nil {
		t.Fatalf("first secret-sync intent: %v", err)
	}
	if err := apply(job, resealedPayload); err != nil {
		t.Fatalf("same command with a fresh envelope nonce: %v", err)
	}

	drift := job
	drift.SecretVersion++
	drift.ValueDigest = strings.Repeat("e", 64)
	if err := apply(drift, resealedPayload); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed source version/digest error = %v, want ErrIdempotencyConflict", err)
	}

	var stored []byte
	var jobOutboxID, storedOutboxID int64
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`SELECT outbox_id FROM secret_sync_jobs WHERE tenant_id = $1 AND id = $2`,
			tenantA, job.ID).Scan(&jobOutboxID); err != nil {
			return err
		}
		return tx.QueryRow(ctx,
			`SELECT id, payload FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
			tenantA, job.IdempotencyKey).Scan(&storedOutboxID, &stored)
	}); err != nil {
		t.Fatal(err)
	}
	if jobOutboxID != storedOutboxID || !bytes.Equal(stored, firstPayload) {
		t.Fatalf("replay changed durable pair: job outbox=%d row=%d payload=%s", jobOutboxID, storedOutboxID, stored)
	}
}

func TestSecretSyncRebuildReattachIgnoresGenericOutboxKeyCollision(t *testing.T) {
	s := newStore(t)
	resetSecretIntegrationTables(t, s)
	seedTwoTenants(t, s)
	ctx := context.Background()
	epoch := mustSecretSyncTenantEpoch(t, s, tenantA)
	job := store.SecretSyncJob{
		ID: "sync-generic-key-collision", TenantID: tenantA, TenantEpoch: epoch,
		SecretName: "production/api", SecretVersion: 9, Target: "github-actions",
		RemoteKey: "API_TOKEN", ValueDigest: strings.Repeat("9", 64),
		IdempotencyKey: "shared-cross-subsystem-key", TargetOrder: 900,
		RequestedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	payload := []byte(`{"id":"sync-generic-key-collision","key":"API_TOKEN","target":"github-actions","sealed":"c2VhbGVk"}`)
	if _, err := s.SystemPool().Exec(ctx, `
		INSERT INTO outbox (tenant_id, destination, payload, idempotency_key)
		VALUES ($1, 'notification.email', '{}'::bytea, $2)`, tenantA, job.IdempotencyKey); err != nil {
		t.Fatal(err)
	}
	original := applySecretSyncIntentFixture(t, s, job, payload)
	if _, err := s.SystemPool().Exec(ctx, `TRUNCATE secret_sync_jobs`); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplySecretSyncIntentTx(ctx, tx, job, "secret.sync.github-actions", payload)
	}); err != nil {
		t.Fatalf("reattach with lower generic same-key row: %v", err)
	}
	rebuilt, err := s.GetSecretSyncJob(ctx, tenantA, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.OutboxID != original.OutboxID {
		t.Fatalf("reattached outbox id=%d, want exact secret-sync row %d", rebuilt.OutboxID, original.OutboxID)
	}
	var rows int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		tenantA, job.IdempotencyKey).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("same-key cross-subsystem outbox rows=%d, want generic + secret-sync", rows)
	}
}

func TestDynamicSecretLeaseProjectionIsRestartSafeAndTenantScoped(t *testing.T) {
	s := newStore(t)
	resetSecretIntegrationTables(t, s)
	seedTwoTenants(t, s)
	ctx := context.Background()
	issuedAt := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)

	leaseA := store.DynamicSecretLease{
		ID:               "lease-shared",
		TenantID:         tenantA,
		IdempotencyKey:   "lease-request-a-1",
		Provider:         "postgresql",
		Role:             "readonly",
		BackendRef:       "trstctl_a_lease_shared",
		SealedCredential: []byte("sealed-credential-a"),
		IssueOutboxID:    601,
		IssuedAt:         issuedAt,
		ExpiresAt:        issuedAt.Add(30 * time.Minute),
		HardExpiresAt:    issuedAt.Add(2 * time.Hour),
		UpdatedAt:        issuedAt,
	}
	leaseB := leaseA
	leaseB.TenantID = tenantB
	leaseB.IdempotencyKey = "lease-request-b-1"
	leaseB.Provider = "mysql"
	leaseB.BackendRef = "trstctl_b_lease_shared@%"

	// Pending is committed before the provider call. If the process dies after the
	// provider creates a deterministic lease id, a retry finds this row by the
	// tenant-scoped idempotency key and resumes instead of creating another id.
	projectPendingDynamicSecretLease(t, s, tenantA, leaseA)
	pendingLease, err := s.GetDynamicSecretLeaseByIdempotencyKey(ctx, tenantA, leaseA.IdempotencyKey)
	if err != nil {
		t.Fatalf("GetDynamicSecretLeaseByIdempotencyKey(pending): %v", err)
	}
	if pendingLease.ID != leaseA.ID || pendingLease.State != store.DynamicSecretLeasePending || pendingLease.BackendRef != "" {
		t.Fatalf("pending lease = %+v, want deterministic id with no backend result", pendingLease)
	}
	projectIssuedDynamicSecretLease(t, s, tenantA, leaseA)
	projectDynamicSecretLease(t, s, tenantB, leaseB)

	// A composite tenant/id key lets both tenants use the same public lease id,
	// while RLS still returns the correct tenant-owned row.
	gotA, err := s.GetDynamicSecretLease(ctx, tenantA, leaseA.ID)
	if err != nil {
		t.Fatalf("GetDynamicSecretLease(A): %v", err)
	}
	gotB, err := s.GetDynamicSecretLease(ctx, tenantB, leaseB.ID)
	if err != nil {
		t.Fatalf("GetDynamicSecretLease(B): %v", err)
	}
	if gotA.Provider != "postgresql" || gotB.Provider != "mysql" {
		t.Fatalf("tenant projections crossed: A=%+v B=%+v", gotA, gotB)
	}

	bOnly := leaseB
	bOnly.ID = "lease-b-only"
	bOnly.IdempotencyKey = "lease-request-b-2"
	bOnly.BackendRef = "trstctl_b_only@%"
	bOnly.SealedCredential = []byte("sealed-credential-b-only")
	bOnly.IssueOutboxID = 602
	projectDynamicSecretLease(t, s, tenantB, bOnly)
	if _, err := s.GetDynamicSecretLease(ctx, tenantA, bOnly.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("tenant A read tenant B lease: err=%v, want ErrNoRows", err)
	}
	if _, err := s.GetDynamicSecretLeaseByIdempotencyKey(ctx, tenantA, bOnly.IdempotencyKey); !store.IsNotFound(err) {
		t.Fatalf("tenant A resolved tenant B idempotency key: err=%v, want store.IsNotFound", err)
	}

	failed := leaseA
	failed.ID = "lease-failed"
	failed.IdempotencyKey = "lease-request-a-failed"
	failed.BackendRef = ""
	failed.SealedCredential = nil
	failed.IssueOutboxID = 603
	projectPendingDynamicSecretLease(t, s, tenantA, failed)
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyDynamicSecretLeaseIssuanceFailedTx(ctx, tx, tenantA, failed.ID, "provider denied role", issuedAt.Add(time.Second))
	}); err != nil {
		t.Fatalf("project issuance failure: %v", err)
	}
	failedGot, err := s.GetDynamicSecretLeaseByIdempotencyKey(ctx, tenantA, failed.IdempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	if failedGot.State != store.DynamicSecretLeaseFailed || failedGot.LastError == "" {
		t.Fatalf("failed issuance evidence = %+v", failedGot)
	}

	wrongRequest := failed
	wrongRequest.IdempotencyKey = "lease-request-a-wrong"
	wrongRequest.BackendRef = "must-not-activate"
	wrongRequest.SealedCredential = []byte("sealed-wrong-request")
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyDynamicSecretLeaseIssuedTx(ctx, tx, wrongRequest)
	})
	if !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("different idempotency key claimed pending lease: err=%v, want idempotency conflict", err)
	}

	// The expiry scheduler reads durable rows, so a process restart cannot lose a
	// lease that is now due.
	due, err := s.ListDueDynamicSecretLeases(ctx, tenantA, issuedAt.Add(31*time.Minute), 20)
	if err != nil {
		t.Fatalf("ListDueDynamicSecretLeases: %v", err)
	}
	if len(due) != 1 || due[0].ID != leaseA.ID {
		t.Fatalf("due leases = %+v, want only %s", due, leaseA.ID)
	}

	renewedExpiry := issuedAt.Add(90 * time.Minute)
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyDynamicSecretLeaseRenewedTx(ctx, tx, tenantA, leaseA.ID, renewedExpiry, issuedAt.Add(time.Minute))
	}); err != nil {
		t.Fatalf("renew lease: %v", err)
	}
	due, err = s.ListDueDynamicSecretLeases(ctx, tenantA, issuedAt.Add(31*time.Minute), 20)
	if err != nil {
		t.Fatalf("ListDueDynamicSecretLeases after renewal: %v", err)
	}
	if len(due) != 0 {
		t.Fatalf("renewed lease remained due: %+v", due)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyDynamicSecretLeaseRenewedTx(ctx, tx, tenantA, leaseA.ID,
			issuedAt.Add(45*time.Minute), issuedAt.Add(30*time.Second))
	}); err != nil {
		t.Fatalf("replay stale renewal: %v", err)
	}

	// Replaying the original issue event must not roll the renewal back.
	projectDynamicSecretLease(t, s, tenantA, leaseA)
	gotA, err = s.GetDynamicSecretLease(ctx, tenantA, leaseA.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !gotA.ExpiresAt.Equal(renewedExpiry) {
		t.Fatalf("duplicate issue regressed expiry to %s, want %s", gotA.ExpiresAt, renewedExpiry)
	}

	// The hard expiry is storage-enforced, so even a bad projection event cannot
	// extend this credential beyond the configured maximum lease lifetime.
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyDynamicSecretLeaseRenewedTx(ctx, tx, tenantA, leaseA.ID,
			issuedAt.Add(3*time.Hour), issuedAt.Add(2*time.Minute))
	})
	if err == nil {
		t.Fatal("renewal past hard_expires_at succeeded")
	}

	const revokeOutboxID int64 = 701
	revokedAt := issuedAt.Add(10 * time.Minute)
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyDynamicSecretLeaseRevocationRequestedTx(ctx, tx, tenantA, leaseA.ID, revokeOutboxID, revokedAt)
	}); err != nil {
		t.Fatalf("request revocation: %v", err)
	}
	completedAt := revokedAt.Add(time.Second)
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyDynamicSecretLeaseRevocationCompletedTx(ctx, tx, tenantA, leaseA.ID, completedAt)
	}); err != nil {
		t.Fatalf("complete revocation: %v", err)
	}
	// A duplicated stale failure event must not downgrade proof that the provider
	// credential was already deleted.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyDynamicSecretLeaseRevocationFailedTx(ctx, tx, tenantA, leaseA.ID, "stale timeout", completedAt.Add(time.Second))
	}); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("replay stale revocation failure error = %v, want idempotency conflict", err)
	}
	gotA, err = s.GetDynamicSecretLease(ctx, tenantA, leaseA.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotA.State != store.DynamicSecretLeaseRevoked || gotA.RevocationStatus != store.DynamicSecretRevocationCompleted {
		t.Fatalf("revocation state = %s/%s, want revoked/completed", gotA.State, gotA.RevocationStatus)
	}
	if gotA.RevokeOutboxID == nil || *gotA.RevokeOutboxID != revokeOutboxID {
		t.Fatalf("revoke outbox id = %v, want %d", gotA.RevokeOutboxID, revokeOutboxID)
	}

	list, err := s.ListDynamicSecretLeasesPage(ctx, tenantA, "postgresql", store.DynamicSecretLeaseRevoked, "", 20)
	if err != nil {
		t.Fatalf("ListDynamicSecretLeasesPage: %v", err)
	}
	if len(list) != 1 || list[0].ID != leaseA.ID {
		t.Fatalf("filtered lease list = %+v, want only %s", list, leaseA.ID)
	}

	// The epoch lookup is itself RLS-scoped, so tenant A cannot even acquire the
	// registration authority needed to reach tenant B's INSERT/WITH CHECK path.
	crossTenant := leaseA
	crossTenant.ID = "lease-cross-tenant"
	crossTenant.TenantID = tenantB
	crossTenant.IdempotencyKey = "lease-request-cross"
	crossTenant.IssueOutboxID = 604
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyDynamicSecretLeasePendingTx(ctx, tx, crossTenant)
	})
	if !errors.Is(err, store.ErrDynamicSecretTenantEpochMismatch) {
		t.Fatalf("cross-tenant lease projection err=%v, want lifecycle mismatch hidden by RLS", err)
	}
}

func TestSecretSyncJobProjectionTracksOutboxWithoutSecretMaterial(t *testing.T) {
	s := newStore(t)
	resetSecretIntegrationTables(t, s)
	seedTwoTenants(t, s)
	ctx := context.Background()
	requestedAt := time.Date(2026, 7, 11, 13, 0, 0, 0, time.UTC)

	jobA := store.SecretSyncJob{
		ID:             "sync-shared",
		TenantID:       tenantA,
		SecretName:     "production/database",
		SecretVersion:  7,
		Target:         "github-actions",
		RemoteKey:      "DATABASE_URL",
		ValueDigest:    strings.Repeat("a", 64),
		OutboxID:       801,
		IdempotencyKey: "sync-request-a-1",
		RequestedAt:    requestedAt,
		UpdatedAt:      requestedAt,
	}
	jobB := jobA
	jobB.TenantID = tenantB
	jobB.Target = "gitlab-ci"
	jobB.OutboxID = 901
	jobB.IdempotencyKey = "sync-request-b-1"
	projectSecretSyncJob(t, s, tenantA, jobA)
	projectSecretSyncJob(t, s, tenantB, jobB)

	gotA, err := s.GetSecretSyncJob(ctx, tenantA, jobA.ID)
	if err != nil {
		t.Fatalf("GetSecretSyncJob(A): %v", err)
	}
	gotB, err := s.GetSecretSyncJob(ctx, tenantB, jobB.ID)
	if err != nil {
		t.Fatalf("GetSecretSyncJob(B): %v", err)
	}
	if gotA.Target != "github-actions" || gotB.Target != "gitlab-ci" {
		t.Fatalf("tenant sync jobs crossed: A=%+v B=%+v", gotA, gotB)
	}

	bOnly := jobB
	bOnly.ID = "sync-b-only"
	bOnly.OutboxID = 902
	bOnly.IdempotencyKey = "sync-request-b-2"
	projectSecretSyncJob(t, s, tenantB, bOnly)
	if _, err := s.GetSecretSyncJob(ctx, tenantA, bOnly.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("tenant A read tenant B sync job: err=%v, want ErrNoRows", err)
	}

	deliveredAt := requestedAt.Add(time.Second)
	if err := applySecretSyncTerminalFixture(t, s, tenantA, jobA.ID, store.SecretSyncJobDelivered,
		1, "github-etag-7", "", deliveredAt); err != nil {
		t.Fatalf("deliver secret sync job: %v", err)
	}
	// Replaying queue and then a stale failure must not regress delivered state.
	projectSecretSyncJob(t, s, tenantA, jobA)
	if err := applySecretSyncTerminalFixture(t, s, tenantA, jobA.ID, store.SecretSyncJobFailed,
		2, "", "stale failure", deliveredAt.Add(time.Second)); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("opposite stale sync failure error=%v, want ErrIdempotencyConflict", err)
	}
	gotA, err = s.GetSecretSyncJob(ctx, tenantA, jobA.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotA.Status != store.SecretSyncJobDelivered || gotA.DeliveredAt == nil || gotA.RemoteVersion != "github-etag-7" || gotA.Attempts != 1 || gotA.LastError != "" {
		t.Fatalf("delivered evidence regressed: %+v", gotA)
	}

	failed := jobA
	failed.ID = "sync-terminal-failed"
	failed.OutboxID = 805
	failed.TargetOrder = 805
	failed.IdempotencyKey = "sync-request-terminal-failed"
	projectSecretSyncJob(t, s, tenantA, failed)
	if err := applySecretSyncTerminalFixture(t, s, tenantA, failed.ID, store.SecretSyncJobFailed,
		1, "", "canonical failure", deliveredAt); err != nil {
		t.Fatal(err)
	}
	if err := applySecretSyncTerminalFixture(t, s, tenantA, failed.ID, store.SecretSyncJobDelivered,
		2, "late-etag", "", deliveredAt.Add(time.Second)); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("late delivered evidence error=%v, want ErrIdempotencyConflict", err)
	}
	failedStored, err := s.GetSecretSyncJob(ctx, tenantA, failed.ID)
	if err != nil {
		t.Fatal(err)
	}
	if failedStored.Status != store.SecretSyncJobFailed || failedStored.Attempts != 1 || failedStored.LastError != "canonical failure" || failedStored.RemoteVersion != "" {
		t.Fatalf("failed evidence regressed after later delivered event: %+v", failedStored)
	}

	newer := jobA
	newer.ID = "sync-version-8"
	newer.SecretVersion = 8
	newer.ValueDigest = strings.Repeat("b", 64)
	newer.OutboxID = 802
	newer.IdempotencyKey = "sync-request-a-2"
	newer.RequestedAt = requestedAt.Add(time.Minute)
	newer.UpdatedAt = newer.RequestedAt
	projectSecretSyncJob(t, s, tenantA, newer)
	latest, err := s.GetLatestSecretSyncJob(ctx, tenantA, newer.SecretName, newer.Target, newer.RemoteKey)
	if err != nil {
		t.Fatalf("GetLatestSecretSyncJob: %v", err)
	}
	if latest.ID != newer.ID || latest.SecretVersion != 8 || latest.Status != store.SecretSyncJobPending {
		t.Fatalf("latest sync job = %+v, want pending version 8", latest)
	}

	pending, err := s.ListSecretSyncJobsPage(ctx, tenantA, "github-actions", store.SecretSyncJobPending, "", 20)
	if err != nil {
		t.Fatalf("ListSecretSyncJobsPage: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != newer.ID {
		t.Fatalf("pending jobs = %+v, want only %s", pending, newer.ID)
	}

	// Idempotency keys are unique per tenant, so a retry cannot create a second
	// projected job even if it accidentally carries a new job id.
	duplicateRequest := newer
	duplicateRequest.ID = "sync-duplicate-idempotency"
	duplicateRequest.OutboxID = 803
	duplicateRequest.TargetOrder = 803
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplySecretSyncJobQueuedTx(ctx, tx, duplicateRequest)
	})
	if err == nil {
		t.Fatal("duplicate tenant/idempotency_key created a second sync job")
	}

	crossTenant := newer
	crossTenant.ID = "sync-cross-tenant"
	crossTenant.TenantID = tenantB
	crossTenant.TenantEpoch = mustSecretSyncTenantEpoch(t, s, tenantB)
	crossTenant.OutboxID = 804
	crossTenant.TargetOrder = 804
	crossTenant.IdempotencyKey = "sync-request-cross"
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplySecretSyncJobQueuedTx(ctx, tx, crossTenant)
	})
	if err == nil || !isRLSViolation(err) {
		t.Fatalf("cross-tenant sync projection err=%v, want RLS policy denial", err)
	}

	// The only bytea columns are the explicitly envelope-sealed worker preparation
	// and credential result; no plaintext secret/value column becomes queryable
	// status data.
	var secretByteColumns []string
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT array_agg(column_name ORDER BY column_name)
		   FROM information_schema.columns
		  WHERE table_schema = 'public'
		    AND table_name IN ('dynamic_secret_leases', 'secret_sync_jobs')
		    AND data_type = 'bytea'`).Scan(&secretByteColumns); err != nil {
		t.Fatalf("inspect projection columns: %v", err)
	}
	if got := strings.Join(secretByteColumns, ","); got != "sealed_credential,sealed_preparation" {
		t.Fatalf("secret integration bytea columns = %q, want only sealed credential/preparation ciphertext", got)
	}
}

func TestSecretIntegrationTablesForceRLS(t *testing.T) {
	s := newStore(t)
	resetSecretIntegrationTables(t, s)
	ctx := context.Background()
	for _, table := range []string{"dynamic_secret_operations", "dynamic_secret_leases", "secret_sync_jobs"} {
		var enabled, forced, hasWithCheck bool
		if err := s.SystemPool().QueryRow(ctx,
			`SELECT c.relrowsecurity,
			        c.relforcerowsecurity,
			        EXISTS (
			            SELECT 1 FROM pg_policies p
			             WHERE p.schemaname = 'public'
			               AND p.tablename = $1
			               AND p.with_check IS NOT NULL
			        )
			   FROM pg_class c
			   JOIN pg_namespace n ON n.oid = c.relnamespace
			  WHERE n.nspname = 'public' AND c.relname = $1`, table).
			Scan(&enabled, &forced, &hasWithCheck); err != nil {
			t.Fatalf("inspect RLS for %s: %v", table, err)
		}
		if !enabled || !forced || !hasWithCheck {
			t.Errorf("%s RLS enabled=%t forced=%t with_check=%t, want all true", table, enabled, forced, hasWithCheck)
		}
	}
}
