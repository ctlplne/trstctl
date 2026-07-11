// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"bytes"
	"context"
	"errors"
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
	err := s.WithTenant(context.Background(), tenantID, func(tx pgx.Tx) error {
		return s.ApplySecretSyncJobQueuedTx(context.Background(), tx, job)
	})
	if err != nil {
		t.Fatalf("ApplySecretSyncJobQueuedTx(%s/%s): %v", tenantID, job.ID, err)
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
		SecretName:     "production/database",
		SecretVersion:  9,
		Target:         "github-actions",
		RemoteKey:      "DATABASE_URL",
		ValueDigest:    strings.Repeat("c", 64),
		IdempotencyKey: "sync-concurrent-key",
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
		ID: "sync-collision", TenantID: tenantA, SecretName: "production/database",
		SecretVersion: 4, Target: "github-actions", RemoteKey: "DATABASE_URL",
		ValueDigest: strings.Repeat("a", 64), IdempotencyKey: "secret.sync.github-actions:raw-collision",
		RequestedAt: now, UpdatedAt: now,
	}
	changed := first
	changed.Target = "gitlab-ci"
	changed.RemoteKey = "CHANGED_DATABASE_URL"
	changed.ValueDigest = strings.Repeat("b", 64)
	changed.IdempotencyKey = "secret.sync.gitlab-ci:raw-collision"
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
		ID: "sync-replay-binding", TenantID: tenantA, SecretName: "production/api",
		SecretVersion: 8, Target: "github-actions", RemoteKey: "API_TOKEN",
		ValueDigest: strings.Repeat("d", 64), IdempotencyKey: "secret.sync.github-actions:replay-binding",
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
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyDynamicSecretLeaseIssuedTx(ctx, tx, wrongRequest)
	})
	if !store.IsNotFound(err) {
		t.Fatalf("different idempotency key claimed pending lease: err=%v, want store.IsNotFound", err)
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
	}); err != nil {
		t.Fatalf("replay stale revocation failure: %v", err)
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

	// WITH CHECK rejects a projection carrying tenant B while the transaction is
	// bound to tenant A; an explicit query predicate is not the only defense.
	crossTenant := leaseA
	crossTenant.ID = "lease-cross-tenant"
	crossTenant.TenantID = tenantB
	crossTenant.IdempotencyKey = "lease-request-cross"
	crossTenant.IssueOutboxID = 604
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyDynamicSecretLeasePendingTx(ctx, tx, crossTenant)
	})
	if err == nil || !isRLSViolation(err) {
		t.Fatalf("cross-tenant lease projection err=%v, want RLS policy denial", err)
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
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplySecretSyncJobDeliveredTx(ctx, tx, tenantA, jobA.ID, 1, "github-etag-7", deliveredAt)
	}); err != nil {
		t.Fatalf("deliver secret sync job: %v", err)
	}
	// Replaying queue and then a stale failure must not regress delivered state.
	projectSecretSyncJob(t, s, tenantA, jobA)
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplySecretSyncJobFailedTx(ctx, tx, tenantA, jobA.ID, 2, "stale failure", deliveredAt.Add(time.Second))
	}); err != nil {
		t.Fatalf("replay stale sync failure: %v", err)
	}
	gotA, err = s.GetSecretSyncJob(ctx, tenantA, jobA.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotA.Status != store.SecretSyncJobDelivered || gotA.DeliveredAt == nil || gotA.RemoteVersion != "github-etag-7" {
		t.Fatalf("delivered evidence regressed: %+v", gotA)
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
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplySecretSyncJobQueuedTx(ctx, tx, duplicateRequest)
	})
	if err == nil {
		t.Fatal("duplicate tenant/idempotency_key created a second sync job")
	}

	crossTenant := newer
	crossTenant.ID = "sync-cross-tenant"
	crossTenant.TenantID = tenantB
	crossTenant.OutboxID = 804
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
