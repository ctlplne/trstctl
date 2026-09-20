// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestSecretSyncReceiverBeginMakesOffboardBusyAcrossExpiredLeaseAUD109(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	job := seedSecretSyncOffboardFenceJob(t, s, tenantA, "busy-old-generation")

	token, proceed, err := s.BeginSecretSyncReceiverIO(ctx, tenantA, job.TenantEpoch, job.ID, job.OutboxID, func(context.Context, store.TenantRegistrationSnapshot) error { return nil })
	if err != nil || !proceed || token != 1 {
		t.Fatalf("BeginSecretSyncReceiverIO = (%d,%t,%v), want (1,true,nil)", token, proceed, err)
	}
	if _, err := s.SystemPool().Exec(ctx, `
		UPDATE outbox
		   SET status = 'processing', lease_until = now() - interval '1 minute'
		 WHERE tenant_id = $1 AND id = $2`, tenantA, job.OutboxID); err != nil {
		t.Fatal(err)
	}

	attestation, err := s.OffboardTenant(ctx, tenantA)
	var busy *store.TenantSecretSyncNotQuiescentError
	if !errors.As(err, &busy) {
		t.Fatalf("offboard behind expired receiver lease error = %v, want typed not-quiescent", err)
	}
	if busy.TenantID != tenantA || busy.TenantEpoch != job.TenantEpoch || busy.JobID != job.ID || busy.OutboxID != job.OutboxID {
		t.Fatalf("busy identity = %+v, want exact job %+v", busy, job)
	}
	if attestation.Complete {
		t.Fatalf("busy offboard attestation = %+v, must not claim completion", attestation)
	}
	if _, err := s.GetSecretSyncJob(ctx, tenantA, job.ID); err != nil {
		t.Fatalf("busy offboard deleted old receiver authority: %v", err)
	}

	terminalAt := time.Date(2026, 8, 11, 15, 5, 0, 0, time.UTC)
	if err := s.WithTenantProjection(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplySecretSyncTerminalEventTx(ctx, tx, store.SecretSyncTerminalEvent{
			TenantID: tenantA, TenantEpoch: job.TenantEpoch, JobID: job.ID,
			Status: store.SecretSyncJobDelivered, Attempts: 1, OccurredAt: terminalAt,
			EventID: store.SecretSyncDeliveredEventID(tenantA, job.ID), EventType: "secret.sync.delivered",
			EventSequence: job.TargetOrder + 1, PayloadDigest: strings.Repeat("a", 64),
		})
	}); err != nil {
		t.Fatalf("settle old receiver command: %v", err)
	}
	if attestation, err = s.OffboardTenant(ctx, tenantA); !errors.As(err, &busy) || attestation.Complete {
		t.Fatalf("offboard before exact outbox terminal receipt = %+v, %v; want typed not-quiescent", attestation, err)
	}
	if _, err := s.SystemPool().Exec(ctx, `
		UPDATE outbox
		   SET status = 'delivered', delivered_at = $3, worker_id = NULL, lease_until = NULL
		 WHERE tenant_id = $1 AND id = $2`, tenantA, job.OutboxID, terminalAt); err != nil {
		t.Fatalf("finalize exact delivered outbox receipt: %v", err)
	}
	if attestation, err = s.OffboardTenant(ctx, tenantA); err != nil || !attestation.Complete {
		t.Fatalf("offboard after canonical terminal = %+v, %v", attestation, err)
	}
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "tenant-a-reregistered"}); err != nil {
		t.Fatal(err)
	}
	newEpoch, err := s.ApplicationSecretTenantEpoch(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if newEpoch == job.TenantEpoch {
		t.Fatalf("re-registration reused erased tenant epoch %q", newEpoch)
	}
}

func TestTenantOffboardWinsBeforeStaleReceiverBeginAUD109(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	job := seedSecretSyncOffboardFenceJob(t, s, tenantA, "offboard-first")

	started := make(chan struct{})
	result := make(chan struct {
		token   int64
		proceed bool
		err     error
	}, 1)
	var guarded atomic.Int64
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := s.PreflightTenantOffboardTx(ctx, tx, tenantA); err != nil {
			return err
		}
		go func() {
			close(started)
			token, proceed, err := s.BeginSecretSyncReceiverIO(ctx, tenantA, job.TenantEpoch, job.ID, job.OutboxID, func(context.Context, store.TenantRegistrationSnapshot) error {
				guarded.Add(1)
				return nil
			})
			result <- struct {
				token   int64
				proceed bool
				err     error
			}{token: token, proceed: proceed, err: err}
		}()
		<-started
		_, err := s.OffboardTenantTx(ctx, tx, tenantA)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	got := <-result
	if got.err != nil || got.proceed || got.token != 0 {
		t.Fatalf("stale Begin after offboard = (%d,%t,%v), want (0,false,nil)", got.token, got.proceed, got.err)
	}
	if guarded.Load() != 0 {
		t.Fatalf("retained-history guard ran %d time(s) after tenant deletion, want zero", guarded.Load())
	}
}

func TestApplicationSecretEpochRejectsMissingTenantAndBusyTenantIsIsolatedAUD109(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	const missing = "33333333-3333-4333-8333-333333333333"
	if _, err := s.ApplicationSecretTenantEpoch(ctx, missing); !errors.Is(err, store.ErrApplicationSecretTenantEpochMismatch) {
		t.Fatalf("missing-tenant epoch error = %v, want lifecycle mismatch", err)
	}
	var leaked int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM application_secret_tenant_epochs WHERE tenant_id = $1`, missing).Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked != 0 {
		t.Fatalf("missing tenant created %d epoch row(s)", leaked)
	}

	job := seedSecretSyncOffboardFenceJob(t, s, tenantA, "tenant-isolation")
	if _, proceed, err := s.BeginSecretSyncReceiverIO(ctx, tenantA, job.TenantEpoch, job.ID, job.OutboxID, nil); err != nil || !proceed {
		t.Fatalf("begin tenant A receiver = (%t,%v)", proceed, err)
	}
	if attestation, err := s.OffboardTenant(ctx, tenantB); err != nil || !attestation.Complete {
		t.Fatalf("tenant B offboard behind tenant A ambiguity = %+v, %v", attestation, err)
	}
	if _, err := s.GetSecretSyncJob(ctx, tenantA, job.ID); err != nil {
		t.Fatalf("tenant B offboard touched tenant A job: %v", err)
	}
}

func TestSecretSyncOverlappingReceiverGenerationsStayOffboardBusyAfterTerminalAUD109(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	job := seedSecretSyncOffboardFenceJob(t, s, tenantA, "overlapping-generations")

	for wantToken := int64(1); wantToken <= 2; wantToken++ {
		token, proceed, err := s.BeginSecretSyncReceiverIO(ctx, tenantA, job.TenantEpoch, job.ID, job.OutboxID, nil)
		if err != nil || !proceed || token != wantToken {
			t.Fatalf("BeginSecretSyncReceiverIO generation %d = (%d,%t,%v)", wantToken, token, proceed, err)
		}
	}
	terminalAt := time.Date(2026, 8, 11, 16, 5, 0, 0, time.UTC)
	if err := s.WithTenantProjection(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplySecretSyncTerminalEventTx(ctx, tx, store.SecretSyncTerminalEvent{
			TenantID: tenantA, TenantEpoch: job.TenantEpoch, JobID: job.ID,
			Status: store.SecretSyncJobDelivered, Attempts: 2, OccurredAt: terminalAt,
			EventID: store.SecretSyncDeliveredEventID(tenantA, job.ID), EventType: "secret.sync.delivered",
			EventSequence: job.TargetOrder + 1, PayloadDigest: strings.Repeat("c", 64),
		})
	}); err != nil {
		t.Fatalf("project generation-two terminal: %v", err)
	}

	attestation, err := s.OffboardTenant(ctx, tenantA)
	var busy *store.TenantSecretSyncNotQuiescentError
	if !errors.As(err, &busy) {
		t.Fatalf("offboard after one of two receiver generations terminalized = %+v, %v; want typed not-quiescent", attestation, err)
	}
	if busy.ReceiverIOStarts != 2 || busy.JobID != job.ID || busy.OutboxID != job.OutboxID {
		t.Fatalf("overlap authority = %+v, want exact two-generation identity", busy)
	}
	if _, err := s.ApplicationSecretTenantEpoch(ctx, tenantA); err != nil {
		t.Fatalf("ambiguous lifecycle was deleted or replaced: %v", err)
	}
}

func TestSecretSyncOrphanEffectPossibleAuthorityBlocksOffboardAUD109(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	job := seedSecretSyncOffboardFenceJob(t, s, tenantA, "orphan-authority")
	if _, proceed, err := s.BeginSecretSyncReceiverIO(ctx, tenantA, job.TenantEpoch, job.ID, job.OutboxID, nil); err != nil || !proceed {
		t.Fatalf("begin receiver = (%t,%v)", proceed, err)
	}
	if _, err := s.SystemPool().Exec(ctx, `
		UPDATE secret_sync_jobs
		   SET outbox_id = outbox_id + 1000000
		 WHERE tenant_id = $1 AND id = $2`, tenantA, job.ID); err != nil {
		t.Fatal(err)
	}

	attestation, err := s.OffboardTenant(ctx, tenantA)
	var busy *store.TenantSecretSyncNotQuiescentError
	if !errors.As(err, &busy) {
		t.Fatalf("offboard with orphan effect_possible outbox = %+v, %v; want typed not-quiescent", attestation, err)
	}
	if busy.OutboxID != job.OutboxID || busy.Reason == "" {
		t.Fatalf("orphan authority = %+v, want exact outbox and closed reason", busy)
	}
}

func TestMissingTenantOffboardFenceSerializesReregistrationAUD109(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	const tenantID = "44444444-4444-4444-8444-444444444444"

	if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := s.PreflightTenantOffboardTx(ctx, tx, tenantID); err != nil {
			return err
		}
		attemptCtx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
		defer cancel()
		registrationDone := make(chan error, 1)
		go func() {
			registrationDone <- s.UpsertTenant(attemptCtx, store.Tenant{TenantID: tenantID, Name: "must wait", EventSeq: 41})
		}()
		if err := <-registrationDone; err == nil {
			return errors.New("registration crossed a missing-row offboard lifecycle fence")
		}
		_, err := s.OffboardTenantTx(ctx, tx, tenantID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "new lifecycle", EventSeq: 42}); err != nil {
		t.Fatalf("registration after missing-row offboard fence: %v", err)
	}
	tenant, err := s.GetTenant(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if tenant.Name != "new lifecycle" || tenant.EventSeq != 42 {
		t.Fatalf("registered tenant = %+v", tenant)
	}
}

func TestSecretSyncQueuedResolverIsTheOnlyEpochCreatorAUD109(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE tenants SET event_seq = 40 WHERE tenant_id = $1`, tenantA); err != nil {
		t.Fatal(err)
	}

	// A retained result cannot create lifecycle authority by itself.
	if err := s.WithTenantProjection(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := s.ResolveSecretSyncTenantEpochTx(ctx, tx, tenantA, "", 41)
		if !errors.Is(err, store.ErrApplicationSecretTenantEpochMismatch) {
			t.Fatalf("legacy terminal resolver error = %v, want epoch mismatch", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var epochs int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM application_secret_tenant_epochs WHERE tenant_id = $1`, tenantA,
	).Scan(&epochs); err != nil || epochs != 0 {
		t.Fatalf("terminal resolver epoch rows = %d, err=%v; want zero", epochs, err)
	}

	// An old queued root is inert, but the first root after this exact
	// registration may create the epoch and every result then maps to it.
	if err := s.WithTenantProjection(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := s.ResolveSecretSyncQueuedTenantEpochTx(ctx, tx, tenantA, "", 39)
		if !errors.Is(err, store.ErrApplicationSecretTenantEpochMismatch) {
			t.Fatalf("pre-registration queued resolver error = %v, want epoch mismatch", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var epoch string
	if err := s.WithTenantProjection(ctx, tenantA, func(tx pgx.Tx) error {
		var err error
		epoch, err = s.ResolveSecretSyncQueuedTenantEpochTx(ctx, tx, tenantA, "", 41)
		return err
	}); err != nil || epoch == "" {
		t.Fatalf("current queued resolver epoch = %q, err=%v", epoch, err)
	}
	if err := s.WithTenantProjection(ctx, tenantA, func(tx pgx.Tx) error {
		resolved, err := s.ResolveSecretSyncTenantEpochTx(ctx, tx, tenantA, "", 42)
		if err != nil {
			return err
		}
		if resolved != epoch {
			t.Fatalf("terminal resolver epoch = %q, want %q", resolved, epoch)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// A current queued root carries the exact epoch that the producer used. A
	// fresh event-only recovery target has no independent epoch row, so that root
	// may restore the named epoch after proving it belongs to this registration.
	// A terminal still cannot create the row and a conflicting later root cannot
	// replace it.
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE tenants SET event_seq = 50 WHERE tenant_id = $1`, tenantB); err != nil {
		t.Fatal(err)
	}
	const restoredEpoch = "33333333-3333-4333-8333-333333333333"
	if err := s.WithTenantProjection(ctx, tenantB, func(tx pgx.Tx) error {
		_, err := s.ResolveSecretSyncTenantEpochTx(ctx, tx, tenantB, restoredEpoch, 51)
		if !errors.Is(err, store.ErrApplicationSecretTenantEpochMismatch) {
			t.Fatalf("current terminal resolver error = %v, want epoch mismatch", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenantProjection(ctx, tenantB, func(tx pgx.Tx) error {
		resolved, err := s.ResolveSecretSyncQueuedTenantEpochTx(ctx, tx, tenantB, restoredEpoch, 51)
		if err != nil {
			return err
		}
		if resolved != restoredEpoch {
			t.Fatalf("current queued resolver epoch = %q, want %q", resolved, restoredEpoch)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenantProjection(ctx, tenantB, func(tx pgx.Tx) error {
		_, err := s.ResolveSecretSyncQueuedTenantEpochTx(ctx, tx, tenantB,
			"44444444-4444-4444-8444-444444444444", 52)
		if !errors.Is(err, store.ErrApplicationSecretTenantEpochMismatch) {
			t.Fatalf("conflicting queued resolver error = %v, want epoch mismatch", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func seedSecretSyncOffboardFenceJob(t *testing.T, s *store.Store, tenantID, suffix string) store.SecretSyncJob {
	t.Helper()
	ctx := context.Background()
	epoch, err := s.ApplicationSecretTenantEpoch(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 11, 15, 0, 0, 0, time.UTC)
	job := store.SecretSyncJob{
		ID: "sync-offboard-" + suffix, TenantID: tenantID, TenantEpoch: epoch,
		SecretName: "production/database", SecretVersion: 1, Target: "ci", RemoteKey: "DATABASE_URL",
		ValueDigest: strings.Repeat("b", 64), TargetOrder: 9109,
		IdempotencyKey: store.SecretSyncOutboxIdempotencyKey("ci", "sync-offboard-"+suffix),
		RequestBinding: "sha256:" + suffix, RequestedAt: now, UpdatedAt: now,
	}
	payload, err := json.Marshal(struct {
		ID             string `json:"id"`
		Key            string `json:"key"`
		Target         string `json:"target"`
		RequestBinding string `json:"request_binding"`
		Sealed         []byte `json:"sealed"`
	}{ID: job.ID, Key: job.RemoteKey, Target: job.Target, RequestBinding: job.RequestBinding, Sealed: []byte("sealed")})
	if err != nil {
		t.Fatal(err)
	}
	return applySecretSyncIntentFixture(t, s, job, payload)
}
