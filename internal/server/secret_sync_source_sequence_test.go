// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestSecretSyncWorkerExactSourceSurvivesColdRestartAndRefusesProjectionDrift(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111178"
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "nats")
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	other, err := log.Append(ctx, events.Event{
		ID: "unrelated-before-secret-sync", Type: projections.EventTenantRegistered,
		TenantID: tenant, Data: []byte(`{"name":"unrelated"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	job := store.SecretSyncJob{
		ID: "job-1", TenantID: tenant, TenantEpoch: "epoch-1",
		SecretName: "test/source", SecretVersion: 1, Target: "ci", RemoteKey: "TOKEN",
		ValueDigest: "digest", IdempotencyKey: "sync-job-1", RequestBinding: "request-1",
	}
	queued := projections.SecretSyncQueued{
		TenantEpoch: job.TenantEpoch, ID: job.ID, SecretName: job.SecretName,
		SecretVersion: job.SecretVersion, Target: job.Target, RemoteKey: job.RemoteKey,
		ValueDigest: job.ValueDigest, IdempotencyKey: job.IdempotencyKey,
		RequestBinding: job.RequestBinding, Sealed: []byte("sealed test payload"),
	}
	data, err := json.Marshal(queued)
	if err != nil {
		t.Fatal(err)
	}
	command, err := log.Append(ctx, events.Event{
		ID:   store.SecretSyncQueuedEventID(tenant, job.ID),
		Type: projections.EventSecretSyncQueued, TenantID: tenant,
		SchemaVersion: projections.SecretSyncEventSchemaVersion, Data: data,
	})
	if err != nil {
		t.Fatal(err)
	}
	job.TargetOrder = int64(command.Sequence) // #nosec G115 -- this fixture appends exactly two events.
	outbox := secretSyncOutboxPayload{
		ID: job.ID, Key: job.RemoteKey, Target: job.Target,
		RequestBinding: job.RequestBinding, Sealed: queued.Sealed,
	}
	check := func(stage string, source *events.Log) {
		t.Helper()
		if err := validateProjectedSecretSyncSource(ctx, source, job, outbox); err != nil {
			t.Fatalf("%s exact retained source: %v", stage, err)
		}
		wrongOrder := job
		wrongOrder.TargetOrder = int64(other.Sequence) // #nosec G115 -- this fixture appends exactly two events.
		if err := validateProjectedSecretSyncSource(ctx, source, wrongOrder, outbox); !errors.Is(err, store.ErrIdempotencyConflict) {
			t.Fatalf("%s wrong event order = %v, want conflict", stage, err)
		}
		missing := job
		missing.TargetOrder = int64(command.Sequence + 1) // #nosec G115 -- this fixture appends exactly two events.
		if err := validateProjectedSecretSyncSource(ctx, source, missing, outbox); !errors.Is(err, store.ErrIdempotencyConflict) {
			t.Fatalf("%s missing exact order = %v, want conflict", stage, err)
		}
		wrongTenant := job
		wrongTenant.TenantID = "22222222-2222-4222-8222-222222222278"
		if err := validateProjectedSecretSyncSource(ctx, source, wrongTenant, outbox); !errors.Is(err, store.ErrIdempotencyConflict) {
			t.Fatalf("%s wrong tenant = %v, want conflict", stage, err)
		}
		wrongPayload := outbox
		wrongPayload.Sealed = []byte("changed")
		if err := validateProjectedSecretSyncSource(ctx, source, job, wrongPayload); !errors.Is(err, store.ErrIdempotencyConflict) {
			t.Fatalf("%s changed command = %v, want conflict", stage, err)
		}
	}
	check("before restart", log)
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("close reopened event log: %v", err)
		}
	}()
	check("after restart", reopened)
}
