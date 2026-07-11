// SPDX-License-Identifier: MPL-2.0

package projections_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestSecretIntegrationEventsRebuildLeaseAndSealedOutbox(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	projector := projections.New(s)
	apply := func(eventType string, payload any) {
		t.Helper()
		event := appendJSONEvent(t, log, eventType, tenantA, payload)
		if err := projector.Apply(ctx, event); err != nil {
			t.Fatalf("apply %s: %v", eventType, err)
		}
	}

	apply(projections.EventTenantRegistered, map[string]string{"name": "Acme"})
	now := time.Now().UTC()
	apply(projections.EventDynamicSecretLeasePending, projections.DynamicSecretLeasePending{
		ID: "lease-restart", IdempotencyKey: "issue-restart", Provider: "postgres-production", Role: "reader",
		ExpiresAt: now.Add(time.Hour), HardExpiresAt: now.Add(2 * time.Hour),
	})
	apply(projections.EventDynamicSecretLeasePrepared, projections.DynamicSecretLeasePrepared{
		ID: "lease-restart", Provider: "postgres-production", SealedPreparation: []byte("sealed-worker-preparation"),
	})
	apply(projections.EventDynamicSecretLeaseIssued, projections.DynamicSecretLeaseIssued{
		ID: "lease-restart", IdempotencyKey: "issue-restart", Provider: "postgres-production", Role: "reader",
		BackendRef: "trstctl_reader_restart", SealedCredential: []byte("sealed-dynamic-credential"),
		ExpiresAt: now.Add(time.Hour), HardExpiresAt: now.Add(2 * time.Hour),
	})
	apply(projections.EventDynamicSecretLeaseRevocationRequested, projections.DynamicSecretLeaseRevocationRequested{
		ID: "lease-restart", Provider: "postgres-production", BackendRef: "trstctl_reader_restart",
	})

	ciphertext := []byte("ciphertext-only-not-a-secret-value")
	apply(projections.EventSecretSyncQueued, projections.SecretSyncQueued{
		ID: "sync-restart", SecretName: "production/database", SecretVersion: 4,
		Target: "github-production", RemoteKey: "DATABASE_URL",
		ValueDigest:    "b149c21602f0c4b98c0fb0c2a9f8b9047da02d4bd734682360a8f9d65bb3f857",
		IdempotencyKey: "secret.sync.github-production:sync-restart", Sealed: ciphertext,
	})
	apply(projections.EventSecretSyncDelivered, projections.SecretSyncDelivered{ID: "sync-restart", Attempts: 1})

	assertSecretIntegrationProjection(t, s)
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	assertSecretIntegrationProjection(t, s)

	var payload []byte
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT payload FROM outbox WHERE tenant_id = $1 AND destination = 'secret.sync.github-production'`, tenantA).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte("actual-secret-value")) || !bytes.Contains(payload, []byte(`"sealed"`)) {
		t.Fatalf("secret-sync outbox payload is not ciphertext-only: %q", payload)
	}
}

func assertSecretIntegrationProjection(t *testing.T, s *store.Store) {
	t.Helper()
	ctx := context.Background()
	lease, err := s.GetDynamicSecretLease(ctx, tenantA, "lease-restart")
	if err != nil {
		t.Fatal(err)
	}
	if lease.State != store.DynamicSecretLeaseRevoked || lease.RevocationStatus != store.DynamicSecretRevocationPending || lease.BackendRef != "trstctl_reader_restart" || len(lease.SealedPreparation) != 0 {
		t.Fatalf("lease projection = %+v", lease)
	}
	job, err := s.GetSecretSyncJob(ctx, tenantA, "sync-restart")
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != store.SecretSyncJobDelivered || job.Attempts != 1 || job.OutboxID == 0 {
		t.Fatalf("sync job projection = %+v", job)
	}
	var issues, revocations, syncs int
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE destination = 'dynsecret.issue'),
		        count(*) FILTER (WHERE destination = 'dynsecret.revoke'),
		        count(*) FILTER (WHERE destination = 'secret.sync.github-production')
		   FROM outbox WHERE tenant_id = $1`, tenantA).Scan(&issues, &revocations, &syncs); err != nil {
		t.Fatal(err)
	}
	if issues != 1 || revocations != 1 || syncs != 1 {
		t.Fatalf("outbox counts issues=%d revocations=%d syncs=%d, want 1/1/1", issues, revocations, syncs)
	}
}
