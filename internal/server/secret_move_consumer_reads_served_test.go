// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// P6-L4: a moved leaked secret closes only once its consumers picked up the
// rotated version, and a consumer that reads through the KV-compatible /v1
// surface, or reads a copy a secret-sync target received, is a consumer like
// one reading the native API. A KV read of the rotated version records its
// reader; a sync delivery of it records the target as "secret-sync:<target>".
func TestServedKVReadsAndSyncDeliveriesCountAsConsumerReadsP6L4(t *testing.T) {
	ctx := context.Background()
	receiver := newSignedWebhookReceiver(t, []byte("receiver-shared-signing-key"))
	registry, minter, err := secretSyncTargetsFromConfig(ctx, []config.SecretSyncTargetConfig{{
		TenantID: servedTestTenant, ID: "payments-hook", Type: "webhook", Endpoint: receiver.server.URL,
		AllowInsecureLoopback: true,
		SigningKeyRef:         writeServedCredentialFile(t, "webhook-signing-key", "receiver-shared-signing-key"),
		BodyTemplate:          `{"name":"${key}","value":"${value}","delivery":"${delivery_id}","at":${timestamp}}`,
	}}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(minter.Close)
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantSecretSyncTargets = registry
	})
	registerServedTenant(t, h, "p6l4 consumer reads tenant")
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "p6l4-operator", "secrets:read", "secrets:write")
	consumer := seedScopedTokenSubject(t, h.store, h.tenant, "payments-api", "secrets:read")

	// Two leaked values, each moved into the store at version 1.
	moved := map[string]string{
		"payments/kv-token":   "33333333-3333-4333-8333-3333333364a1",
		"payments/sync-token": "33333333-3333-4333-8333-3333333364a2",
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		const sourceID, runID = "33333333-3333-4333-8333-3333333364b1", "33333333-3333-4333-8333-3333333364b2"
		now := time.Now().UTC()
		if err := h.store.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
			ID: sourceID, TenantID: h.tenant, Kind: "repository", Name: "p6l4-repository",
			Config: []byte(`{}`), CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			return err
		}
		if err := h.store.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{
			ID: runID, TenantID: h.tenant, SourceID: sourceID, Status: "queued", CreatedAt: now,
		}); err != nil {
			return err
		}
		for name, findingID := range moved {
			if err := h.store.ApplyDiscoveryFindingRecordedTx(ctx, tx, store.DiscoveryFinding{
				ID: findingID, TenantID: h.tenant, RunID: runID, SourceID: sourceID,
				Kind: "leaked_secret", Ref: "repo://acme/payments/" + name, Provenance: "repository",
				Fingerprint: "fp-p6l4-" + findingID[len(findingID)-2:], RiskScore: 80, Metadata: []byte(`{"rule_id":"generic-api-key"}`),
				DiscoveredAt: now,
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed the leaked-secret findings: %v", err)
	}
	for name, findingID := range moved {
		if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", operator, "p6l4-store-"+findingID,
			map[string]any{"name": name, "value": "p6l4-leaked-" + findingID[len(findingID)-2:]}); status != http.StatusCreated {
			t.Fatalf("store %s: %d %s", name, status, body)
		}
		if _, err := h.srv.orch.RecordDiscoveryFindingSecretMoved(ctx, h.tenant, projections.DiscoveryFindingSecretMoved{
			FindingID: findingID, SecretName: name, SecretVersion: 1, MovedBy: "p6l4-operator",
		}); err != nil {
			t.Fatalf("move %s: %v", name, err)
		}
		if status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/"+name, operator, "p6l4-rotate-"+findingID,
			map[string]any{"value": "p6l4-rotated-" + findingID[len(findingID)-2:]}); status != http.StatusOK {
			t.Fatalf("rotate %s: %d %s", name, status, body)
		}
	}
	consumerRead := func(findingID string) store.DiscoveryFindingSecretMove {
		t.Helper()
		moves, err := h.store.DiscoveryFindingSecretMovesFor(ctx, h.tenant, []string{findingID})
		if err != nil {
			t.Fatal(err)
		}
		return moves[findingID]
	}

	// A consumer reads the rotated version through the KV-compatible surface.
	if status, body := q6VaultRequest(t, h, consumer, http.MethodGet, "/v1/secret/data/payments/kv-token"); status != http.StatusOK {
		t.Fatalf("KV read: %d %s", status, body)
	}
	if m := consumerRead(moved["payments/kv-token"]); m.ConsumerReadVersion != 2 || m.ConsumerReader != "payments-api" {
		t.Fatalf("a KV read of the rotated version = read version %d by %q, want version 2 by payments-api", m.ConsumerReadVersion, m.ConsumerReader)
	}

	// The rotated version reaches a sync target its consumers read from.
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/syncs", operator, "p6l4-sync",
		map[string]any{"name": "payments/sync-token", "target": "payments-hook", "remote_key": "SYNC_TOKEN"})
	if status != http.StatusOK {
		t.Fatalf("queue the sync: %d %s", status, body)
	}
	job := drainSecretSyncUntil(t, h, currentSecretSyncJobIDForTest(t, h.store, h.tenant, "p6l4-sync"), store.SecretSyncJobDelivered, 3)
	if job.Status != store.SecretSyncJobDelivered || job.SecretVersion != 2 {
		t.Fatalf("the sync = %+v, want version 2 delivered", job)
	}
	if m := consumerRead(moved["payments/sync-token"]); m.ConsumerReadVersion != 2 || m.ConsumerReader != "secret-sync:payments-hook" {
		t.Fatalf("a sync delivery of the rotated version = read version %d by %q, want version 2 by secret-sync:payments-hook",
			m.ConsumerReadVersion, m.ConsumerReader)
	}
}
