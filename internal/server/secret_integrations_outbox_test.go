// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secretsync"
	"trstctl.com/trstctl/internal/store"
)

type outboxDynamicProvider struct {
	name    string
	revoked []string
}

func (p *outboxDynamicProvider) Name() string { return p.name }
func (p *outboxDynamicProvider) Generate(context.Context, dynsecret.GenerateRequest) (dynsecret.Credential, error) {
	return dynsecret.Credential{}, nil
}
func (p *outboxDynamicProvider) Revoke(_ context.Context, ref string) error {
	p.revoked = append(p.revoked, ref)
	return nil
}

type outboxSyncPusher struct {
	keys   []string
	values [][]byte
}

func (p *outboxSyncPusher) Push(_ context.Context, key string, value []byte) error {
	p.keys = append(p.keys, key)
	p.values = append(p.values, append([]byte(nil), value...))
	return nil
}

func TestSecretIntegrationOutboxDispatcherRoutesTenantBoundWork(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	kek, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer kek.Destroy()
	provider := &outboxDynamicProvider{name: "pg-production"}
	pusher := &outboxSyncPusher{}
	dispatcher := &secretIntegrationOutboxDispatcher{
		dynamicProviders: DynamicSecretProviderRegistry{tenant: {provider}},
		syncTargets: SecretSyncTargetRegistry{tenant: {
			"github-production": secretsync.NewTarget("github-production", pusher),
		}},
		kek: kek,
	}

	revokePayload, err := json.Marshal(dynsecret.RevokeItem{LeaseID: "lease-1", Provider: provider.name, BackendRef: "db-user-1"})
	if err != nil {
		t.Fatal(err)
	}
	handled, err := dispatcher.Deliver(context.Background(), orchestrator.Message{
		TenantID: tenant, Destination: dynamicSecretRevokeDestination, Payload: revokePayload,
	})
	if err != nil || !handled {
		t.Fatalf("dynamic revoke handled=%v err=%v", handled, err)
	}
	if len(provider.revoked) != 1 || provider.revoked[0] != "db-user-1" {
		t.Fatalf("provider revocations = %#v", provider.revoked)
	}

	value := []byte("secret value")
	sealed, err := seal.Seal(kek, value, secretSyncAAD(tenant, "github-production", "sync-1", "DEPLOY_TOKEN"))
	if err != nil {
		t.Fatal(err)
	}
	syncPayload, err := json.Marshal(secretSyncOutboxPayload{
		ID: "sync-1", Key: "DEPLOY_TOKEN", Target: "github-production", Sealed: sealed,
	})
	if err != nil {
		t.Fatal(err)
	}
	handled, err = dispatcher.Deliver(context.Background(), orchestrator.Message{
		TenantID: tenant, Destination: secretSyncDestination("github-production"), Payload: syncPayload,
	})
	if err != nil || !handled {
		t.Fatalf("secret sync handled=%v err=%v", handled, err)
	}
	if len(pusher.values) != 1 || !bytes.Equal(pusher.values[0], value) || pusher.keys[0] != "DEPLOY_TOKEN" {
		t.Fatalf("pushed keys=%#v values=%q", pusher.keys, pusher.values)
	}
}

func TestSecretIntegrationOutboxDispatcherFailsClosed(t *testing.T) {
	dispatcher := &secretIntegrationOutboxDispatcher{}
	for _, destination := range []string{"dynsecret.unknown", "secret.sync.missing"} {
		handled, err := dispatcher.Deliver(context.Background(), orchestrator.Message{
			TenantID: "11111111-1111-1111-1111-111111111111", Destination: destination,
		})
		if !handled || err == nil {
			t.Fatalf("destination %q handled=%v err=%v, want handled error", destination, handled, err)
		}
		if !strings.Contains(err.Error(), "unsupported") && !strings.Contains(err.Error(), "not configured") && !strings.Contains(err.Error(), "requires a KEK") {
			t.Fatalf("destination %q error %q does not explain fail-closed routing", destination, err)
		}
	}

	handled, err := dispatcher.Deliver(context.Background(), orchestrator.Message{Destination: "webhook.customer"})
	if handled || err != nil {
		t.Fatalf("unrelated destination handled=%v err=%v", handled, err)
	}
}

func TestDurableSecretSyncBindsCallerAndSkipsDeliveredRedelivery(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111124"
	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	tenantData, _ := json.Marshal(map[string]string{"name": "Secret Sync Durable Binding"})
	tenantEvent, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenant, Data: tenantData})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).Apply(ctx, tenantEvent); err != nil {
		t.Fatal(err)
	}
	kek, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x73}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kek.Destroy)
	value := []byte("one durable sync value")
	const (
		target  = "github-production"
		binding = "sha256:principal-a-secret-name-target-key"
		idemKey = "durable-secret-sync"
	)
	if err := queueSecretSyncEvent(ctx, st, log, kek, tenant, "production/deploy", 7, target, "DEPLOY_TOKEN", idemKey, binding, value); err != nil {
		t.Fatal(err)
	}
	jobs, err := st.ListSecretSyncJobsPage(ctx, tenant, target, store.SecretSyncJobPending, "", 10)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("pending sync jobs=%+v err=%v", jobs, err)
	}
	job := jobs[0]
	if job.RequestBinding != binding || job.ID != store.DurableSecretSyncJobID(tenant, idemKey) {
		t.Fatalf("projected command binding=%q id=%q, want %q/%q", job.RequestBinding, job.ID, binding, store.DurableSecretSyncJobID(tenant, idemKey))
	}
	outbox := orchestrator.NewOutbox(st)
	record, err := outbox.Get(ctx, tenant, job.OutboxID)
	if err != nil {
		t.Fatal(err)
	}
	var lane string
	if err := st.SystemPool().QueryRow(ctx,
		`SELECT effect_lane FROM outbox WHERE tenant_id = $1 AND id = $2`, tenant, record.ID).Scan(&lane); err != nil {
		t.Fatal(err)
	}
	if lane != "secret.sync:"+target {
		t.Fatalf("secret-sync effect lane=%q", lane)
	}
	pusher := &outboxSyncPusher{}
	dispatcher := &secretIntegrationOutboxDispatcher{
		store: st, log: log, kek: kek,
		syncTargets: SecretSyncTargetRegistry{tenant: {
			target: secretsync.NewTarget(target, pusher),
		}},
	}
	message := orchestrator.Message{
		ID: record.ID, TenantID: tenant, Destination: record.Destination,
		IdempotencyKey: record.IdempotencyKey, Payload: record.Payload, Attempts: 1,
	}
	for attempt := 1; attempt <= 2; attempt++ {
		handled, err := dispatcher.Deliver(ctx, message)
		if err != nil || !handled {
			t.Fatalf("delivery %d handled=%t err=%v", attempt, handled, err)
		}
	}
	if len(pusher.values) != 1 || !bytes.Equal(pusher.values[0], value) {
		t.Fatalf("external sync writes=%d values=%q, want one", len(pusher.values), pusher.values)
	}
	delivered, err := st.GetSecretSyncJob(ctx, tenant, job.ID)
	if err != nil || delivered.Status != store.SecretSyncJobDelivered {
		t.Fatalf("delivered projection=%+v err=%v", delivered, err)
	}
	if _, err := st.SystemPool().Exec(ctx,
		`DELETE FROM outbox WHERE tenant_id = $1 AND id = $2`, tenant, record.ID); err != nil {
		t.Fatal(err)
	}
	// Exact replay after response/outbox GC is answered from the durable command
	// binding and never recreates the external intent.
	if err := queueSecretSyncEvent(ctx, st, log, kek, tenant, "production/deploy", 7, target, "DEPLOY_TOKEN", idemKey, binding, value); err != nil {
		t.Fatalf("exact replay after outbox GC: %v", err)
	}
	if err := queueSecretSyncEvent(ctx, st, log, kek, tenant, "production/deploy", 7, target, "DEPLOY_TOKEN", idemKey, "sha256:principal-b-secret-name-target-key", value); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed principal after GC error=%v, want conflict", err)
	}
	queuedEvents := 0
	if err := log.Replay(ctx, 1, func(event events.Event) error {
		if event.TenantID == tenant && event.Type == projections.EventSecretSyncQueued {
			queuedEvents++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if queuedEvents != 1 {
		t.Fatalf("secret-sync queued events=%d, want one canonical event", queuedEvents)
	}
}
