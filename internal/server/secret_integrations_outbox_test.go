// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/cloudauth"
	"trstctl.com/trstctl/internal/config"
	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/outboxgc"
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
	err    error
}

func (p *outboxSyncPusher) Push(_ context.Context, key string, value []byte) error {
	p.keys = append(p.keys, key)
	p.values = append(p.values, append([]byte(nil), value...))
	return p.err
}

type aud110SyncPusher struct {
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
	mu      sync.Mutex
	keys    []string
}

func newAUD110SyncPusher(release <-chan struct{}) *aud110SyncPusher {
	return &aud110SyncPusher{entered: make(chan struct{}), release: release}
}

func (p *aud110SyncPusher) Push(ctx context.Context, key string, _ []byte) error {
	p.mu.Lock()
	p.keys = append(p.keys, key)
	p.mu.Unlock()
	p.once.Do(func() { close(p.entered) })
	if p.release == nil {
		return nil
	}
	select {
	case <-p.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *aud110SyncPusher) deliveredKeys() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.keys...)
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

	revokePayload, err := json.Marshal(dynsecret.RevokeItem{
		TenantEpoch: "unverified-epoch", LeaseID: "lease-1", Provider: provider.name, BackendRef: "db-user-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	handled, err := dispatcher.Deliver(context.Background(), orchestrator.Message{
		TenantID: tenant, Destination: dynamicSecretRevokeDestination, Payload: revokePayload,
	})
	if err == nil || !handled {
		t.Fatalf("dynamic revoke without durable epoch authority handled=%v err=%v, want fail closed", handled, err)
	}
	if len(provider.revoked) != 0 {
		t.Fatalf("dynamic revoke without durable epoch authority called provider: %#v", provider.revoked)
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

func TestSecretIntegrationOutboxTenantRegistriesDoNotFallBackAcrossTenantScope(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111125"
	ctx := context.Background()
	kek, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x72}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kek.Destroy)

	provider := &outboxDynamicProvider{name: "shared-provider"}
	dispatcher := &secretIntegrationOutboxDispatcher{
		dynamicProviders:         DynamicSecretProviderRegistry{},
		fallbackDynamicProviders: []dynsecret.Provider{provider},
	}
	if got := dispatcher.dynamicProvidersForTenant(tenant); len(got) != 0 {
		t.Fatalf("tenant registry miss returned %d global providers, want zero", len(got))
	}
	if len(provider.revoked) != 0 {
		t.Fatalf("tenant registry miss called global provider %d times", len(provider.revoked))
	}

	// A nil registry is the explicit single-tenant compatibility mode. Only that
	// mode may use the process-wide provider list.
	dispatcher.dynamicProviders = nil
	if got := dispatcher.dynamicProvidersForTenant(tenant); len(got) != 1 || got[0] != provider {
		t.Fatalf("nil registry fallback providers=%v, want configured singleton", got)
	}

	pusher := &outboxSyncPusher{}
	value := []byte("tenant-registry-secret")
	sealed, err := seal.Seal(kek, value, secretSyncAAD(tenant, "shared-target", "sync-tenant-registry", "TOKEN"))
	if err != nil {
		t.Fatal(err)
	}
	syncPayload, err := json.Marshal(secretSyncOutboxPayload{
		ID: "sync-tenant-registry", Key: "TOKEN", Target: "shared-target", Sealed: sealed,
	})
	if err != nil {
		t.Fatal(err)
	}
	syncMessage := orchestrator.Message{
		TenantID: tenant, Destination: secretSyncDestination("shared-target"), Payload: syncPayload,
	}
	dispatcher = &secretIntegrationOutboxDispatcher{
		kek: kek, syncTargets: SecretSyncTargetRegistry{},
		fallbackSyncTargets: map[string]*secretsync.Target{
			"shared-target": secretsync.NewTarget("shared-target", pusher),
		},
	}
	if handled, err := dispatcher.Deliver(ctx, syncMessage); !handled || err == nil || !strings.Contains(err.Error(), "not configured for tenant") {
		t.Fatalf("tenant sync registry miss handled=%t err=%v, want fail-closed tenant miss", handled, err)
	}
	if len(pusher.values) != 0 {
		t.Fatalf("tenant sync registry miss called global target %d times", len(pusher.values))
	}

	dispatcher.syncTargets = nil
	if handled, err := dispatcher.Deliver(ctx, syncMessage); !handled || err != nil {
		t.Fatalf("nil sync registry fallback handled=%t err=%v", handled, err)
	}
	if len(pusher.values) != 1 || !bytes.Equal(pusher.values[0], value) {
		t.Fatalf("nil sync registry fallback values=%q, want one exact value", pusher.values)
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
	if err := queueSecretSyncEvent(ctx, st, log, kek, tenant, "production/deploy", 7, target, "DEPLOY_TOKEN", idemKey, binding, value, nil); err != nil {
		t.Fatal(err)
	}
	jobs, err := st.ListSecretSyncJobsPage(ctx, tenant, target, store.SecretSyncJobPending, "", 10)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("pending sync jobs=%+v err=%v", jobs, err)
	}
	job := jobs[0]
	wantJobID := currentSecretSyncJobIDForTest(t, st, tenant, idemKey)
	if job.RequestBinding != binding || job.ID != wantJobID {
		t.Fatalf("projected command binding=%q id=%q, want %q/%q", job.RequestBinding, job.ID, binding, wantJobID)
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
		`UPDATE outbox SET status = 'delivered', delivered_at = now() WHERE tenant_id = $1 AND id = $2`,
		tenant, record.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SystemPool().Exec(ctx,
		`DELETE FROM outbox WHERE tenant_id = $1 AND id = $2`, tenant, record.ID); err != nil {
		t.Fatal(err)
	}
	// Exact replay after response/outbox GC is answered from the durable command
	// binding and never recreates the external intent.
	if err := queueSecretSyncEvent(ctx, st, log, kek, tenant, "production/deploy", 7, target, "DEPLOY_TOKEN", idemKey, binding, value, nil); err != nil {
		t.Fatalf("exact replay after outbox GC: %v", err)
	}
	if err := queueSecretSyncEvent(ctx, st, log, kek, tenant, "production/deploy", 7, target, "DEPLOY_TOKEN", idemKey, "sha256:principal-b-secret-name-target-key", value, nil); !errors.Is(err, store.ErrIdempotencyConflict) {
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

func newAUD109SecretSyncFixture(t *testing.T, tenantID string) (*store.Store, *events.Log, *seal.LocalKEK) {
	t.Helper()
	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	registeredData, _ := json.Marshal(map[string]string{"name": "AUD-109"})
	registered, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantID, Data: registeredData})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).Apply(ctx, registered); err != nil {
		t.Fatal(err)
	}
	kek, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x79}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kek.Destroy)
	return st, log, kek
}

func queueAUD109SecretSync(
	t *testing.T,
	st *store.Store,
	log *events.Log,
	kek seal.KeyWrapper,
	tenantID, idempotencyKey, remoteKey string,
) (store.SecretSyncJob, orchestrator.Message) {
	t.Helper()
	ctx := context.Background()
	if err := queueSecretSyncEvent(ctx, st, log, kek, tenantID, "production/database", 1,
		"ci", remoteKey, idempotencyKey, "binding:"+idempotencyKey, []byte("value:"+idempotencyKey), nil); err != nil {
		t.Fatal(err)
	}
	jobID := currentSecretSyncJobIDForTest(t, st, tenantID, idempotencyKey)
	job, err := st.GetSecretSyncJob(ctx, tenantID, jobID)
	if err != nil {
		t.Fatal(err)
	}
	record, err := orchestrator.NewOutbox(st).Get(ctx, tenantID, job.OutboxID)
	if err != nil {
		t.Fatal(err)
	}
	return job, orchestrator.Message{
		ID: record.ID, TenantID: tenantID, Destination: record.Destination,
		IdempotencyKey: record.IdempotencyKey, Payload: record.Payload, Attempts: 1,
	}
}

func TestSecretSyncSameNamedTargetsAreTenantCapacityIsolatedAUD110(t *testing.T) {
	const (
		tenantA = "11111111-1111-4111-8111-111111111140"
		tenantB = "22222222-2222-4222-8222-222222222140"
	)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	projector := projections.New(st)
	for _, tenantID := range []string{tenantA, tenantB} {
		data, marshalErr := json.Marshal(map[string]string{"name": "AUD-110 " + tenantID})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		registered, appendErr := log.Append(ctx, events.Event{
			Type: projections.EventTenantRegistered, TenantID: tenantID, Data: data,
		})
		if appendErr != nil {
			t.Fatal(appendErr)
		}
		if applyErr := projector.Apply(ctx, registered); applyErr != nil {
			t.Fatal(applyErr)
		}
	}
	kek, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x7a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kek.Destroy)

	queue := func(tenantID, key, idempotencyKey string) string {
		t.Helper()
		if err := queueSecretSyncEvent(ctx, st, log, kek, tenantID,
			"production/aud110", 1, "ci", key, idempotencyKey,
			"binding:"+idempotencyKey, []byte("value:"+idempotencyKey), nil); err != nil {
			t.Fatal(err)
		}
		return currentSecretSyncJobIDForTest(t, st, tenantID, idempotencyKey)
	}
	aFirstID := queue(tenantA, "TOKEN_A", "aud110-a-first")
	bID := queue(tenantB, "TOKEN_B", "aud110-b")
	aAliasID := queue(tenantA, "/TOKEN_A/", "aud110-a-alias")
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SystemPool().Exec(ctx,
		`UPDATE projection_checkpoint SET applied_seq = $1, updated_at = now() WHERE id = 1`, head); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSecretSyncJob(ctx, tenantA, bID); !store.IsNotFound(err) {
		t.Fatalf("tenant A read tenant B secret-sync job = %v, want RLS-hidden not found", err)
	}

	releaseA := make(chan struct{})
	pusherA := newAUD110SyncPusher(releaseA)
	pusherB := newAUD110SyncPusher(nil)
	secretDispatcher := &secretIntegrationOutboxDispatcher{
		store: st, log: log, kek: kek,
		syncTargets: SecretSyncTargetRegistry{
			tenantA: {"ci": secretsync.NewTarget("ci", pusherA)},
			tenantB: {"ci": secretsync.NewTarget("ci", pusherB)},
		},
	}
	handler := &issuanceDispatcher{secretIntegrations: secretDispatcher}
	outbox := orchestrator.NewOutbox(st,
		orchestrator.WithMaxInFlightPerDestination(1),
		orchestrator.WithMaxInFlightPerTenant(1),
		orchestrator.WithWorkerID("aud110-secret-sync"),
	)
	type result struct {
		processed int
		err       error
	}
	results := make(chan result, 2)
	dispatch := func() {
		processed, dispatchErr := outbox.DispatchScoped(ctx, handler,
			orchestrator.DestinationScope{IncludePrefixes: []string{"secret.sync"}})
		results <- result{processed: processed, err: dispatchErr}
	}
	go dispatch()
	select {
	case <-pusherA.entered:
	case <-ctx.Done():
		t.Fatalf("tenant A ci target did not enter: %v", ctx.Err())
	}
	if got := pusherA.deliveredKeys(); len(got) != 1 || got[0] != "TOKEN_A" {
		t.Fatalf("tenant A calls while first target is blocked = %v, want only TOKEN_A", got)
	}

	go dispatch()
	var progressErr error
	select {
	case <-pusherB.entered:
	case <-time.After(time.Second):
		progressErr = errors.New("tenant B ci target was blocked by tenant A's same-named processing lane")
	}
	if got := pusherA.deliveredKeys(); progressErr == nil && len(got) != 1 {
		progressErr = fmt.Errorf("same-tenant remote-key alias overtook its blocked predecessor: %v", got)
	}
	close(releaseA)

	total := 0
	for range 2 {
		select {
		case result := <-results:
			if result.err != nil && progressErr == nil {
				progressErr = result.err
			}
			total += result.processed
		case <-ctx.Done():
			if progressErr == nil {
				progressErr = fmt.Errorf("AUD-110 dispatchers did not finish: %w", ctx.Err())
			}
		}
	}
	if progressErr != nil {
		t.Fatal(progressErr)
	}
	if total != 3 {
		t.Fatalf("processed secret-sync commands=%d, want two tenant-A FIFO commands plus tenant B", total)
	}
	if got := pusherA.deliveredKeys(); strings.Join(got, ",") != "TOKEN_A,/TOKEN_A/" {
		t.Fatalf("tenant A FIFO receiver calls=%v", got)
	}
	if got := pusherB.deliveredKeys(); len(got) != 1 || got[0] != "TOKEN_B" {
		t.Fatalf("tenant B receiver calls=%v, want its independently configured ci target", got)
	}
	for _, check := range []struct {
		tenantID string
		jobID    string
	}{
		{tenantID: tenantA, jobID: aFirstID},
		{tenantID: tenantB, jobID: bID},
		{tenantID: tenantA, jobID: aAliasID},
	} {
		job, getErr := st.GetSecretSyncJob(ctx, check.tenantID, check.jobID)
		if getErr != nil || job.Status != store.SecretSyncJobDelivered {
			t.Fatalf("delivered job %s/%s = %+v, %v", check.tenantID, check.jobID, job, getErr)
		}
	}
}

func TestSecretSyncRetainedTenantOffboardBlocksReceiverIOBeforeSQLProjectionAUD109(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111132"
	ctx := context.Background()
	st, log, kek := newAUD109SecretSyncFixture(t, tenantID)
	job, message := queueAUD109SecretSync(
		t, st, log, kek, tenantID, "offboard-append-sql-rollback", "TOKEN",
	)
	registration, err := orchestrator.ResolveLiveTenantRegistrationAuthority(ctx, log, st, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	offboardData, err := json.Marshal(map[string]int{"rows_deleted": 1})
	if err != nil {
		t.Fatal(err)
	}
	offboarded, err := log.Append(ctx, events.Event{
		ID:   projections.TenantOffboardEventID(tenantID, registration.EventID),
		Type: projections.EventTenantOffboarded, TenantID: tenantID,
		SchemaVersion: events.DefaultSchemaVersion, Data: offboardData,
	})
	if err != nil {
		t.Fatal(err)
	}
	if offboarded.Sequence <= registration.EventSequence {
		t.Fatalf("offboard sequence=%d, want after registration %d",
			offboarded.Sequence, registration.EventSequence)
	}

	pusher := &outboxSyncPusher{}
	dispatcher := &secretIntegrationOutboxDispatcher{
		store: st, log: log, kek: kek,
		syncTargets: SecretSyncTargetRegistry{tenantID: {
			"ci": secretsync.NewTarget("ci", pusher),
		}},
	}
	handled, err := dispatcher.Deliver(ctx, message)
	if !handled || !orchestrator.IsDeliveryDeferred(err) ||
		!errors.Is(err, errSecretSyncTenantOffboardRetained) {
		t.Fatalf("delivery behind retained offboard handled=%t err=%v, want deferred lifecycle fence",
			handled, err)
	}
	if len(pusher.keys) != 0 {
		t.Fatalf("retained offboard permitted receiver I/O: %v", pusher.keys)
	}
	authority, err := st.SecretSyncReceiverAuthority(ctx, tenantID, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if authority.JobStatus != store.SecretSyncJobPending ||
		authority.EffectState != store.SecretSyncReceiverNoEffect ||
		authority.ReceiverIOStarts != 0 {
		t.Fatalf("retained offboard changed receiver authority: %+v", authority)
	}
	for _, eventID := range []string{
		store.SecretSyncDeliveredEventID(tenantID, job.ID),
		store.SecretSyncFailedEventID(tenantID, job.ID),
	} {
		if _, found, lookupErr := log.EventByID(ctx, eventID); lookupErr != nil || found {
			t.Fatalf("retained offboard produced secret-sync terminal %s = (found:%t, %v)",
				eventID, found, lookupErr)
		}
	}
	if tenant, err := st.GetTenant(ctx, tenantID); err != nil || tenant.EventSeq != registration.EventSequence {
		t.Fatalf("rollback fixture tenant=%+v err=%v, want live SQL registration until offboard recovery",
			tenant, err)
	}
}

func downgradeAUD109PostgresOutboxArtifact(
	t *testing.T,
	artifact []byte,
	mutateSecretSync ...func(map[string]json.RawMessage),
) []byte {
	t.Helper()
	lines := bytes.Split(bytes.TrimSpace(artifact), []byte{'\n'})
	if len(lines) < 2 {
		t.Fatal("postgres-state artifact has no body/trailer")
	}
	digest := trstcrypto.NewSHA256HMACDigest(nil)
	var downgraded bytes.Buffer
	for _, original := range lines[:len(lines)-1] {
		line := append([]byte(nil), original...)
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(line, &envelope); err != nil {
			t.Fatal(err)
		}
		var table string
		_ = json.Unmarshal(envelope["table"], &table)
		if table == "outbox" {
			var row map[string]json.RawMessage
			if err := json.Unmarshal(envelope["row"], &row); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{
				"secret_sync_target_order", "secret_sync_order_from_event",
				"secret_sync_receiver_effect_state", "secret_sync_receiver_io_starts",
				"secret_sync_failure_detail", "secret_sync_failure_attempts",
			} {
				delete(row, field)
			}
			var destination string
			if err := json.Unmarshal(row["destination"], &destination); err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(destination, secretSyncDestinationPrefix) && len(mutateSecretSync) > 0 {
				mutateSecretSync[0](row)
			}
			encodedRow, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			envelope["row"] = encodedRow
			line, err = json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
		}
		downgraded.Write(line)
		downgraded.WriteByte('\n')
		if _, err := digest.Write(line); err != nil {
			t.Fatal(err)
		}
		if _, err := digest.Write([]byte{'\n'}); err != nil {
			t.Fatal(err)
		}
	}
	var trailer map[string]json.RawMessage
	if err := json.Unmarshal(lines[len(lines)-1], &trailer); err != nil {
		t.Fatal(err)
	}
	encodedDigest, err := json.Marshal(digest.SHA256Hex())
	if err != nil {
		t.Fatal(err)
	}
	trailer["sha256"] = encodedDigest
	encodedTrailer, err := json.Marshal(trailer)
	if err != nil {
		t.Fatal(err)
	}
	downgraded.Write(encodedTrailer)
	downgraded.WriteByte('\n')
	return downgraded.Bytes()
}

func setAUD109ReplicaFixture(t *testing.T, st *store.Store, query string, args ...any) {
	t.Helper()
	ctx := context.Background()
	conn, err := st.SystemPool().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SET session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := conn.Exec(context.Background(), `SET session_replication_role = origin`); err != nil {
			t.Errorf("restore session_replication_role: %v", err)
		}
	}()
	if _, err := conn.Exec(ctx, query, args...); err != nil {
		t.Fatal(err)
	}
}

func TestSecretSyncTerminalFailureRequiresExactRetainedQueuedAuthorityAUD109(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111109"
	ctx := context.Background()
	st, log, kek := newAUD109SecretSyncFixture(t, tenantID)
	dispatcher := &secretIntegrationOutboxDispatcher{store: st, log: log, kek: kek}
	definite := orchestrator.DefiniteNoEffect(errors.New("local receiver prerequisite is absent"))

	valid, validMessage := queueAUD109SecretSync(t, st, log, kek, tenantID, "terminal-valid", "TOKEN_VALID")
	validMessage.Attempts = 3
	if handled, err := dispatcher.DeliverTerminalFailure(ctx, validMessage, definite); !handled || err != nil {
		t.Fatalf("valid terminal failure = (%t, %v)", handled, err)
	}
	if job, err := st.GetSecretSyncJob(ctx, tenantID, valid.ID); err != nil || job.Status != store.SecretSyncJobFailed {
		t.Fatalf("valid terminal projection = %+v, %v", job, err)
	}

	forged, forgedMessage := queueAUD109SecretSync(t, st, log, kek, tenantID, "terminal-forged-positive", "TOKEN_FORGED")
	if _, err := st.SystemPool().Exec(ctx,
		`UPDATE secret_sync_jobs SET value_digest = $3 WHERE tenant_id = $1 AND id = $2`,
		tenantID, forged.ID, strings.Repeat("f", 64)); err != nil {
		t.Fatal(err)
	}
	if handled, err := dispatcher.DeliverTerminalFailure(ctx, forgedMessage, definite); !handled || !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("forged positive terminal failure = (%t, %v), want retained-source conflict", handled, err)
	}
	if job, err := st.GetSecretSyncJob(ctx, tenantID, forged.ID); err != nil || job.Status != store.SecretSyncJobPending {
		t.Fatalf("forged positive changed pending job = %+v, %v", job, err)
	}

	legacy, legacyMessage := queueAUD109SecretSync(t, st, log, kek, tenantID, "terminal-negative", "TOKEN_NEGATIVE")
	setAUD109ReplicaFixture(t, st,
		`UPDATE secret_sync_jobs SET target_order = -target_order WHERE tenant_id = $1 AND id = $2`, tenantID, legacy.ID)
	setAUD109ReplicaFixture(t, st,
		`UPDATE outbox SET secret_sync_target_order = -secret_sync_target_order, secret_sync_order_from_event = false WHERE tenant_id = $1 AND id = $2`,
		tenantID, legacy.OutboxID)
	if handled, err := dispatcher.DeliverTerminalFailure(ctx, legacyMessage, definite); !handled || err == nil || !strings.Contains(err.Error(), "migration-derived") {
		t.Fatalf("negative pending terminal failure = (%t, %v), want non-authoritative rejection", handled, err)
	}
	if job, err := st.GetSecretSyncJob(ctx, tenantID, legacy.ID); err != nil || job.Status != store.SecretSyncJobPending {
		t.Fatalf("negative pending job changed = %+v, %v", job, err)
	}
}

func TestSecretSyncAmbiguousMaxAttemptKeepsFIFOBarrierAUD109(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111110"
	ctx := context.Background()
	st, log, kek := newAUD109SecretSyncFixture(t, tenantID)
	older, olderMessage := queueAUD109SecretSync(t, st, log, kek, tenantID, "ambiguous-old", "TOKEN_OLD")
	newer, _ := queueAUD109SecretSync(t, st, log, kek, tenantID, "ambiguous-new", "TOKEN_NEW")
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SystemPool().Exec(ctx, `UPDATE projection_checkpoint SET applied_seq = $1 WHERE id = 1`, head); err != nil {
		t.Fatal(err)
	}
	pusher := &outboxSyncPusher{err: errors.New("receiver response was lost; outcome is unknown")}
	secretDispatcher := &secretIntegrationOutboxDispatcher{
		store: st, log: log, kek: kek,
		syncTargets: SecretSyncTargetRegistry{tenantID: {
			"ci": secretsync.NewTarget("ci", pusher),
		}},
	}
	handler := &issuanceDispatcher{secretIntegrations: secretDispatcher}
	outbox := orchestrator.NewOutbox(st,
		orchestrator.WithMaxAttempts(1),
		orchestrator.WithBackoff(func(int) time.Duration { return 0 }),
	)
	for sweep := 0; sweep < 2; sweep++ {
		processed, err := outbox.DispatchScoped(ctx, handler,
			orchestrator.DestinationScope{IncludePrefixes: []string{"secret.sync."}})
		if err != nil || processed != 1 {
			t.Fatalf("ambiguous sweep %d = (%d, %v), want one old retry", sweep, processed, err)
		}
	}
	if len(pusher.keys) != 2 || pusher.keys[0] != olderMessageDestinationKey(olderMessage) || pusher.keys[1] != olderMessageDestinationKey(olderMessage) {
		t.Fatalf("ambiguous receiver calls=%v, want only old command twice", pusher.keys)
	}
	for _, jobID := range []string{older.ID, newer.ID} {
		job, err := st.GetSecretSyncJob(ctx, tenantID, jobID)
		if err != nil || job.Status != store.SecretSyncJobPending {
			t.Fatalf("ambiguous barrier job %s = %+v, %v", jobID, job, err)
		}
		record, err := outbox.Get(ctx, tenantID, job.OutboxID)
		if err != nil || record.Status != "pending" || record.Attempts != 0 {
			t.Fatalf("ambiguous barrier outbox %s = %+v, %v", jobID, record, err)
		}
	}

	// A successful retry of the SAME idempotent predecessor may close that job,
	// but it cannot prove the earlier generations stopped before they could write.
	// The sticky multi-start count therefore remains a FIFO barrier for successors
	// until a provider-specific reconciler supplies stronger readback proof.
	pusher.err = nil
	processed, err := outbox.DispatchScoped(ctx, handler,
		orchestrator.DestinationScope{IncludePrefixes: []string{"secret.sync."}})
	if err != nil || processed != 1 {
		t.Fatalf("idempotent predecessor retry sweep = (%d, %v), want only old success", processed, err)
	}
	if len(pusher.keys) != 3 || pusher.keys[2] != olderMessageDestinationKey(olderMessage) {
		t.Fatalf("post-ambiguity receiver calls=%v, want only the old idempotent retry", pusher.keys)
	}
	if olderAfter, err := st.GetSecretSyncJob(ctx, tenantID, older.ID); err != nil || olderAfter.Status != store.SecretSyncJobDelivered {
		t.Fatalf("retried old job = %+v, %v", olderAfter, err)
	}
	if newerAfter, err := st.GetSecretSyncJob(ctx, tenantID, newer.ID); err != nil || newerAfter.Status != store.SecretSyncJobPending {
		t.Fatalf("ambiguous successor = %+v, %v, want pending", newerAfter, err)
	}
	if processed, err = outbox.DispatchScoped(ctx, handler,
		orchestrator.DestinationScope{IncludePrefixes: []string{"secret.sync."}}); err != nil || processed != 0 {
		t.Fatalf("terminal multi-start predecessor released successor = (%d, %v), want (0, nil)", processed, err)
	}
}

func olderMessageDestinationKey(message orchestrator.Message) string {
	var payload secretSyncOutboxPayload
	_ = json.Unmarshal(message.Payload, &payload)
	return payload.Key
}

type aud109TerminalBarrierHandler struct {
	base      *issuanceDispatcher
	ready     chan<- struct{}
	release   <-chan struct{}
	readyOnce sync.Once
}

func (h *aud109TerminalBarrierHandler) Deliver(context.Context, orchestrator.Message) error {
	// This reclaimed generation proves its own path stopped before receiver I/O.
	// The prior expired generation is still alive and racing to retain success.
	return orchestrator.DefiniteNoEffect(errors.New("reclaimed worker has no configured receiver"))
}

func (h *aud109TerminalBarrierHandler) DeliverTerminalFailure(
	ctx context.Context,
	message orchestrator.Message,
	cause error,
) error {
	h.readyOnce.Do(func() { close(h.ready) })
	select {
	case <-h.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return h.base.DeliverTerminalFailure(ctx, message, cause)
}

func TestSecretSyncTerminalChoiceSerializesAcrossReplicasAUD109(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111111"
	ctx := context.Background()
	st, log, kek := newAUD109SecretSyncFixture(t, tenantID)
	job, _ := queueAUD109SecretSync(t, st, log, kek, tenantID, "terminal-race", "TOKEN")
	token, proceed, err := st.BeginSecretSyncReceiverIO(
		ctx, tenantID, job.TenantEpoch, job.ID, job.OutboxID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != 1 || !proceed {
		t.Fatalf("receiver start = (%d, %t), want (1, true)", token, proceed)
	}
	delivered := &secretIntegrationOutboxDispatcher{store: st, log: log, kek: kek}
	failed := &secretIntegrationOutboxDispatcher{store: st, log: log, kek: kek}

	start := make(chan struct{})
	results := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	go func() {
		ready.Done()
		<-start
		results <- delivered.appendAndProjectSecretSyncEvidence(ctx,
			store.SecretSyncDeliveredEventID(tenantID, job.ID), tenantID,
			projections.EventSecretSyncDelivered,
			projections.SecretSyncDelivered{ID: job.ID, TenantEpoch: job.TenantEpoch, Attempts: 1})
	}()
	go func() {
		ready.Done()
		<-start
		results <- failed.appendAndProjectSecretSyncEvidence(ctx,
			store.SecretSyncFailedEventID(tenantID, job.ID), tenantID,
			projections.EventSecretSyncFailed,
			projections.SecretSyncFailed{ID: job.ID, TenantEpoch: job.TenantEpoch, Attempts: 1, Error: "closed failure"})
	}()
	ready.Wait()
	close(start)
	var succeeded, conflicted int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, store.ErrIdempotencyConflict):
			conflicted++
		default:
			t.Fatalf("terminal choice race: %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("terminal choice race succeeded=%d conflicted=%d, want 1/1", succeeded, conflicted)
	}
	terminalEvents := 0
	if err := log.Replay(ctx, 1, func(event events.Event) error {
		if event.TenantID == tenantID && (event.Type == projections.EventSecretSyncDelivered || event.Type == projections.EventSecretSyncFailed) {
			terminalEvents++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if terminalEvents != 1 {
		t.Fatalf("retained terminal events=%d, want exactly one", terminalEvents)
	}
}

func TestSecretSyncDualTerminalHistoryFailsBeforeReceiverIOAUD109(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111131"
	ctx := context.Background()
	st, log, kek := newAUD109SecretSyncFixture(t, tenantID)
	job, message := queueAUD109SecretSync(t, st, log, kek, tenantID, "dual-terminal-history", "TOKEN")
	terminal := []struct {
		id        string
		eventType string
		payload   any
	}{
		{
			id:        store.SecretSyncDeliveredEventID(tenantID, job.ID),
			eventType: projections.EventSecretSyncDelivered,
			payload: projections.SecretSyncDelivered{
				ID: job.ID, TenantEpoch: job.TenantEpoch, Attempts: 1,
			},
		},
		{
			id:        store.SecretSyncFailedEventID(tenantID, job.ID),
			eventType: projections.EventSecretSyncFailed,
			payload: projections.SecretSyncFailed{
				ID: job.ID, TenantEpoch: job.TenantEpoch, Attempts: 1, Error: "closed contradictory history",
			},
		},
	}
	for _, candidate := range terminal {
		data, err := json.Marshal(candidate.payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(ctx, events.Event{
			ID: candidate.id, Type: candidate.eventType, TenantID: tenantID,
			SchemaVersion: projections.SecretSyncEventSchemaVersion, Data: data,
		}); err != nil {
			t.Fatal(err)
		}
	}
	pusher := &outboxSyncPusher{}
	dispatcher := &secretIntegrationOutboxDispatcher{
		store: st, log: log, kek: kek,
		syncTargets: SecretSyncTargetRegistry{tenantID: {
			"ci": secretsync.NewTarget("ci", pusher),
		}},
	}
	if err := dispatcher.deliverSecretSync(ctx, message); !errors.Is(err, store.ErrIdempotencyConflict) ||
		!strings.Contains(err.Error(), "both delivered and failed") {
		t.Fatalf("dual retained terminal history error=%v, want fail-closed conflict", err)
	}
	if len(pusher.keys) != 0 {
		t.Fatalf("dual retained terminal history reached receiver I/O: %v", pusher.keys)
	}
	if pending, err := st.GetSecretSyncJob(ctx, tenantID, job.ID); err != nil || pending.Status != store.SecretSyncJobPending {
		t.Fatalf("dual retained terminal history changed pending SQL = %+v, %v", pending, err)
	}
}

func TestSecretSyncExpiredLeaseOverlapRetainsOneTerminalChoiceAUD109(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111113"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, log, kek := newAUD109SecretSyncFixture(t, tenantID)
	job, _ := queueAUD109SecretSync(t, st, log, kek, tenantID, "terminal-expired-overlap", "TOKEN")
	successor, _ := queueAUD109SecretSync(t, st, log, kek, tenantID, "terminal-expired-successor", "TOKEN_NEW")
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SystemPool().Exec(ctx, `UPDATE projection_checkpoint SET applied_seq = $1 WHERE id = 1`, head); err != nil {
		t.Fatal(err)
	}

	// Generation A completes receiver I/O, then pauses before retaining its
	// delivered event. Generation B advances its worker clock beyond A's lease,
	// reclaims the same durable command, and pauses immediately before retaining a
	// typed definite-no-effect failure. Releasing both pauses creates the exact
	// delivered-vs-failed choice race across two worker generations.
	deliveryRelease := make(chan struct{})
	failureRelease := make(chan struct{})
	receiverDone := make(chan struct{})
	var receiverDoneOnce sync.Once
	pusher := &outboxSyncPusher{}
	deliveredDispatcher := &secretIntegrationOutboxDispatcher{
		store: st, log: log, kek: kek,
		syncTargets: SecretSyncTargetRegistry{tenantID: {
			"ci": secretsync.NewTarget("ci", pusher),
		}},
		afterSecretSyncDelivery: func(hookCtx context.Context, _ secretSyncOutboxPayload) error {
			receiverDoneOnce.Do(func() { close(receiverDone) })
			select {
			case <-deliveryRelease:
				return nil
			case <-hookCtx.Done():
				return hookCtx.Err()
			}
		},
	}
	deliveredHandler := &issuanceDispatcher{secretIntegrations: deliveredDispatcher}
	base := time.Now().UTC()
	workerA := orchestrator.NewOutbox(st,
		orchestrator.WithWorkerID("aud109-expired-delivered"),
		orchestrator.WithNow(func() time.Time { return base }),
		orchestrator.WithLeaseTTL(time.Second),
		orchestrator.WithMaxAttempts(10),
	)
	type dispatchResult struct {
		processed int
		err       error
	}
	results := make(chan dispatchResult, 2)
	go func() {
		processed, dispatchErr := workerA.DispatchScoped(ctx, deliveredHandler,
			orchestrator.DestinationScope{IncludePrefixes: []string{"secret.sync."}})
		results <- dispatchResult{processed: processed, err: dispatchErr}
	}()
	select {
	case <-receiverDone:
	case <-ctx.Done():
		t.Fatalf("first worker did not reach the post-receiver overlap seam: %v", ctx.Err())
	}

	terminalReady := make(chan struct{})
	failedDispatcher := &secretIntegrationOutboxDispatcher{store: st, log: log, kek: kek}
	failedHandler := &aud109TerminalBarrierHandler{
		base:    &issuanceDispatcher{secretIntegrations: failedDispatcher},
		ready:   terminalReady,
		release: failureRelease,
	}
	workerB := orchestrator.NewOutbox(st,
		orchestrator.WithWorkerID("aud109-expired-failed"),
		orchestrator.WithNow(func() time.Time { return base.Add(2 * time.Second) }),
		orchestrator.WithLeaseTTL(time.Second),
		orchestrator.WithMaxAttempts(1),
	)
	go func() {
		processed, dispatchErr := workerB.DispatchScoped(ctx, failedHandler,
			orchestrator.DestinationScope{IncludePrefixes: []string{"secret.sync."}})
		results <- dispatchResult{processed: processed, err: dispatchErr}
	}()
	select {
	case <-terminalReady:
	case <-ctx.Done():
		t.Fatalf("second worker did not reclaim the expired lease: %v", ctx.Err())
	}
	if len(pusher.keys) != 1 || pusher.keys[0] != "TOKEN" {
		t.Fatalf("paused overlap receiver calls=%v, want only old command", pusher.keys)
	}
	if pending, err := st.GetSecretSyncJob(ctx, tenantID, successor.ID); err != nil || pending.Status != store.SecretSyncJobPending {
		t.Fatalf("paused overlap successor = %+v, %v, want pending", pending, err)
	}
	// Both workers have now demonstrated that the due successor could not pass
	// the reclaimed predecessor. Move only that successor beyond this sweep's
	// fixed cutoff so each overlapping DispatchScoped call observes exactly one
	// generation; make it due again for the cleanup proof below.
	if _, err := st.SystemPool().Exec(ctx, `
		UPDATE outbox
		   SET next_attempt_at = $3
		 WHERE tenant_id = $1 AND id = $2`, tenantID, successor.OutboxID, base.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Let the generation which actually reached the receiver retain its success
	// before the reclaimed no-I/O generation tries to retain a conflicting
	// failure. Separate release gates keep the test deterministic while the two
	// generations still overlap behind the same expired durable lease.
	close(deliveryRelease)
	for phase := range 2 {
		select {
		case result := <-results:
			if result.processed != 1 {
				t.Fatalf("overlapping worker processed=%d, want one claimed generation", result.processed)
			}
			if result.err != nil && !errors.Is(result.err, store.ErrIdempotencyConflict) &&
				!strings.Contains(result.err.Error(), "lease for row") {
				t.Fatalf("overlapping worker returned unexpected error: %v", result.err)
			}
			if phase == 0 {
				close(failureRelease)
			}
		case <-ctx.Done():
			t.Fatalf("overlapping terminal workers did not finish: %v", ctx.Err())
		}
	}

	terminalType := ""
	terminalEvents := 0
	if err := log.Replay(ctx, 1, func(event events.Event) error {
		if event.TenantID == tenantID && (event.Type == projections.EventSecretSyncDelivered || event.Type == projections.EventSecretSyncFailed) {
			terminalEvents++
			terminalType = event.Type
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if terminalEvents != 1 {
		t.Fatalf("expired-lease overlap retained terminal events=%d, want exactly one", terminalEvents)
	}
	if terminalType != projections.EventSecretSyncDelivered {
		t.Fatalf("expired-lease overlap retained terminal event=%q, want delivered; a reclaimed generation cannot prove the expired receiver had no effect", terminalType)
	}
	retained, err := st.GetSecretSyncJob(ctx, tenantID, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if retained.Status != store.SecretSyncJobDelivered {
		t.Fatalf("expired-lease overlap retained job status=%q, want delivered", retained.Status)
	}
	if pending, err := st.GetSecretSyncJob(ctx, tenantID, successor.ID); err != nil || pending.Status != store.SecretSyncJobPending {
		t.Fatalf("post-overlap successor = %+v, %v, want pending until predecessor cleanup", pending, err)
	}
	if _, err := st.SystemPool().Exec(ctx, `
		UPDATE outbox
		   SET next_attempt_at = $3
		 WHERE tenant_id = $1 AND id = $2`, tenantID, successor.OutboxID, base); err != nil {
		t.Fatal(err)
	}
	cleanup := orchestrator.NewOutbox(st,
		orchestrator.WithWorkerID("aud109-expired-cleanup"),
		orchestrator.WithMaxAttempts(10),
	)
	processed, err := cleanup.DispatchScoped(ctx, deliveredHandler,
		orchestrator.DestinationScope{IncludePrefixes: []string{"secret.sync."}})
	if err != nil || processed != 1 {
		t.Fatalf("post-overlap successor dispatch = (%d, %v), want one; the winning generation already finalized its predecessor", processed, err)
	}
	if delivered, err := st.GetSecretSyncJob(ctx, tenantID, successor.ID); err != nil || delivered.Status != store.SecretSyncJobDelivered {
		t.Fatalf("post-overlap successor = %+v, %v, want delivered", delivered, err)
	}
	if len(pusher.keys) != 2 || pusher.keys[0] != "TOKEN" || pusher.keys[1] != "TOKEN_NEW" {
		t.Fatalf("expired overlap receiver calls=%v, want old then successor", pusher.keys)
	}
}

func TestSecretSyncPriorAmbiguousAttemptBlocksSuccessorAfterPredecessorSucceedsAUD109(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111114"
	ctx := context.Background()
	st, log, kek := newAUD109SecretSyncFixture(t, tenantID)
	older, _ := queueAUD109SecretSync(t, st, log, kek, tenantID, "serial-ambiguous-old", "TOKEN_OLD")
	newer, _ := queueAUD109SecretSync(t, st, log, kek, tenantID, "serial-ambiguous-new", "TOKEN_NEW")
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SystemPool().Exec(ctx, `UPDATE projection_checkpoint SET applied_seq = $1 WHERE id = 1`, head); err != nil {
		t.Fatal(err)
	}

	pusher := &outboxSyncPusher{err: errors.New("receiver response was lost; prior outcome is unknown")}
	dispatcher := &secretIntegrationOutboxDispatcher{
		store: st, log: log, kek: kek,
		syncTargets: SecretSyncTargetRegistry{tenantID: {
			"ci": secretsync.NewTarget("ci", pusher),
		}},
	}
	handler := &issuanceDispatcher{secretIntegrations: dispatcher}
	outbox := orchestrator.NewOutbox(st,
		orchestrator.WithMaxAttempts(2),
		orchestrator.WithBackoff(func(int) time.Duration { return 0 }),
	)
	processed, err := outbox.DispatchScoped(ctx, handler,
		orchestrator.DestinationScope{IncludePrefixes: []string{"secret.sync."}})
	if err != nil || processed != 1 {
		t.Fatalf("first ambiguous attempt = (%d, %v), want one retained old attempt", processed, err)
	}
	authority, err := st.SecretSyncReceiverAuthority(ctx, tenantID, older.ID)
	if err != nil {
		t.Fatal(err)
	}
	if authority.EffectState != store.SecretSyncReceiverEffectPossible {
		t.Fatalf("prior ambiguous attempt state=%q, want effect_possible", authority.EffectState)
	}

	// The next generation stops before receiver I/O because its target vanished.
	// That fact describes only this generation; it must not erase the first
	// generation's durable ambiguity or release the successor.
	dispatcher.syncTargets = SecretSyncTargetRegistry{tenantID: {}}
	processed, err = outbox.DispatchScoped(ctx, handler,
		orchestrator.DestinationScope{IncludePrefixes: []string{"secret.sync."}})
	if err != nil || processed != 1 {
		t.Fatalf("later pre-I/O attempt = (%d, %v), want one deferred old attempt", processed, err)
	}
	for _, jobID := range []string{older.ID, newer.ID} {
		job, getErr := st.GetSecretSyncJob(ctx, tenantID, jobID)
		if getErr != nil || job.Status != store.SecretSyncJobPending {
			t.Fatalf("pre-reconciliation job %s = %+v, %v, want pending FIFO barrier", jobID, job, getErr)
		}
	}
	terminalEvents := 0
	if err := log.Replay(ctx, 1, func(event events.Event) error {
		if event.TenantID == tenantID && (event.Type == projections.EventSecretSyncDelivered || event.Type == projections.EventSecretSyncFailed) {
			terminalEvents++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if terminalEvents != 0 {
		t.Fatalf("later current-generation no-effect proof retained %d terminal events before reconciliation", terminalEvents)
	}
	if len(pusher.keys) != 1 || pusher.keys[0] != "TOKEN_OLD" {
		t.Fatalf("serial ambiguity receiver calls=%v, want only the first old attempt", pusher.keys)
	}

	// Generic target code has no authenticated receiver readback, so it cannot
	// invent an effect_possible -> failed reconciliation. Restoring the target and
	// successfully retrying the predecessor closes that job, but the second start
	// cannot erase the first generation's ambiguity or release the successor.
	pusher.err = nil
	dispatcher.syncTargets = SecretSyncTargetRegistry{tenantID: {
		"ci": secretsync.NewTarget("ci", pusher),
	}}
	processed, err = outbox.DispatchScoped(ctx, handler,
		orchestrator.DestinationScope{IncludePrefixes: []string{"secret.sync."}})
	if err != nil || processed != 1 {
		t.Fatalf("post-retry predecessor dispatch = (%d, %v), want only predecessor", processed, err)
	}
	if olderAfter, getErr := st.GetSecretSyncJob(ctx, tenantID, older.ID); getErr != nil || olderAfter.Status != store.SecretSyncJobDelivered {
		t.Fatalf("retried predecessor = %+v, %v", olderAfter, getErr)
	}
	if newerAfter, getErr := st.GetSecretSyncJob(ctx, tenantID, newer.ID); getErr != nil || newerAfter.Status != store.SecretSyncJobPending {
		t.Fatalf("ambiguous successor = %+v, %v, want pending", newerAfter, getErr)
	}
	if len(pusher.keys) != 2 || pusher.keys[1] != "TOKEN_OLD" {
		t.Fatalf("post-ambiguity receiver calls=%v, want only old idempotent retry", pusher.keys)
	}
	if processed, err = outbox.DispatchScoped(ctx, handler,
		orchestrator.DestinationScope{IncludePrefixes: []string{"secret.sync."}}); err != nil || processed != 0 {
		t.Fatalf("terminal two-start predecessor released successor = (%d, %v), want (0, nil)", processed, err)
	}
}

func TestSecretSyncOnlyFirstTypedNoNetworkStartCanAuthorizeFailureAUD109(t *testing.T) {
	t.Run("only started generation", func(t *testing.T) {
		const tenantID = "11111111-1111-4111-8111-111111111117"
		ctx := context.Background()
		st, log, kek := newAUD109SecretSyncFixture(t, tenantID)
		job, message := queueAUD109SecretSync(t, st, log, kek, tenantID, "first-no-network", "TOKEN")
		pusher := &outboxSyncPusher{err: cloudauth.OfflineDisabled("AWS")}
		dispatcher := &secretIntegrationOutboxDispatcher{
			store: st, log: log, kek: kek,
			syncTargets: SecretSyncTargetRegistry{tenantID: {
				"ci": secretsync.NewTarget("ci", pusher),
			}},
		}
		if err := dispatcher.deliverSecretSync(ctx, message); err != nil {
			t.Fatalf("only-started typed no-network failure: %v", err)
		}
		authority, err := st.SecretSyncReceiverAuthority(ctx, tenantID, job.ID)
		if err != nil {
			t.Fatal(err)
		}
		if authority.EffectState != store.SecretSyncReceiverFailureAuthorized ||
			authority.ReceiverIOStarts != 1 ||
			authority.FailureDetail != "AWS workload identity disabled by air-gap policy" ||
			authority.FailureAttempts != 1 {
			t.Fatalf("only-started failure authority = %+v", authority)
		}
		if failed, err := st.GetSecretSyncJob(ctx, tenantID, job.ID); err != nil || failed.Status != store.SecretSyncJobFailed {
			t.Fatalf("only-started failed job = %+v, %v", failed, err)
		}
	})

	t.Run("prior ambiguous generation", func(t *testing.T) {
		const tenantID = "11111111-1111-4111-8111-111111111118"
		ctx := context.Background()
		st, log, kek := newAUD109SecretSyncFixture(t, tenantID)
		job, message := queueAUD109SecretSync(t, st, log, kek, tenantID, "prior-before-no-network", "TOKEN")
		pusher := &outboxSyncPusher{err: errors.New("receiver response lost")}
		dispatcher := &secretIntegrationOutboxDispatcher{
			store: st, log: log, kek: kek,
			syncTargets: SecretSyncTargetRegistry{tenantID: {
				"ci": secretsync.NewTarget("ci", pusher),
			}},
		}
		if err := dispatcher.deliverSecretSync(ctx, message); err == nil {
			t.Fatal("ambiguous first receiver generation unexpectedly succeeded")
		}
		message.Attempts = 2
		pusher.err = cloudauth.OfflineDisabled("AWS")
		if err := dispatcher.deliverSecretSync(ctx, message); err == nil || !strings.Contains(err.Error(), "remains ambiguous") {
			t.Fatalf("second typed no-network result error=%v, want command-global ambiguity", err)
		}
		authority, err := st.SecretSyncReceiverAuthority(ctx, tenantID, job.ID)
		if err != nil {
			t.Fatal(err)
		}
		if authority.EffectState != store.SecretSyncReceiverEffectPossible || authority.ReceiverIOStarts != 2 ||
			authority.FailureDetail != "" || authority.FailureAttempts != 0 {
			t.Fatalf("prior ambiguity authority = %+v, want sticky possible/count 2", authority)
		}
		if _, found, err := log.EventByID(ctx, store.SecretSyncFailedEventID(tenantID, job.ID)); err != nil || found {
			t.Fatalf("ambiguous typed no-network terminal = (found:%t, %v), want absent", found, err)
		}

		message.Attempts = 3
		pusher.err = nil
		if err := dispatcher.deliverSecretSync(ctx, message); err != nil {
			t.Fatalf("same idempotent predecessor success: %v", err)
		}
		if delivered, err := st.GetSecretSyncJob(ctx, tenantID, job.ID); err != nil || delivered.Status != store.SecretSyncJobDelivered {
			t.Fatalf("same predecessor delivery = %+v, %v", delivered, err)
		}
		authority, err = st.SecretSyncReceiverAuthority(ctx, tenantID, job.ID)
		if err != nil || authority.EffectState != store.SecretSyncReceiverEffectPossible ||
			authority.ReceiverIOStarts != 3 || authority.FailureAttempts != 0 {
			t.Fatalf("delivered multi-generation authority = %+v, %v", authority, err)
		}
	})
}

func TestSecretSyncAmbiguityAuthoritySurvivesPostgresRestoreAndRebuildAUD109(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111119"
	ctx := context.Background()
	st, log, kek := newAUD109SecretSyncFixture(t, tenantID)
	job, _ := queueAUD109SecretSync(t, st, log, kek, tenantID, "backup-ambiguous", "TOKEN")
	for want := int64(1); want <= 2; want++ {
		token, proceed, err := st.BeginSecretSyncReceiverIO(
			ctx, tenantID, job.TenantEpoch, job.ID, job.OutboxID, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !proceed || token != want {
			t.Fatalf("receiver token %d = (%d, %t)", want, token, proceed)
		}
	}
	cut, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var artifact bytes.Buffer
	if _, err := backup.WritePostgresStateAtCut(ctx, st, &artifact, cut); err != nil {
		t.Fatalf("backup ambiguity authority: %v", err)
	}

	// A fresh read model first recreates the queued row from AN-2 with the safe
	// default. Restoring the independent PostgreSQL artifact must put back the
	// non-replayable ambiguity authority exactly.
	restored := newServerTestStore(t)
	if err := projections.New(restored).Rebuild(ctx, log); err != nil {
		t.Fatalf("pre-restore rebuild: %v", err)
	}
	if _, err := backup.RestorePostgresState(ctx, restored, bytes.NewReader(artifact.Bytes())); err != nil {
		t.Fatalf("restore ambiguity authority: %v", err)
	}
	// Restore's custom GUC is transaction-local. A normal owner-role insert after
	// commit must not inherit the restore exception and forge non-initial receiver
	// authority into a new command.
	if _, err := restored.SystemPool().Exec(ctx, `
		INSERT INTO outbox
		       (tenant_id, destination, effect_lane, payload, idempotency_key,
		        secret_sync_target_order, secret_sync_order_from_event,
		        secret_sync_receiver_effect_state, secret_sync_receiver_io_starts)
		VALUES ($1, 'secret.sync.ci', 'secret.sync:ci', $2,
		        'secret-sync-post-restore-marker-probe', $3, true, 'effect_possible', 2)`,
		tenantID, []byte(`{"sealed":"marker-probe"}`), job.TargetOrder+1); err == nil ||
		!strings.Contains(err.Error(), "new secret-sync outbox rows require a positive AN-2 event order") {
		t.Fatalf("post-restore normal insert error=%v, want transaction-local marker rejection", err)
	}
	assertAuthority := func(stage string) {
		t.Helper()
		authority, err := restored.SecretSyncReceiverAuthority(ctx, tenantID, job.ID)
		if err != nil {
			t.Fatalf("%s authority: %v", stage, err)
		}
		if authority.EffectState != store.SecretSyncReceiverEffectPossible ||
			authority.ReceiverIOStarts != 2 || authority.FailureDetail != "" || authority.FailureAttempts != 0 {
			t.Fatalf("%s authority = %+v, want exact effect_possible/count 2", stage, authority)
		}
	}
	assertAuthority("after PostgreSQL restore")
	if err := projections.New(restored).Rebuild(ctx, log); err != nil {
		t.Fatalf("post-restore rebuild: %v", err)
	}
	assertAuthority("after rebuild reattach")
}

func TestSecretSyncFullStateRestoreRemapsReverseSQLIDsByStableCommandAUD109(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111121"
	ctx := context.Background()
	st, log, kek := newAUD109SecretSyncFixture(t, tenantID)
	oldInitial, _ := queueAUD109SecretSync(t, st, log, kek, tenantID, "reverse-id-old", "TOKEN_OLD")
	newInitial, _ := queueAUD109SecretSync(t, st, log, kek, tenantID, "reverse-id-new", "TOKEN_NEW")
	oldEvent, found, err := log.EventByID(ctx, store.SecretSyncQueuedEventID(tenantID, oldInitial.ID))
	if err != nil || !found {
		t.Fatalf("load old queued event = (found:%t, %v)", found, err)
	}
	newEvent, found, err := log.EventByID(ctx, store.SecretSyncQueuedEventID(tenantID, newInitial.ID))
	if err != nil || !found {
		t.Fatalf("load new queued event = (found:%t, %v)", found, err)
	}

	// Recreate the source projection in commit order opposite AN-2 order. The
	// backup therefore gives the older event the larger SQL identity.
	if _, err := st.SystemPool().Exec(ctx, `TRUNCATE TABLE secret_sync_jobs, outbox RESTART IDENTITY`); err != nil {
		t.Fatal(err)
	}
	projector := projections.New(st)
	if err := projector.Apply(ctx, newEvent); err != nil {
		t.Fatalf("project newer command first: %v", err)
	}
	if err := projector.Apply(ctx, oldEvent); err != nil {
		t.Fatalf("project older command second: %v", err)
	}
	sourceOld, err := st.GetSecretSyncJob(ctx, tenantID, oldInitial.ID)
	if err != nil {
		t.Fatal(err)
	}
	sourceNew, err := st.GetSecretSyncJob(ctx, tenantID, newInitial.ID)
	if err != nil {
		t.Fatal(err)
	}
	if sourceOld.OutboxID <= sourceNew.OutboxID || sourceOld.TargetOrder >= sourceNew.TargetOrder {
		t.Fatalf("reverse source ids/orders old=(id:%d order:%d) new=(id:%d order:%d)",
			sourceOld.OutboxID, sourceOld.TargetOrder, sourceNew.OutboxID, sourceNew.TargetOrder)
	}
	if token, proceed, err := st.BeginSecretSyncReceiverIO(
		ctx, tenantID, sourceOld.TenantEpoch, sourceOld.ID, sourceOld.OutboxID, nil,
	); err != nil || !proceed || token != 1 {
		t.Fatalf("seed source receiver authority = (token:%d proceed:%t err:%v)", token, proceed, err)
	}
	cut, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var artifact bytes.Buffer
	if _, err := backup.WritePostgresStateAtCut(ctx, st, &artifact, cut); err != nil {
		t.Fatalf("write reverse-id PostgreSQL artifact: %v", err)
	}

	restored := newServerTestStore(t)
	if err := projections.New(restored).Rebuild(ctx, log); err != nil {
		t.Fatalf("first recovery rebuild: %v", err)
	}
	freshOld, err := restored.GetSecretSyncJob(ctx, tenantID, sourceOld.ID)
	if err != nil {
		t.Fatal(err)
	}
	freshNew, err := restored.GetSecretSyncJob(ctx, tenantID, sourceNew.ID)
	if err != nil {
		t.Fatal(err)
	}
	if freshOld.OutboxID >= freshNew.OutboxID {
		t.Fatalf("fresh replay did not allocate normal SQL order: old=%d new=%d", freshOld.OutboxID, freshNew.OutboxID)
	}
	if _, err := backup.RestorePostgresState(ctx, restored, bytes.NewReader(artifact.Bytes())); err != nil {
		t.Fatalf("restore reverse-id PostgreSQL authority: %v", err)
	}
	assertAssociation := func(stage string, source store.SecretSyncJob) {
		t.Helper()
		job, err := restored.GetSecretSyncJob(ctx, tenantID, source.ID)
		if err != nil {
			t.Fatalf("%s job %s: %v", stage, source.ID, err)
		}
		if job.OutboxID != source.OutboxID {
			t.Fatalf("%s job %s outbox=%d, want source artifact id %d", stage, source.ID, job.OutboxID, source.OutboxID)
		}
		record, err := orchestrator.NewOutbox(restored).Get(ctx, tenantID, job.OutboxID)
		if err != nil {
			t.Fatalf("%s outbox %s: %v", stage, source.ID, err)
		}
		var payload secretSyncOutboxPayload
		if err := json.Unmarshal(record.Payload, &payload); err != nil {
			t.Fatalf("%s decode outbox %s: %v", stage, source.ID, err)
		}
		if payload.ID != source.ID || record.IdempotencyKey != source.IdempotencyKey ||
			record.Destination != "secret.sync."+source.Target {
			t.Fatalf("%s stable association job=%+v outbox=%+v payload=%+v", stage, job, record, payload)
		}
	}
	assertAssociation("after PostgreSQL import", sourceOld)
	assertAssociation("after PostgreSQL import", sourceNew)
	if authority, err := restored.SecretSyncReceiverAuthority(ctx, tenantID, sourceOld.ID); err != nil ||
		authority.EffectState != store.SecretSyncReceiverEffectPossible || authority.ReceiverIOStarts != 1 {
		t.Fatalf("restored old receiver authority = %+v, %v", authority, err)
	}
	if err := projections.New(restored).Rebuild(ctx, log); err != nil {
		t.Fatalf("final recovery rebuild: %v", err)
	}
	assertAssociation("after final rebuild", sourceOld)
	assertAssociation("after final rebuild", sourceNew)
}

func TestSecretSyncLegacyPostgresArtifactReconcilesRebuiltAuthorityAUD109(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111120"
	ctx := context.Background()
	st, log, kek := newAUD109SecretSyncFixture(t, tenantID)
	job, _ := queueAUD109SecretSync(t, st, log, kek, tenantID, "legacy-backup", "TOKEN")
	// A pre-0153 artifact knew only generic claim attempts. Treat both old claims as
	// potentially effectful; never guess that a missing receiver receipt meant no I/O.
	if _, err := st.SystemPool().Exec(ctx,
		`UPDATE outbox SET attempts = 2 WHERE tenant_id = $1 AND id = $2`, tenantID, job.OutboxID); err != nil {
		t.Fatal(err)
	}
	var neutralOutboxID int64
	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		neutralOutboxID, err = orchestrator.NewOutbox(st).Enqueue(ctx, tx, orchestrator.Entry{
			TenantID: tenantID, Destination: "webhook.audit", EffectLane: "webhook.audit",
			IdempotencyKey: "legacy-backup-neutral", Payload: []byte(`{"notice":"queued"}`),
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	cut, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var current bytes.Buffer
	if _, err := backup.WritePostgresStateAtCut(ctx, st, &current, cut); err != nil {
		t.Fatalf("write current postgres artifact: %v", err)
	}
	legacy := downgradeAUD109PostgresOutboxArtifact(t, current.Bytes())

	restored := newServerTestStore(t)
	if err := projections.New(restored).Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild before legacy artifact restore: %v", err)
	}
	if _, err := backup.RestorePostgresState(ctx, restored, bytes.NewReader(legacy)); err != nil {
		t.Fatalf("restore reconciled legacy artifact: %v", err)
	}
	if err := projections.New(restored).Rebuild(ctx, log); err != nil {
		t.Fatalf("final rebuild after legacy artifact restore: %v", err)
	}
	authority, err := restored.SecretSyncReceiverAuthority(ctx, tenantID, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if authority.EffectState != store.SecretSyncReceiverEffectPossible ||
		authority.ReceiverIOStarts != 2 || authority.FailureDetail != "" || authority.FailureAttempts != 0 {
		t.Fatalf("legacy secret-sync authority = %+v, want conservative rebuilt order/count 2", authority)
	}
	var orderNull, sourceNull bool
	var effectState, failureDetail string
	var starts int64
	var failureAttempts int
	if err := restored.SystemPool().QueryRow(ctx, `
		SELECT secret_sync_target_order IS NULL, secret_sync_order_from_event IS NULL,
		       secret_sync_receiver_effect_state, secret_sync_receiver_io_starts,
		       secret_sync_failure_detail, secret_sync_failure_attempts
		  FROM outbox WHERE tenant_id = $1 AND id = $2`, tenantID, neutralOutboxID).Scan(
		&orderNull, &sourceNull, &effectState, &starts, &failureDetail, &failureAttempts); err != nil {
		t.Fatal(err)
	}
	if !orderNull || !sourceNull || effectState != "none" || starts != 0 || failureDetail != "" || failureAttempts != 0 {
		t.Fatalf("legacy non-secret neutral authority=(order-null:%t,source-null:%t,state:%q,starts:%d,detail:%q,failure-attempts:%d)",
			orderNull, sourceNull, effectState, starts, failureDetail, failureAttempts)
	}

	// The same legacy secret-sync row without its already-rebuilt AN-2 job cannot
	// manufacture a SQL-id order or receiver state.
	missingAuthority := newServerTestStore(t)
	if _, err := backup.RestorePostgresState(ctx, missingAuthority, bytes.NewReader(legacy)); err == nil ||
		!strings.Contains(err.Error(), "no exact rebuilt job/event authority") {
		t.Fatalf("legacy restore without rebuilt job error=%v, want fail-closed authority rejection", err)
	}

	// A real old claim increments attempts in the same SQL statement that moves the
	// row to processing. Treating processing/zero as receiver state none would erase
	// an in-flight generation instead of conservatively retaining ambiguity.
	processingWithoutClaim := downgradeAUD109PostgresOutboxArtifact(t, current.Bytes(), func(row map[string]json.RawMessage) {
		row["status"] = json.RawMessage(`"processing"`)
		row["attempts"] = json.RawMessage(`0`)
	})
	contradictory := newServerTestStore(t)
	if err := projections.New(contradictory).Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild before contradictory legacy restore: %v", err)
	}
	if _, err := backup.RestorePostgresState(ctx, contradictory, bytes.NewReader(processingWithoutClaim)); err == nil ||
		!strings.Contains(err.Error(), "processing state has no claim attempt") {
		t.Fatalf("legacy processing/zero restore error=%v, want fail-closed claim-shape rejection", err)
	}
}

func TestSecretSyncLegacyFailedArtifactPreservesAmbiguityThroughRestoreAUD109(t *testing.T) {
	for _, schema := range []struct {
		name    string
		version int
	}{
		{name: "legacy-v1-event", version: events.DefaultSchemaVersion},
		{name: "current-v2-event", version: projections.SecretSyncEventSchemaVersion},
	} {
		t.Run(schema.name, func(t *testing.T) {
			const tenantID = "11111111-1111-4111-8111-111111111122"
			ctx := context.Background()
			st, log, kek := newAUD109SecretSyncFixture(t, tenantID)
			job, _ := queueAUD109SecretSync(t, st, log, kek, tenantID, "legacy-failed-artifact-"+schema.name, "TOKEN")
			if schema.version == events.DefaultSchemaVersion {
				for want := int64(1); want <= 2; want++ {
					token, proceed, err := st.BeginSecretSyncReceiverIO(
						ctx, tenantID, job.TenantEpoch, job.ID, job.OutboxID, nil,
					)
					if err != nil || !proceed || token != want {
						t.Fatalf("legacy failure receiver generation %d = (token:%d proceed:%t err:%v)", want, token, proceed, err)
					}
				}
			}
			failed := projections.SecretSyncFailed{
				ID: job.ID, Attempts: 2, Error: "legacy retry exhaustion",
			}
			if schema.version == projections.SecretSyncEventSchemaVersion {
				failed.TenantEpoch = job.TenantEpoch
			}
			failedData, err := json.Marshal(failed)
			if err != nil {
				t.Fatal(err)
			}
			failedEvent, err := log.Append(ctx, events.Event{
				ID:   store.SecretSyncFailedEventID(tenantID, job.ID),
				Type: projections.EventSecretSyncFailed, TenantID: tenantID,
				SchemaVersion: schema.version, Data: failedData,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := projections.New(st).Apply(ctx, failedEvent); err != nil {
				t.Fatal(err)
			}
			if _, err := st.SystemPool().Exec(ctx,
				`UPDATE outbox SET attempts = 2 WHERE tenant_id = $1 AND id = $2`, tenantID, job.OutboxID); err != nil {
				t.Fatal(err)
			}
			cut, err := log.LastSequence(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var current bytes.Buffer
			if _, err := backup.WritePostgresStateAtCut(ctx, st, &current, cut); err != nil {
				t.Fatalf("write legacy failed artifact: %v", err)
			}
			legacy := downgradeAUD109PostgresOutboxArtifact(t, current.Bytes())

			restored := newServerTestStore(t)
			if err := projections.New(restored).Rebuild(ctx, log); err != nil {
				t.Fatalf("first rebuild before legacy failed restore: %v", err)
			}
			if _, err := backup.RestorePostgresState(ctx, restored, bytes.NewReader(legacy)); err != nil {
				t.Fatalf("restore legacy failed artifact: %v", err)
			}
			if err := projections.New(restored).Rebuild(ctx, log); err != nil {
				t.Fatalf("final rebuild after legacy failed restore: %v", err)
			}
			authority, err := restored.SecretSyncReceiverAuthority(ctx, tenantID, job.ID)
			if err != nil {
				t.Fatal(err)
			}
			if authority.JobStatus != store.SecretSyncJobFailed ||
				authority.EffectState != store.SecretSyncReceiverEffectPossible ||
				authority.ReceiverIOStarts != 2 || authority.FailureDetail != "" || authority.FailureAttempts != 0 {
				t.Fatalf("restored legacy failed authority = %+v, want permanent two-start ambiguity", authority)
			}
			if _, err := restored.OffboardTenant(ctx, tenantID); err == nil {
				t.Fatal("restored legacy failed ambiguity allowed tenant offboard")
			} else {
				var busy *store.TenantSecretSyncNotQuiescentError
				if !errors.As(err, &busy) || busy.JobID != job.ID || busy.ReceiverIOStarts != 2 {
					t.Fatalf("restored legacy failed offboard error = %v, want exact ambiguity barrier", err)
				}
			}
		})
	}
}

func TestSecretSyncFailureAuthorityCrashReconstructsExactEventWithoutIOAUD109(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111115"
	const closedFailure = "external delivery exhausted its retry budget"
	ctx := context.Background()
	st, log, kek := newAUD109SecretSyncFixture(t, tenantID)
	job, message := queueAUD109SecretSync(t, st, log, kek, tenantID, "authority-before-append", "TOKEN")
	crash := errors.New("crash after durable failure authority")
	terminal := &secretIntegrationOutboxDispatcher{
		store: st, log: log, kek: kek,
		afterSecretSyncFailureAuthority: func(_ context.Context, authority store.SecretSyncReceiverAuthority) error {
			if authority.EffectState != store.SecretSyncReceiverFailureAuthorized ||
				authority.ReceiverIOStarts != 0 || authority.FailureDetail != closedFailure ||
				authority.FailureAttempts != 1 {
				return fmt.Errorf("failure authority before crash = %+v", authority)
			}
			return crash
		},
	}
	if handled, err := terminal.DeliverTerminalFailure(ctx, message,
		orchestrator.DefiniteNoEffect(errors.New("local target prerequisite is absent"))); !handled || !errors.Is(err, crash) {
		t.Fatalf("failure-authority crash = (%t, %v), want retained authority then crash", handled, err)
	}
	if _, found, err := log.EventByID(ctx, store.SecretSyncFailedEventID(tenantID, job.ID)); err != nil || found {
		t.Fatalf("failed event before restart = (found:%t, %v), want absent", found, err)
	}
	if pending, err := st.GetSecretSyncJob(ctx, tenantID, job.ID); err != nil || pending.Status != store.SecretSyncJobPending {
		t.Fatalf("job before authority recovery = %+v, %v, want pending", pending, err)
	}

	// A real expired-lease recovery consumes a new generic outbox attempt before it
	// notices the committed authority. The deterministic event must retain the
	// originally authorized count, not rebuild different bytes from this retry.
	message.Attempts++
	pusher := &outboxSyncPusher{}
	restarted := &secretIntegrationOutboxDispatcher{
		store: st, log: log, kek: kek,
		syncTargets: SecretSyncTargetRegistry{tenantID: {
			"ci": secretsync.NewTarget("ci", pusher),
		}},
	}
	if err := restarted.deliverSecretSync(ctx, message); err != nil {
		t.Fatalf("restart recovery from failure authority: %v", err)
	}
	if len(pusher.keys) != 0 {
		t.Fatalf("restart called receiver behind failure authority: %v", pusher.keys)
	}
	canonical, found, err := log.EventByID(ctx, store.SecretSyncFailedEventID(tenantID, job.ID))
	if err != nil || !found {
		t.Fatalf("reconstructed failed event = (found:%t, %v)", found, err)
	}
	var retained projections.SecretSyncFailed
	if err := json.Unmarshal(canonical.Data, &retained); err != nil || retained.Error != closedFailure || retained.Attempts != 1 {
		t.Fatalf("reconstructed failed payload = %+v, %v, want exact frozen detail", retained, err)
	}
	if failed, err := st.GetSecretSyncJob(ctx, tenantID, job.ID); err != nil ||
		failed.Status != store.SecretSyncJobFailed || failed.LastError != closedFailure {
		t.Fatalf("recovered failed job = %+v, %v", failed, err)
	}
}

func TestSecretSyncFailedAppendBeforeProjectionStopsPausedOldGenerationAUD109(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111116"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, log, kek := newAUD109SecretSyncFixture(t, tenantID)
	job, message := queueAUD109SecretSync(t, st, log, kek, tenantID, "append-before-project", "TOKEN")
	ready := make(chan struct{})
	release := make(chan struct{})
	pusher := &outboxSyncPusher{}
	oldGeneration := &secretIntegrationOutboxDispatcher{
		store: st, log: log, kek: kek,
		syncTargets: SecretSyncTargetRegistry{tenantID: {
			"ci": secretsync.NewTarget("ci", pusher),
		}},
		beforeSecretSyncReceiverAuthority: func(waitCtx context.Context, _ secretSyncOutboxPayload) error {
			close(ready)
			select {
			case <-release:
				return nil
			case <-waitCtx.Done():
				return waitCtx.Err()
			}
		},
	}
	oldDone := make(chan error, 1)
	go func() { oldDone <- oldGeneration.deliverSecretSync(ctx, message) }()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatalf("old generation did not reach final pre-I/O gate: %v", ctx.Err())
	}

	crash := errors.New("crash after failed append before projection")
	terminal := &secretIntegrationOutboxDispatcher{
		store: st, log: log, kek: kek,
		afterCanonicalAppend: func(event events.Event) error {
			if event.ID != store.SecretSyncFailedEventID(tenantID, job.ID) {
				return fmt.Errorf("unexpected canonical event %s", event.ID)
			}
			return crash
		},
	}
	if handled, err := terminal.DeliverTerminalFailure(ctx, message,
		orchestrator.DefiniteNoEffect(errors.New("new generation stopped before receiver I/O"))); !handled || !errors.Is(err, crash) {
		t.Fatalf("append-before-projection crash = (%t, %v)", handled, err)
	}
	if pending, err := st.GetSecretSyncJob(ctx, tenantID, job.ID); err != nil || pending.Status != store.SecretSyncJobPending {
		t.Fatalf("job after append-before-project crash = %+v, %v, want pending SQL", pending, err)
	}
	if _, found, err := log.EventByID(ctx, store.SecretSyncFailedEventID(tenantID, job.ID)); err != nil || !found {
		t.Fatalf("retained failed event after crash = (found:%t, %v)", found, err)
	}
	close(release)
	select {
	case err := <-oldDone:
		if err != nil {
			t.Fatalf("old pre-I/O generation recovery: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("old generation did not finish after terminal append: %v", ctx.Err())
	}
	if len(pusher.keys) != 0 {
		t.Fatalf("old generation performed receiver I/O behind retained failure: %v", pusher.keys)
	}
	if failed, err := st.GetSecretSyncJob(ctx, tenantID, job.ID); err != nil || failed.Status != store.SecretSyncJobFailed {
		t.Fatalf("old gate did not project retained failure = %+v, %v", failed, err)
	}
}

func TestSecretSyncPurgedTerminalRebuildUsesProductionDispatcherWithoutOldIOAUD109(t *testing.T) {
	for _, terminalStatus := range []store.SecretSyncJobStatus{store.SecretSyncJobDelivered, store.SecretSyncJobFailed} {
		t.Run(string(terminalStatus), func(t *testing.T) {
			const tenantID = "11111111-1111-4111-8111-111111111112"
			ctx := context.Background()
			st, log, kek := newAUD109SecretSyncFixture(t, tenantID)
			old, _ := queueAUD109SecretSync(t, st, log, kek, tenantID, "purged-old-"+string(terminalStatus), "TOKEN_OLD")
			newer, _ := queueAUD109SecretSync(t, st, log, kek, tenantID, "purged-new-"+string(terminalStatus), "TOKEN_NEW")
			dispatcher := &secretIntegrationOutboxDispatcher{store: st, log: log, kek: kek}
			if terminalStatus == store.SecretSyncJobDelivered {
				_, proceed, err := st.BeginSecretSyncReceiverIO(
					ctx, tenantID, old.TenantEpoch, old.ID, old.OutboxID, nil)
				if err != nil {
					t.Fatal(err)
				}
				if !proceed {
					t.Fatal("purged delivered fixture could not cross receiver boundary")
				}
				if err := dispatcher.appendAndProjectSecretSyncEvidence(ctx,
					store.SecretSyncDeliveredEventID(tenantID, old.ID), tenantID,
					projections.EventSecretSyncDelivered,
					projections.SecretSyncDelivered{ID: old.ID, TenantEpoch: old.TenantEpoch, Attempts: 1}); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := st.WithSecretSyncTerminalChoiceLock(ctx, tenantID, old.ID, func(lockCtx context.Context) error {
					authorized, err := st.AuthorizeSecretSyncPreIOFailure(lockCtx, tenantID, old.ID, old.OutboxID, "closed failure", 1)
					if err == nil && !authorized {
						return errors.New("purged failed fixture lacked pre-I/O authority")
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
				if err := dispatcher.appendAndProjectSecretSyncEvidence(ctx,
					store.SecretSyncFailedEventID(tenantID, old.ID), tenantID,
					projections.EventSecretSyncFailed,
					projections.SecretSyncFailed{ID: old.ID, TenantEpoch: old.TenantEpoch, Attempts: 1, Error: "closed failure"}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := st.SystemPool().Exec(ctx, `
				UPDATE outbox SET status = 'delivered', delivered_at = $3
				 WHERE tenant_id = $1 AND id = $2`, tenantID, old.OutboxID, time.Now().UTC().Add(-72*time.Hour)); err != nil {
				t.Fatal(err)
			}
			if reclaimed, err := outboxgc.New(st, time.Hour).Sweep(ctx); err != nil || reclaimed != 1 {
				t.Fatalf("purge old terminal = (%d, %v), want (1, nil)", reclaimed, err)
			}
			projector := projections.New(st)
			if err := projector.Rebuild(ctx, log); err != nil {
				t.Fatalf("atomic full rebuild: %v", err)
			}

			pusher := &outboxSyncPusher{}
			dispatcher.syncTargets = SecretSyncTargetRegistry{tenantID: {
				"ci": secretsync.NewTarget("ci", pusher),
			}}
			handler := &issuanceDispatcher{secretIntegrations: dispatcher}
			processed, err := orchestrator.NewOutbox(st).DispatchScoped(ctx, handler,
				orchestrator.DestinationScope{IncludePrefixes: []string{"secret.sync."}})
			if err != nil || processed != 2 {
				t.Fatalf("production post-rebuild dispatch = (%d, %v), want two cleanup/progress rows", processed, err)
			}
			if len(pusher.keys) != 1 || pusher.keys[0] != "TOKEN_NEW" {
				t.Fatalf("production post-rebuild receiver calls=%v, want only safe successor", pusher.keys)
			}
			oldAfter, err := st.GetSecretSyncJob(ctx, tenantID, old.ID)
			if err != nil || oldAfter.Status != terminalStatus {
				t.Fatalf("old terminal after rebuild/cleanup = %+v, %v", oldAfter, err)
			}
			newAfter, err := st.GetSecretSyncJob(ctx, tenantID, newer.ID)
			if err != nil || newAfter.Status != store.SecretSyncJobDelivered {
				t.Fatalf("safe successor after rebuild = %+v, %v", newAfter, err)
			}
		})
	}
}
