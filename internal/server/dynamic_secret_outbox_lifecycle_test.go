// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type issueOutboxProvider struct {
	name     string
	mu       sync.Mutex
	requests []dynsecret.GenerateRequest
	revoked  []string
}

func (p *issueOutboxProvider) Name() string              { return p.name }
func (p *issueOutboxProvider) MaximumTTL() time.Duration { return time.Hour }
func (p *issueOutboxProvider) Generate(_ context.Context, req dynsecret.GenerateRequest) (dynsecret.Credential, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.requests = append(p.requests, req)
	return dynsecret.Credential{BackendRef: "native-principal-for-" + req.LeaseID, Secret: []byte("issued-only-by-outbox-worker")}, nil
}
func (p *issueOutboxProvider) Revoke(_ context.Context, ref string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.revoked = append(p.revoked, ref)
	return nil
}

func (p *issueOutboxProvider) Requests() []dynsecret.GenerateRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]dynsecret.GenerateRequest(nil), p.requests...)
}

func (p *issueOutboxProvider) Revocations() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.revoked...)
}

// PostgreSQL timestamptz stores microseconds, while Go and the immutable event
// payload retain nanoseconds. The worker must bind the outbox command to the
// exact value PostgreSQL can persist instead of rejecting its own round trip
// before the provider call.
func TestDynamicSecretIssueBindingSurvivesPostgresTimestampPrecision(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111125"
	ctx := context.Background()
	st, log, _, outbox, provider, dispatcher := newDynamicSecretOutboxTestStack(t, tenant)

	expiresAt := time.Date(2099, time.July, 12, 4, 5, 6, 123456789, time.UTC)
	hardExpiresAt := expiresAt.Add(30 * time.Minute)
	pending := projections.DynamicSecretLeasePending{
		ID: "lease-postgres-time-precision", IdempotencyKey: "issue-postgres-time-precision",
		RequestBinding: "sha256:postgres-time-precision", Provider: provider.name, Role: "reader",
		ExpiresAt: expiresAt, HardExpiresAt: hardExpiresAt,
	}
	data, err := json.Marshal(pending)
	if err != nil {
		t.Fatal(err)
	}
	event, err := log.Append(ctx, events.Event{
		Type: projections.EventDynamicSecretLeasePending, TenantID: tenant,
		Time: expiresAt.Add(-time.Hour), Data: data,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).Apply(ctx, event); err != nil {
		t.Fatal(err)
	}
	record, err := st.GetDynamicSecretLease(ctx, tenant, pending.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.ExpiresAt.Equal(pending.ExpiresAt) {
		t.Fatal("test did not exercise PostgreSQL's sub-microsecond timestamp normalization")
	}
	message, err := outbox.Get(ctx, tenant, record.IssueOutboxID)
	if err != nil {
		t.Fatal(err)
	}
	var changed projections.DynamicSecretIssueCommand
	if err := json.Unmarshal(message.Payload, &changed); err != nil {
		t.Fatal(err)
	}
	changed.ExpiresAt = changed.ExpiresAt.Add(time.Microsecond)
	changedPayload, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	badHandled, badErr := dispatcher.Deliver(ctx, orchestrator.Message{
		ID: message.ID, TenantID: tenant, Destination: message.Destination,
		IdempotencyKey: message.IdempotencyKey, Payload: changedPayload, Attempts: 1,
	})
	if !badHandled || badErr == nil || len(provider.Requests()) != 0 {
		t.Fatalf("one-microsecond command change handled=%t err=%v provider_calls=%d, want fail-closed before provider", badHandled, badErr, len(provider.Requests()))
	}
	if err := json.Unmarshal(message.Payload, &changed); err != nil {
		t.Fatal(err)
	}
	changed.HardExpiresAt = changed.HardExpiresAt.Add(time.Microsecond)
	changedPayload, err = json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	badHandled, badErr = dispatcher.Deliver(ctx, orchestrator.Message{
		ID: message.ID, TenantID: tenant, Destination: message.Destination,
		IdempotencyKey: message.IdempotencyKey, Payload: changedPayload, Attempts: 1,
	})
	if !badHandled || badErr == nil || len(provider.Requests()) != 0 {
		t.Fatalf("one-microsecond hard-expiry change handled=%t err=%v provider_calls=%d, want fail-closed before provider", badHandled, badErr, len(provider.Requests()))
	}
	handled, err := dispatcher.Deliver(ctx, orchestrator.Message{
		ID: message.ID, TenantID: tenant, Destination: message.Destination,
		IdempotencyKey: message.IdempotencyKey, Payload: message.Payload, Attempts: 1,
	})
	if err != nil || !handled {
		t.Fatalf("PostgreSQL-normalized command binding handled=%t err=%v", handled, err)
	}
	if requests := provider.Requests(); len(requests) != 1 || requests[0].LeaseID != pending.ID {
		t.Fatalf("provider requests=%+v, want one request for %s", requests, pending.ID)
	}
	issued, err := st.GetDynamicSecretLease(ctx, tenant, pending.ID)
	if err != nil {
		t.Fatal(err)
	}
	if issued.State != store.DynamicSecretLeaseActive {
		t.Fatalf("lease state=%s, want active", issued.State)
	}
}

func TestDynamicSecretEpochBoundUpgradeCommandsRejectStaleEpochBeforeProviderAUD108(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111126"
	ctx := context.Background()
	st, log, _, outbox, provider, dispatcher := newDynamicSecretOutboxTestStack(t, tenant)
	projector := projections.New(st)
	epoch, err := st.DynamicSecretTenantEpoch(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	const staleEpoch = "00000000-0000-4000-8000-00000000dead"
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	pending := projections.DynamicSecretLeasePending{
		ID: "lease-aud108-upgrade-command", IdempotencyKey: "aud108-upgrade-command",
		RequestBinding: "sha256:aud108-upgrade-command", Provider: provider.name, Role: "reader",
		ExpiresAt:     time.Date(2099, 8, 11, 13, 0, 0, 0, time.UTC),
		HardExpiresAt: time.Date(2099, 8, 11, 14, 0, 0, 0, time.UTC),
	}
	pendingData, err := json.Marshal(pending)
	if err != nil {
		t.Fatal(err)
	}
	pendingEvent, err := log.Append(ctx, events.Event{
		Type: projections.EventDynamicSecretLeasePending, TenantID: tenant,
		Time: now, Data: pendingData,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, pendingEvent); err != nil {
		t.Fatal(err)
	}
	lease, err := st.GetDynamicSecretLease(ctx, tenant, pending.ID)
	if err != nil {
		t.Fatal(err)
	}
	issueMessage, err := outbox.Get(ctx, tenant, lease.IssueOutboxID)
	if err != nil {
		t.Fatal(err)
	}
	var issueCommand projections.DynamicSecretIssueCommand
	if err := json.Unmarshal(issueMessage.Payload, &issueCommand); err != nil {
		t.Fatal(err)
	}
	if issueCommand.TenantEpoch != epoch ||
		issueMessage.IdempotencyKey != store.DynamicSecretIssueOutboxIdempotencyKey(epoch, pending.ID) {
		t.Fatalf("upgraded issue command = epoch:%q key:%q, want epoch:%q canonical key",
			issueCommand.TenantEpoch, issueMessage.IdempotencyKey, epoch)
	}
	staleIssue := issueCommand
	staleIssue.TenantEpoch = staleEpoch
	staleIssuePayload, err := json.Marshal(staleIssue)
	if err != nil {
		t.Fatal(err)
	}
	issueDelivery := orchestrator.Message{
		ID: issueMessage.ID, TenantID: issueMessage.TenantID, Destination: issueMessage.Destination,
		IdempotencyKey: issueMessage.IdempotencyKey, Payload: issueMessage.Payload, Attempts: 1,
	}
	staleIssueMessage := issueDelivery
	staleIssueMessage.IdempotencyKey = store.DynamicSecretIssueOutboxIdempotencyKey(staleEpoch, pending.ID)
	staleIssueMessage.Payload = staleIssuePayload
	if handled, err := dispatcher.Deliver(ctx, staleIssueMessage); !handled || err == nil {
		t.Fatalf("stale-epoch issue dispatch = (handled:%t err:%v), want fail closed", handled, err)
	}
	if calls := len(provider.Requests()); calls != 0 {
		t.Fatalf("stale-epoch issue made %d provider calls, want zero", calls)
	}
	if handled, err := dispatcher.Deliver(ctx, issueDelivery); !handled || err != nil {
		t.Fatalf("exact upgraded issue dispatch = (handled:%t err:%v)", handled, err)
	}
	if calls := len(provider.Requests()); calls != 1 {
		t.Fatalf("exact upgraded issue made %d provider calls, want one", calls)
	}

	issued, err := st.GetDynamicSecretLease(ctx, tenant, pending.ID)
	if err != nil {
		t.Fatal(err)
	}
	revokeData, err := json.Marshal(projections.DynamicSecretLeaseRevocationRequested{
		ID: issued.ID, Provider: issued.Provider, BackendRef: issued.BackendRef,
	})
	if err != nil {
		t.Fatal(err)
	}
	revokeEvent, err := log.Append(ctx, events.Event{
		Type: projections.EventDynamicSecretLeaseRevocationRequested, TenantID: tenant,
		Time: now.Add(time.Minute), Data: revokeData,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, revokeEvent); err != nil {
		t.Fatal(err)
	}
	revoked, err := st.GetDynamicSecretLease(ctx, tenant, pending.ID)
	if err != nil || revoked.RevokeOutboxID == nil {
		t.Fatalf("load upgraded revoke command lease = %+v err=%v", revoked, err)
	}
	revokeMessage, err := outbox.Get(ctx, tenant, *revoked.RevokeOutboxID)
	if err != nil {
		t.Fatal(err)
	}
	var revokeCommand dynsecret.RevokeItem
	if err := json.Unmarshal(revokeMessage.Payload, &revokeCommand); err != nil {
		t.Fatal(err)
	}
	if revokeCommand.TenantEpoch != epoch ||
		revokeMessage.IdempotencyKey != store.DynamicSecretRevokeOutboxIdempotencyKey(epoch, pending.ID) {
		t.Fatalf("upgraded revoke command = epoch:%q key:%q, want epoch:%q canonical key",
			revokeCommand.TenantEpoch, revokeMessage.IdempotencyKey, epoch)
	}
	staleRevoke := revokeCommand
	staleRevoke.TenantEpoch = staleEpoch
	staleRevokePayload, err := json.Marshal(staleRevoke)
	if err != nil {
		t.Fatal(err)
	}
	revokeDelivery := orchestrator.Message{
		ID: revokeMessage.ID, TenantID: revokeMessage.TenantID, Destination: revokeMessage.Destination,
		IdempotencyKey: revokeMessage.IdempotencyKey, Payload: revokeMessage.Payload, Attempts: 1,
	}
	staleRevokeMessage := revokeDelivery
	staleRevokeMessage.IdempotencyKey = store.DynamicSecretRevokeOutboxIdempotencyKey(staleEpoch, pending.ID)
	staleRevokeMessage.Payload = staleRevokePayload
	if handled, err := dispatcher.Deliver(ctx, staleRevokeMessage); !handled || err == nil {
		t.Fatalf("stale-epoch revoke dispatch = (handled:%t err:%v), want fail closed", handled, err)
	}
	if calls := len(provider.Revocations()); calls != 0 {
		t.Fatalf("stale-epoch revoke made %d provider calls, want zero", calls)
	}
	if handled, err := dispatcher.Deliver(ctx, revokeDelivery); !handled || err != nil {
		t.Fatalf("exact upgraded revoke dispatch = (handled:%t err:%v)", handled, err)
	}
	if calls := len(provider.Revocations()); calls != 1 {
		t.Fatalf("exact upgraded revoke made %d provider calls, want one", calls)
	}
}

type preparedIssueOutboxProvider struct {
	*issueOutboxProvider
	prepares atomic.Int64
}

func (p *preparedIssueOutboxProvider) Prepare(_ context.Context, req dynsecret.GenerateRequest) ([]byte, error) {
	p.prepares.Add(1)
	return []byte("worker-preparation-for-" + req.LeaseID), nil
}

func (p *preparedIssueOutboxProvider) GeneratePrepared(ctx context.Context, req dynsecret.GenerateRequest, prepared []byte) (dynsecret.Credential, error) {
	if !bytes.Equal(prepared, []byte("worker-preparation-for-"+req.LeaseID)) {
		return dynsecret.Credential{}, errors.New("prepared identity changed before provider mutation")
	}
	return p.Generate(ctx, req)
}

func TestDynamicSecretPreparedAndIssuedHistoryFenceSurvivesDedupeExpiryAUD108(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111128"
	// JetStream enforces a 100 ms minimum duplicate window. Crossing three times
	// that minimum still proves correctness does not depend on broker retention.
	const duplicateWindow = 100 * time.Millisecond
	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx,
		config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")},
		events.WithDuplicateWindowForTesting(duplicateWindow))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	projector := projections.New(st)
	tenantData, err := json.Marshal(map[string]string{"name": "Dynamic Secret Retained Fence"})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenant, Data: tenantData,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, registered); err != nil {
		t.Fatal(err)
	}
	epoch, err := st.DynamicSecretTenantEpoch(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	pending := projections.DynamicSecretLeasePending{
		TenantEpoch: epoch, ID: "lease-retained-provider-fence",
		IdempotencyKey: "issue-retained-provider-fence", RequestBinding: "sha256:retained-provider-fence",
		Provider: "postgres-production", Role: "reader",
		ExpiresAt: now.Add(30 * time.Minute), HardExpiresAt: now.Add(time.Hour),
	}
	pendingData, err := json.Marshal(pending)
	if err != nil {
		t.Fatal(err)
	}
	pendingEvent, err := log.Append(ctx, events.Event{
		ID:   store.DynamicSecretEventID(tenant, epoch, "issue-requested", pending.ID),
		Type: projections.EventDynamicSecretLeasePending, TenantID: tenant,
		Time: now, SchemaVersion: projections.DynamicSecretEventSchemaVersion, Data: pendingData,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, pendingEvent); err != nil {
		t.Fatal(err)
	}
	record, err := st.GetDynamicSecretLease(ctx, tenant, pending.ID)
	if err != nil {
		t.Fatal(err)
	}
	outbox := orchestrator.NewOutbox(st)
	queued, err := outbox.Get(ctx, tenant, record.IssueOutboxID)
	if err != nil {
		t.Fatal(err)
	}
	message := orchestrator.Message{
		ID: queued.ID, TenantID: queued.TenantID, Destination: queued.Destination,
		IdempotencyKey: queued.IdempotencyKey, Payload: queued.Payload, Attempts: 1,
	}
	kek, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x68}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kek.Destroy)
	provider := &preparedIssueOutboxProvider{issueOutboxProvider: &issueOutboxProvider{name: pending.Provider}}
	preparedCrash := errors.New("test crash after prepared append")
	issuedCrash := errors.New("test crash after issued append")
	var crashedPrepared, crashedIssued bool
	dispatcher := &secretIntegrationOutboxDispatcher{
		dynamicProviders: DynamicSecretProviderRegistry{tenant: {provider}},
		kek:              kek, store: st, log: log,
		afterCanonicalAppend: func(event events.Event) error {
			switch event.Type {
			case projections.EventDynamicSecretLeasePrepared:
				if !crashedPrepared {
					crashedPrepared = true
					return preparedCrash
				}
			case projections.EventDynamicSecretLeaseIssued:
				if !crashedIssued {
					crashedIssued = true
					return issuedCrash
				}
			}
			return nil
		},
	}

	if handled, err := dispatcher.Deliver(ctx, message); !handled || !errors.Is(err, preparedCrash) {
		t.Fatalf("prepared append crash = (handled:%t err:%v)", handled, err)
	}
	if provider.prepares.Load() != 1 || len(provider.Requests()) != 0 {
		t.Fatalf("after prepared crash prepares=%d provider_calls=%d, want 1/0",
			provider.prepares.Load(), len(provider.Requests()))
	}
	time.Sleep(3 * duplicateWindow)
	message.Attempts++
	if handled, err := dispatcher.Deliver(ctx, message); !handled || !errors.Is(err, issuedCrash) {
		t.Fatalf("issued append crash = (handled:%t err:%v)", handled, err)
	}
	if provider.prepares.Load() != 1 || len(provider.Requests()) != 1 {
		t.Fatalf("after issued crash prepares=%d provider_calls=%d, want 1/1",
			provider.prepares.Load(), len(provider.Requests()))
	}
	time.Sleep(3 * duplicateWindow)
	message.Attempts++
	if handled, err := dispatcher.Deliver(ctx, message); !handled || err != nil {
		t.Fatalf("retained issued recovery = (handled:%t err:%v)", handled, err)
	}
	if provider.prepares.Load() != 1 || len(provider.Requests()) != 1 {
		t.Fatalf("retained history repeated provider work: prepares=%d calls=%d",
			provider.prepares.Load(), len(provider.Requests()))
	}
	record, err = st.GetDynamicSecretLease(ctx, tenant, pending.ID)
	if err != nil || record.State != store.DynamicSecretLeaseActive || len(record.SealedCredential) == 0 {
		t.Fatalf("recovered lease = %+v err=%v, want active sealed result", record, err)
	}

	revokeOperationID := "revoke-retained-provider-fence"
	revokeRequested := projections.DynamicSecretLeaseRevocationRequested{
		TenantEpoch: epoch, OperationID: revokeOperationID, ID: pending.ID,
		Provider: pending.Provider, BackendRef: record.BackendRef,
	}
	revokeData, err := json.Marshal(revokeRequested)
	if err != nil {
		t.Fatal(err)
	}
	revokeEvent, err := log.Append(ctx, events.Event{
		ID:   store.DynamicSecretEventID(tenant, epoch, "lease-revocation-requested", revokeOperationID),
		Type: projections.EventDynamicSecretLeaseRevocationRequested, TenantID: tenant,
		SchemaVersion: projections.DynamicSecretEventSchemaVersion, Data: revokeData,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, revokeEvent); err != nil {
		t.Fatal(err)
	}
	record, err = st.GetDynamicSecretLease(ctx, tenant, pending.ID)
	if err != nil || record.RevokeOutboxID == nil {
		t.Fatalf("revocation intent = %+v err=%v", record, err)
	}
	revokeQueued, err := outbox.Get(ctx, tenant, *record.RevokeOutboxID)
	if err != nil {
		t.Fatal(err)
	}
	revokeMessage := orchestrator.Message{
		ID: revokeQueued.ID, TenantID: revokeQueued.TenantID, Destination: revokeQueued.Destination,
		IdempotencyKey: revokeQueued.IdempotencyKey, Payload: revokeQueued.Payload, Attempts: 1,
	}
	revocationCrash := errors.New("test crash after revocation completion append")
	crashedRevocation := false
	dispatcher.afterCanonicalAppend = func(event events.Event) error {
		if event.Type == projections.EventDynamicSecretLeaseRevocationCompleted && !crashedRevocation {
			crashedRevocation = true
			return revocationCrash
		}
		return nil
	}
	if handled, err := dispatcher.Deliver(ctx, revokeMessage); !handled || !errors.Is(err, revocationCrash) {
		t.Fatalf("revocation append crash = (handled:%t err:%v)", handled, err)
	}
	if got := len(provider.Revocations()); got != 1 {
		t.Fatalf("revocation calls after append crash=%d, want one", got)
	}
	time.Sleep(3 * duplicateWindow)
	revokeMessage.Attempts++
	if handled, err := dispatcher.Deliver(ctx, revokeMessage); !handled || err != nil {
		t.Fatalf("retained revocation recovery = (handled:%t err:%v)", handled, err)
	}
	if got := len(provider.Revocations()); got != 1 {
		t.Fatalf("retained revocation repeated provider deletion: calls=%d", got)
	}
	record, err = st.GetDynamicSecretLease(ctx, tenant, pending.ID)
	if err != nil || record.RevocationStatus != store.DynamicSecretRevocationCompleted ||
		record.RevocationCompletedAt == nil {
		t.Fatalf("recovered revocation = %+v err=%v", record, err)
	}
}

func TestDurableDynamicSecretIssueIsOutboxOnlyAndCrashReplaySafe(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111119"
	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	projector := projections.New(st)
	tenantData, err := json.Marshal(map[string]string{"name": "Dynamic Secret Outbox Test"})
	if err != nil {
		t.Fatal(err)
	}
	tenantEvent, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenant, Data: tenantData})
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, tenantEvent); err != nil {
		t.Fatal(err)
	}

	kek, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x61}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kek.Destroy)
	provider := &issueOutboxProvider{name: "postgres-production"}
	outbox := orchestrator.NewOutbox(st)
	dispatcher := &secretIntegrationOutboxDispatcher{
		dynamicProviders: DynamicSecretProviderRegistry{tenant: {provider}},
		kek:              kek, store: st, log: log,
	}
	handler := orchestrator.HandlerFunc(func(ctx context.Context, message orchestrator.Message) error {
		handled, err := dispatcher.Deliver(ctx, message)
		if !handled && err == nil {
			return fmt.Errorf("test outbox did not handle %s", message.Destination)
		}
		return err
	})
	set := bulkhead.NewSet(bulkhead.Config{Name: bulkhead.SubsystemOutbox, Workers: 2, Queue: 4})
	srv := &Server{outbox: outbox, obHandler: handler, outboxWake: make(chan struct{}, 1), bulk: set}
	workerCtx, stopWorker := context.WithCancel(ctx)
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		srv.RunDispatcher(workerCtx)
	}()
	t.Cleanup(func() {
		stopWorker()
		<-workerDone
		set.Close()
	})
	lifecycle, err := newDurableDynamicSecretLifecycle(tenant, []dynsecret.Provider{provider}, st, log, kek, outbox, srv.wakeOutbox)
	if err != nil {
		t.Fatal(err)
	}
	const requestBinding = "sha256:authenticated-principal-provider-role-ttl"
	lease, credential, err := lifecycle.IssueBound(ctx, provider.name, "reader", 30*time.Minute, "issue-outbox-once", requestBinding)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(credential)
	if !bytes.Equal(credential, []byte("issued-only-by-outbox-worker")) {
		t.Fatalf("issued credential mismatch")
	}
	requests := provider.Requests()
	if len(requests) != 1 || requests[0].LeaseID != lease.ID || requests[0].Role != "reader" {
		t.Fatalf("provider requests = %+v, want one deterministic worker request", requests)
	}

	record, err := st.GetDynamicSecretLease(ctx, tenant, lease.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != store.DynamicSecretLeaseActive || record.IssueOutboxID == 0 || len(record.SealedCredential) == 0 || bytes.Contains(record.SealedCredential, credential) {
		t.Fatalf("durable issuance result is not active/outbox-linked/ciphertext-only: %+v", record)
	}
	if record.RequestBinding != requestBinding {
		t.Fatalf("durable lease request binding = %q, want %q", record.RequestBinding, requestBinding)
	}
	outboxRecord, err := outbox.Get(ctx, tenant, record.IssueOutboxID)
	if err != nil {
		t.Fatal(err)
	}
	if outboxRecord.Status != "delivered" || outboxRecord.Destination != dynamicSecretIssueDestination {
		t.Fatalf("issue outbox = %+v, want delivered dynsecret.issue", outboxRecord)
	}

	// Simulate the process dying after the issued event/projector committed but
	// before the outbox worker finalized its claim. Redelivery observes the active
	// sealed result and must not call the provider again.
	handled, err := dispatcher.Deliver(ctx, orchestrator.Message{
		TenantID: tenant, Destination: outboxRecord.Destination, IdempotencyKey: outboxRecord.IdempotencyKey,
		Payload: outboxRecord.Payload, Attempts: outboxRecord.Attempts + 1,
	})
	if err != nil || !handled || len(provider.Requests()) != 1 {
		t.Fatalf("finalization replay handled=%t err=%v provider_calls=%d", handled, err, len(provider.Requests()))
	}

	// A new lifecycle instance models an API restart before its own idempotency
	// result committed. It replays the identical sealed credential and does not
	// dispatch or mint another upstream identity.
	restarted, err := newDurableDynamicSecretLifecycle(tenant, []dynsecret.Provider{provider}, st, log, kek, outbox, func() {
		t.Fatal("active lease replay unexpectedly woke the dispatcher")
	})
	if err != nil {
		t.Fatal(err)
	}
	replayedLease, replayed, err := restarted.IssueBound(ctx, provider.name, "reader", 30*time.Minute, "issue-outbox-once", requestBinding)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(replayed)
	if replayedLease.ID != lease.ID || !bytes.Equal(replayed, credential) || len(provider.Requests()) != 1 {
		t.Fatal("restart replay changed the lease/credential or reminted upstream")
	}
	if _, collisionCredential, err := restarted.IssueBound(ctx, "missing-provider", "reader", 30*time.Minute, "issue-outbox-once", "sha256:changed-caller-command"); err == nil || len(collisionCredential) != 0 || len(provider.Requests()) != 1 {
		secret.Wipe(collisionCredential)
		t.Fatalf("durable binding collision err=%v credential_bytes=%d provider_calls=%d, want fail-closed/no credential/one call", err, len(collisionCredential), len(provider.Requests()))
	}

	if err := log.Replay(ctx, 1, func(event events.Event) error {
		if bytes.Contains(event.Data, credential) {
			return fmt.Errorf("plaintext credential appeared in event %s", event.Type)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDurableDynamicSecretConcurrentIssueUsesOneCanonicalIntent(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111122"
	ctx := context.Background()
	st, log, kek, outbox, provider, dispatcher := newDynamicSecretOutboxTestStack(t, tenant)
	srv, stop := startSecretIntegrationDispatcher(t, st, outbox, dispatcher)
	defer stop()
	lifecycle, err := newDurableDynamicSecretLifecycle(tenant, []dynsecret.Provider{provider}, st, log, kek, outbox, srv.wakeOutbox)
	if err != nil {
		t.Fatal(err)
	}

	type result struct {
		lease      dynsecret.Lease
		credential []byte
		err        error
	}
	const callers = 8
	results := make(chan result, callers)
	start := make(chan struct{})
	for range callers {
		go func() {
			<-start
			lease, credential, issueErr := lifecycle.IssueBound(ctx, provider.name, "reader", 30*time.Minute, "concurrent-exact-issue", "sha256:caller-a-provider-role-ttl")
			results <- result{lease: lease, credential: credential, err: issueErr}
		}()
	}
	close(start)
	var first result
	for i := range callers {
		got := <-results
		if got.err != nil {
			t.Fatalf("concurrent caller %d: %v", i, got.err)
		}
		defer secret.Wipe(got.credential)
		if i == 0 {
			first = got
			continue
		}
		if got.lease.ID != first.lease.ID || !got.lease.ExpiresAt.Equal(first.lease.ExpiresAt) || !bytes.Equal(got.credential, first.credential) {
			t.Fatalf("caller %d observed divergent canonical result: lease=%+v", i, got.lease)
		}
	}
	if calls := len(provider.Requests()); calls != 1 {
		t.Fatalf("provider issue calls=%d, want one", calls)
	}
	pendingEvents := 0
	if err := log.Replay(ctx, 1, func(event events.Event) error {
		if event.TenantID == tenant && event.Type == projections.EventDynamicSecretLeasePending {
			pendingEvents++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if pendingEvents != 1 {
		t.Fatalf("canonical pending events=%d, want one", pendingEvents)
	}
	op, err := st.GetDynamicSecretOperationByIdempotencyKey(ctx, tenant, "concurrent-exact-issue")
	if err != nil || op.Status != store.DynamicSecretOperationCompleted || op.LeaseID != first.lease.ID {
		t.Fatalf("durable issue operation=%+v err=%v", op, err)
	}
}

func TestDurableDynamicSecretRenewRevokeReplayAndWorkerCrashFence(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111123"
	ctx := context.Background()
	st, log, kek, outbox, provider, dispatcher := newDynamicSecretOutboxTestStack(t, tenant)
	srv, stop := startSecretIntegrationDispatcher(t, st, outbox, dispatcher)
	defer stop()
	lifecycle, err := newDurableDynamicSecretLifecycle(tenant, []dynsecret.Provider{provider}, st, log, kek, outbox, srv.wakeOutbox)
	if err != nil {
		t.Fatal(err)
	}
	lease, credential, err := lifecycle.IssueBound(ctx, provider.name, "reader", 20*time.Minute, "lifecycle-issue", "sha256:caller-a-issue")
	if err != nil {
		t.Fatal(err)
	}
	secret.Wipe(credential)
	renewed, err := lifecycle.RenewBound(ctx, lease.ID, 5*time.Minute, "lifecycle-renew", "sha256:caller-a-renew-300")
	if err != nil {
		t.Fatal(err)
	}

	restarted, err := newDurableDynamicSecretLifecycle(tenant, []dynsecret.Provider{provider}, st, log, kek, outbox, srv.wakeOutbox)
	if err != nil {
		t.Fatal(err)
	}
	replayedRenewal, err := restarted.RenewBound(ctx, lease.ID, 5*time.Minute, "lifecycle-renew", "sha256:caller-a-renew-300")
	if err != nil || !replayedRenewal.ExpiresAt.Equal(renewed.ExpiresAt) {
		t.Fatalf("restart renewal replay=%+v err=%v, want exact expiry %s", replayedRenewal, err, renewed.ExpiresAt)
	}
	if _, err := restarted.RenewBound(ctx, lease.ID, 5*time.Minute, "lifecycle-renew", "sha256:caller-b-renew-300"); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed renewal caller error=%v, want idempotency conflict", err)
	}

	revoked, err := restarted.RevokeBound(ctx, lease.ID, "lifecycle-revoke", "sha256:caller-a-revoke")
	if err != nil || revoked.State != dynsecret.LeaseRevoked {
		t.Fatalf("revoke result=%+v err=%v", revoked, err)
	}
	deadline := time.Now().Add(3 * time.Second)
	var record store.DynamicSecretLease
	for {
		record, err = st.GetDynamicSecretLease(ctx, tenant, lease.ID)
		if err != nil {
			t.Fatal(err)
		}
		if record.RevocationStatus == store.DynamicSecretRevocationCompleted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("provider revocation did not complete: %+v", record)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(provider.Revocations()) != 1 || record.RevokeOutboxID == nil {
		t.Fatalf("provider revocations=%v outbox=%v", provider.Revocations(), record.RevokeOutboxID)
	}
	outboxRecord, err := outbox.Get(ctx, tenant, *record.RevokeOutboxID)
	if err != nil {
		t.Fatal(err)
	}
	// Model completion-event commit followed by worker death before ACK. The
	// projected completed status must fence the second external call.
	handled, err := dispatcher.Deliver(ctx, orchestrator.Message{
		ID: outboxRecord.ID, TenantID: tenant, Destination: outboxRecord.Destination,
		IdempotencyKey: outboxRecord.IdempotencyKey, Payload: outboxRecord.Payload,
		Attempts: outboxRecord.Attempts + 1,
	})
	if err != nil || !handled || len(provider.Revocations()) != 1 {
		t.Fatalf("post-completion redelivery handled=%t err=%v revocations=%v", handled, err, provider.Revocations())
	}
	replayedRevoke, err := restarted.RevokeBound(ctx, lease.ID, "lifecycle-revoke", "sha256:caller-a-revoke")
	if err != nil || replayedRevoke.State != dynsecret.LeaseRevoked || !replayedRevoke.ExpiresAt.Equal(revoked.ExpiresAt) {
		t.Fatalf("restart revoke replay=%+v err=%v", replayedRevoke, err)
	}
	if _, err := restarted.RevokeBound(ctx, lease.ID, "lifecycle-revoke", "sha256:caller-b-revoke"); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed revoke caller error=%v, want idempotency conflict", err)
	}
	if _, err := restarted.RenewBound(ctx, lease.ID, time.Minute, "lifecycle-revoke", "sha256:caller-a-renew-with-revoke-key"); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("cross-action idempotency reuse error=%v, want conflict", err)
	}
	// A completed renewal owns its original response even after a later revoke.
	afterRevokeRenewReplay, err := restarted.RenewBound(ctx, lease.ID, 5*time.Minute, "lifecycle-renew", "sha256:caller-a-renew-300")
	if err != nil || afterRevokeRenewReplay.State != dynsecret.LeaseActive || !afterRevokeRenewReplay.ExpiresAt.Equal(renewed.ExpiresAt) {
		t.Fatalf("renewal response drifted after later revoke: %+v err=%v", afterRevokeRenewReplay, err)
	}
}

func startSecretIntegrationDispatcher(t *testing.T, st *store.Store, outbox *orchestrator.Outbox, dispatcher *secretIntegrationOutboxDispatcher) (*Server, func()) {
	t.Helper()
	handler := orchestrator.HandlerFunc(func(ctx context.Context, message orchestrator.Message) error {
		handled, err := dispatcher.Deliver(ctx, message)
		if !handled && err == nil {
			return fmt.Errorf("test outbox did not handle %s", message.Destination)
		}
		return err
	})
	set := bulkhead.NewSet(bulkhead.Config{Name: bulkhead.SubsystemOutbox, Workers: 4, Queue: 16})
	srv := &Server{outbox: outbox, obHandler: handler, outboxWake: make(chan struct{}, 1), bulk: set}
	workerCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.RunDispatcher(workerCtx)
	}()
	var once sync.Once
	return srv, func() {
		once.Do(func() {
			cancel()
			<-done
			set.Close()
		})
	}
}

// TestDynamicSecretRequestCannotDriveGlobalOutbox is the AN-6/AN-7 regression
// guard for served issuance. A request may wake the bounded dispatcher and poll
// its own projected lease, but it may never call Dispatch itself. It also must be
// able to complete through a second bounded worker while an unrelated destination
// is slow.
func TestDynamicSecretRequestCannotDriveGlobalOutbox(t *testing.T) {
	t.Run("no worker leaves unrelated and own intent pending", func(t *testing.T) {
		const tenant = "11111111-1111-4111-8111-111111111120"
		ctx := context.Background()
		st, log, kek, outbox, provider, _ := newDynamicSecretOutboxTestStack(t, tenant)
		preparedProvider := &preparedIssueOutboxProvider{issueOutboxProvider: provider}
		unrelatedID := enqueueDynamicSecretOutboxTest(t, ctx, st, outbox, tenant, "connector.unrelated", "unrelated-no-worker")
		srv := &Server{outboxWake: make(chan struct{}, 1)}
		lifecycle, err := newDurableDynamicSecretLifecycle(tenant, []dynsecret.Provider{preparedProvider}, st, log, kek, outbox, srv.wakeOutbox)
		if err != nil {
			t.Fatal(err)
		}

		requestCtx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
		defer cancel()
		_, credential, issueErr := lifecycle.Issue(requestCtx, provider.name, "reader", 30*time.Minute, "no-inline-global-dispatch")
		secret.Wipe(credential)
		if !errors.Is(issueErr, context.DeadlineExceeded) {
			t.Fatalf("issue without dispatcher error=%v, want context deadline while own projection remains pending", issueErr)
		}
		if calls := len(provider.Requests()); calls != 0 {
			t.Fatalf("request goroutine called provider %d times without a dispatcher", calls)
		}
		if prepares := preparedProvider.prepares.Load(); prepares != 0 {
			t.Fatalf("request goroutine prepared provider identity %d times without a dispatcher", prepares)
		}
		unrelated, err := outbox.Get(ctx, tenant, unrelatedID)
		if err != nil {
			t.Fatal(err)
		}
		if unrelated.Status != "pending" || unrelated.Attempts != 0 {
			t.Fatalf("request dispatched unrelated outbox row: %+v", unrelated)
		}
		pending, err := outbox.Pending(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		var ownPending bool
		for _, record := range pending {
			if record.Destination == dynamicSecretIssueDestination && record.Status == "pending" && record.Attempts == 0 {
				ownPending = true
			}
		}
		if len(pending) != 2 || !ownPending {
			t.Fatalf("request should persist exactly unrelated+own pending intents, got %+v", pending)
		}
	})

	t.Run("bounded worker bypasses slow unrelated destination", func(t *testing.T) {
		const tenant = "11111111-1111-4111-8111-111111111121"
		ctx := context.Background()
		st, log, kek, outbox, provider, dispatcher := newDynamicSecretOutboxTestStack(t, tenant)
		preparedProvider := &preparedIssueOutboxProvider{issueOutboxProvider: provider}
		dispatcher.dynamicProviders = DynamicSecretProviderRegistry{tenant: {preparedProvider}}
		slowStarted := make(chan struct{})
		releaseSlow := make(chan struct{})
		slowFinished := make(chan struct{})
		var slowCalls atomic.Int64
		handler := orchestrator.HandlerFunc(func(deliveryCtx context.Context, message orchestrator.Message) error {
			if message.Destination == "connector.slow" {
				slowCalls.Add(1)
				close(slowStarted)
				select {
				case <-releaseSlow:
					close(slowFinished)
					return nil
				case <-deliveryCtx.Done():
					return deliveryCtx.Err()
				}
			}
			handled, err := dispatcher.Deliver(deliveryCtx, message)
			if !handled && err == nil {
				return fmt.Errorf("test outbox did not handle %s", message.Destination)
			}
			return err
		})
		set := bulkhead.NewSet(bulkhead.Config{Name: bulkhead.SubsystemOutbox, Workers: 2, Queue: 4})
		srv := &Server{outbox: outbox, obHandler: handler, outboxWake: make(chan struct{}, 1), bulk: set}
		workerCtx, stopWorker := context.WithCancel(ctx)
		workerDone := make(chan struct{})
		go func() {
			defer close(workerDone)
			srv.RunDispatcher(workerCtx)
		}()
		var releaseOnce sync.Once
		release := func() { releaseOnce.Do(func() { close(releaseSlow) }) }
		t.Cleanup(func() {
			release()
			stopWorker()
			<-workerDone
			set.Close()
		})

		enqueueDynamicSecretOutboxTest(t, ctx, st, outbox, tenant, "connector.slow", "slow-before-lease")
		srv.wakeOutbox()
		select {
		case <-slowStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("bounded dispatcher did not start unrelated slow destination")
		}

		lifecycle, err := newDurableDynamicSecretLifecycle(tenant, []dynsecret.Provider{preparedProvider}, st, log, kek, outbox, srv.wakeOutbox)
		if err != nil {
			t.Fatal(err)
		}
		type issueResult struct {
			leaseID    string
			credential []byte
			err        error
		}
		resultCh := make(chan issueResult, 1)
		requestCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		go func() {
			lease, credential, issueErr := lifecycle.Issue(requestCtx, provider.name, "reader", 30*time.Minute, "bypass-slow-destination")
			resultCh <- issueResult{leaseID: lease.ID, credential: credential, err: issueErr}
		}()
		var result issueResult
		select {
		case result = <-resultCh:
		case <-time.After(2 * time.Second):
			release()
			t.Fatal("lease request blocked behind an unrelated destination")
		}
		defer secret.Wipe(result.credential)
		if result.err != nil || !bytes.Equal(result.credential, []byte("issued-only-by-outbox-worker")) {
			t.Fatalf("lease result err=%v credential=%q", result.err, result.credential)
		}
		select {
		case <-slowFinished:
			t.Fatal("unrelated slow destination finished before the lease; test did not prove independent progress")
		default:
		}
		if calls := slowCalls.Load(); calls != 1 {
			t.Fatalf("unrelated slow destination calls=%d, want one background-worker call", calls)
		}
		if calls := len(provider.Requests()); calls != 1 {
			t.Fatalf("dynamic provider calls=%d, want one bounded-worker call", calls)
		}
		if prepares := preparedProvider.prepares.Load(); prepares != 1 {
			t.Fatalf("dynamic provider preparations=%d, want one bounded-worker preparation", prepares)
		}
		record, err := st.GetDynamicSecretLease(ctx, tenant, result.leaseID)
		if err != nil {
			t.Fatal(err)
		}
		if record.State != store.DynamicSecretLeaseActive || len(record.SealedPreparation) != 0 {
			t.Fatalf("terminal lease retained worker preparation: state=%s sealed_preparation=%d", record.State, len(record.SealedPreparation))
		}
		preparedEvents := 0
		if err := log.Replay(ctx, 1, func(event events.Event) error {
			if event.Type != projections.EventDynamicSecretLeasePrepared || event.TenantID != tenant {
				return nil
			}
			preparedEvents++
			if bytes.Contains(event.Data, []byte("worker-preparation-for-")) {
				return errors.New("worker preparation appeared in event plaintext")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if preparedEvents != 1 {
			t.Fatalf("prepared lifecycle events=%d, want one ciphertext-only event", preparedEvents)
		}
		release()
		select {
		case <-slowFinished:
		case <-time.After(2 * time.Second):
			t.Fatal("unrelated destination did not finish after release")
		}
	})
}

func newDynamicSecretOutboxTestStack(t *testing.T, tenant string) (*store.Store, *events.Log, seal.KeyWrapper, *orchestrator.Outbox, *issueOutboxProvider, *secretIntegrationOutboxDispatcher) {
	t.Helper()
	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	projector := projections.New(st)
	tenantData, err := json.Marshal(map[string]string{"name": "Dynamic Secret Request Isolation Test"})
	if err != nil {
		t.Fatal(err)
	}
	tenantEvent, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenant, Data: tenantData})
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, tenantEvent); err != nil {
		t.Fatal(err)
	}
	kek, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x62}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kek.Destroy)
	provider := &issueOutboxProvider{name: "postgres-production"}
	outbox := orchestrator.NewOutbox(st)
	dispatcher := &secretIntegrationOutboxDispatcher{
		dynamicProviders: DynamicSecretProviderRegistry{tenant: {provider}},
		kek:              kek, store: st, log: log,
	}
	return st, log, kek, outbox, provider, dispatcher
}

func enqueueDynamicSecretOutboxTest(t *testing.T, ctx context.Context, st *store.Store, outbox *orchestrator.Outbox, tenant, destination, idempotencyKey string) int64 {
	t.Helper()
	var id int64
	err := st.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		var enqueueErr error
		id, enqueueErr = outbox.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID: tenant, Destination: destination, IdempotencyKey: idempotencyKey, Payload: []byte(`{}`),
		})
		return enqueueErr
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}
