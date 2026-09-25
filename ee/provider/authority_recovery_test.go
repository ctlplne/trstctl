// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestProviderAuthorityUpgradeRequiresLegacyCaptureBeforeRecovery(t *testing.T) {
	st, log, _ := authorityReplayFixture(t)
	legacy := CustomerID("legacy-suspended")
	// Model the populated pre-receipt database that migration 0224 detects.
	if _, err := st.SystemPool().Exec(t.Context(), `INSERT INTO provider_tenants
		(tenant_id,slug,name,status,created_at,updated_at) VALUES ($1,'legacy-suspended','Legacy','suspended',now(),now())`, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SystemPool().Exec(t.Context(), `UPDATE provider_authority_projection_state SET needs_rebuild=true WHERE tenant_id=$1`, providerAuthorityTenant); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.SystemPool().Exec(context.Background(), `UPDATE provider_authority_projection_state SET needs_rebuild=false WHERE tenant_id=$1`, providerAuthorityTenant)
	})
	customer := CustomerID("upgrade-new-customer")
	event := appendUnprojectedAuthority(t, log, "upgrade-pending", EventDelegationGranted, customer,
		AuthorityEvent{Delegation: &DelegationMutation{OperatorID: "worker", CustomerID: customer, Operation: OpRead}, EffectiveAt: time.Now().UTC()})
	runtime := NewAuthorityRuntime(st, log)
	if err := runtime.Projection.Apply(t.Context(), event); !errors.Is(err, ErrAuthorityRebuildRequired) {
		t.Fatalf("tail recovery bypassed legacy capture: %v", err)
	}
	if got, err := NewPGStore(st).Tenant(t.Context(), legacy); err != nil || got.Status != TenantSuspended {
		t.Fatalf("uncaptured legacy customer was changed: %+v %v", got, err)
	}
	if err := runtime.Bootstrap(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got, err := NewPGStore(st).Tenant(t.Context(), legacy); err != nil || got.Status != TenantSuspended {
		t.Fatalf("bootstrap lost suspended legacy customer: %+v %v", got, err)
	}
	assertReplayAuthority(t, st, "worker", customer, true)
	before, err := log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Bootstrap(t.Context()); err != nil {
		t.Fatal(err)
	}
	if after, err := log.LastSequence(t.Context()); err != nil || after != before {
		t.Fatalf("bootstrap duplicated legacy capture: before=%d after=%d err=%v", before, after, err)
	}
}

func appendUnprojectedAuthority(t *testing.T, log *events.Log, id, typ, customer string, payload AuthorityEvent) events.Event {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	event, err := log.Append(t.Context(), events.Event{ID: id, Type: typ, TenantID: customer, Time: payload.EffectiveAt, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func TestProviderAuthorityRecoveryPreservesMissingAndLaterDecisions(t *testing.T) {
	st, log, sink := authorityReplayFixture(t)
	customer := CustomerID("crash-order")
	payload := AuthorityEvent{Delegation: &DelegationMutation{
		OperatorID: "worker", CustomerID: customer, Operation: OpRead,
	}, EffectiveAt: time.Now().UTC()}
	crash := errors.New("injected post-append crash")
	sink.projection.applyHook = func(context.Context, events.Event) error { return crash }
	if _, err := sink.Append(t.Context(), "grant-before-crash", EventDelegationGranted, customer, payload); !errors.Is(err, ErrMutationPersistence) {
		t.Fatalf("append must remain retryable after projection failure: %v", err)
	}
	sink.projection.applyHook = nil
	if _, err := sink.Append(t.Context(), "later-revoke", EventDelegationRevoked, customer, payload); err != nil {
		t.Fatal(err)
	}
	assertReplayAuthority(t, st, "worker", customer, false)
	if _, err := sink.Append(t.Context(), "grant-before-crash", EventDelegationGranted, customer, payload); err != nil {
		t.Fatal(err)
	}
	assertReplayAuthority(t, st, "worker", customer, false)
	if head, err := log.LastSequence(t.Context()); err != nil || head != 2 {
		t.Fatalf("retry changed source history: head=%d err=%v", head, err)
	}
	var receipts int
	if err := st.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM provider_authority_projection_receipts WHERE tenant_id=$1`, providerAuthorityTenant).Scan(&receipts); err != nil || receipts != 2 {
		t.Fatalf("both ordered decisions need completion receipts: %d, %v", receipts, err)
	}
}

func TestProviderAuthorityLateFirstApplicationIsRecoveredWithoutDroppingCustomer(t *testing.T) {
	st, log, sink := authorityReplayFixture(t)
	now := time.Now().UTC()
	a := CustomerID("late-first-a")
	b := CustomerID("late-first-b")
	first := appendUnprojectedAuthority(t, log, "unprojected-a", EventDelegationGranted, a,
		AuthorityEvent{Delegation: &DelegationMutation{OperatorID: "worker-a", CustomerID: a, Operation: OpRead}, EffectiveAt: now})
	if _, err := sink.Append(t.Context(), "newer-b", EventDelegationGranted, b,
		AuthorityEvent{Delegation: &DelegationMutation{OperatorID: "worker-b", CustomerID: b, Operation: OpRead}, EffectiveAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := NewAuthorityProjection(st).Apply(t.Context(), first); !errors.Is(err, ErrAuthorityRebuildRequired) {
		t.Fatalf("unproved old application must not silently succeed: %v", err)
	}
	// The production runtime's tail has retained source authority and recovers
	// automatically; no operator restart or discarded event is needed.
	if err := NewAuthorityRuntime(st, log).Projection.Apply(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	assertReplayAuthority(t, st, "worker-a", a, true)
	assertReplayAuthority(t, st, "worker-b", b, true)
	assertReplayAuthority(t, st, "worker-a", b, false)
	assertReplayAuthority(t, st, "worker-b", a, false)
}

func TestProviderAuthorityReceiptRollsBackWithItsEffect(t *testing.T) {
	st, log, sink := authorityReplayFixture(t)
	customer := CustomerID("receipt-rollback")
	payload := AuthorityEvent{Delegation: &DelegationMutation{OperatorID: "worker", CustomerID: customer, Operation: OpRead}, EffectiveAt: time.Now().UTC()}
	event := appendUnprojectedAuthority(t, log, "rolled-back-grant", EventDelegationGranted, customer, payload)
	tx, err := st.SystemPool().Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if err := sink.projection.ApplyTx(t.Context(), tx, event); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertReplayAuthority(t, st, "worker", customer, false)
	var receipts int
	if err := st.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM provider_authority_projection_receipts WHERE tenant_id=$1`, providerAuthorityTenant).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatalf("rolled-back state retained a completion receipt: %d, %v", receipts, err)
	}
	if err := NewAuthorityProjection(st).Apply(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	assertReplayAuthority(t, st, "worker", customer, true)
}

func TestProviderAuthorityFailedRecoveryPreservesCurrentState(t *testing.T) {
	st, log, sink := authorityReplayFixture(t)
	customer := CustomerID("failed-recovery")
	payload := AuthorityEvent{Delegation: &DelegationMutation{OperatorID: "worker", CustomerID: customer, Operation: OpRead}, EffectiveAt: time.Now().UTC()}
	grant, err := sink.Append(t.Context(), "grant", EventDelegationGranted, customer, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sink.Append(t.Context(), "revoke", EventDelegationRevoked, customer, payload); err != nil {
		t.Fatal(err)
	}
	sink.projection.applyHook = func(_ context.Context, event events.Event) error {
		if event.Type == EventDelegationRevoked {
			return errors.New("injected recovery failure after grant")
		}
		return nil
	}
	if err := sink.projection.recoverOrdered(t.Context(), log); err == nil {
		t.Fatal("injected failure was not returned")
	}
	sink.projection.applyHook = nil
	assertReplayAuthority(t, st, "worker", customer, false)
	if err := NewAuthorityProjection(st).Apply(t.Context(), grant); err != nil {
		t.Fatal(err)
	}
	assertReplayAuthority(t, st, "worker", customer, false)
	changed := grant
	changed.Time = changed.Time.Add(time.Second)
	if err := sink.projection.Apply(t.Context(), changed); !errors.Is(err, ErrAuthorityRebuildRequired) {
		t.Fatalf("changed envelope reused a completion receipt: %v", err)
	}
	shortLog, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = shortLog.Close() }()
	if err := sink.projection.recoverOrdered(t.Context(), shortLog); !errors.Is(err, ErrAuthorityRebuildRequired) {
		t.Fatalf("short history erased completed decisions: %v", err)
	}
	assertReplayAuthority(t, st, "worker", customer, false)
}

func TestProviderAuthorityConcurrentIdenticalRetriesRemainRevoked(t *testing.T) {
	st, log, sink := authorityReplayFixture(t)
	customer := CustomerID("concurrent-retry")
	payload := AuthorityEvent{Delegation: &DelegationMutation{OperatorID: "worker", CustomerID: customer, Operation: OpRead}, EffectiveAt: time.Now().UTC()}
	first, err := sink.Append(t.Context(), "grant", EventDelegationGranted, customer, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sink.Append(t.Context(), "revoke", EventDelegationRevoked, customer, payload); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 6)
	for range 6 {
		go func() {
			event, err := NewEventMutationSink(log, NewAuthorityProjection(st)).Append(t.Context(), "grant", EventDelegationGranted, customer, payload)
			if err == nil && (event.ID != first.ID || event.Sequence != first.Sequence) {
				err = errors.New("retry changed canonical event")
			}
			results <- err
		}()
	}
	for range 6 {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
	assertReplayAuthority(t, st, "worker", customer, false)
	if head, err := log.LastSequence(t.Context()); err != nil || head != 2 {
		t.Fatalf("concurrent retry minted events: %d, %v", head, err)
	}
}
