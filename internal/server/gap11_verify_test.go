// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// VM164 (verifier): how far does GAP-11-L1 reach when the projection tail is alive?
// tailLive=true runs the tail's own catch-up between the crash and the retry
// (what the live TailWorker does within milliseconds of the append).
// tailLive=false keeps the tail behind through the whole retry window, then lets it
// catch up AFTER the terminal callback (a tail that was stalled or lagging >8.5 min).
func vm164Flow(t *testing.T, tenant string, tailLive bool) {
	t.Helper()
	ctx := context.Background()
	st, log, kek, outbox, provider, dispatcher := newDynamicSecretOutboxTestStack(t, tenant)
	dispatcher.dynamicProviders = DynamicSecretProviderRegistry{tenant: {gap11MethodRevokingProvider{provider}}}
	srv, stop := startSecretIntegrationDispatcher(t, st, outbox, dispatcher)
	lifecycle, err := newDurableDynamicSecretLifecycle(tenant, []dynsecret.Provider{provider}, st, log, kek, outbox, srv.wakeOutbox)
	if err != nil {
		t.Fatal(err)
	}
	lease, credential, err := lifecycle.IssueBound(ctx, provider.name, "reader", 20*time.Minute, "vm164-issue", "sha256:vm164-issue")
	if err != nil {
		t.Fatal(err)
	}
	secret.Wipe(credential)
	stop()
	if _, err := lifecycle.RevokeBound(ctx, lease.ID, "vm164-revoke", "sha256:vm164-revoke"); err != nil {
		t.Fatal(err)
	}
	pending, err := st.GetDynamicSecretLease(ctx, tenant, lease.ID)
	if err != nil || pending.RevokeOutboxID == nil {
		t.Fatalf("load pending: %+v, %v", pending, err)
	}
	row, err := outbox.Get(ctx, tenant, *pending.RevokeOutboxID)
	if err != nil {
		t.Fatal(err)
	}
	message := orchestrator.Message{ID: row.ID, TenantID: tenant, Destination: row.Destination, IdempotencyKey: row.IdempotencyKey, Payload: row.Payload, Attempts: 1}
	crash := errors.New("vm164: crash after canonical append")
	dispatcher.afterCanonicalAppend = func(e events.Event) error {
		if e.Type == projections.EventDynamicSecretLeaseRevocationCompleted {
			return crash
		}
		return nil
	}
	if handled, err := dispatcher.Deliver(ctx, message); !handled || !errors.Is(err, crash) {
		t.Fatalf("first revocation must append and crash: handled=%t err=%v", handled, err)
	}
	dispatcher.afterCanonicalAppend = nil
	if tailLive {
		if err := projections.New(st).ProjectCatchUp(ctx, log); err != nil {
			t.Fatalf("tail catch-up after the crash: %v", err)
		}
	}
	message.Attempts = 2
	if handled, err := dispatcher.Deliver(ctx, message); !handled || err != nil {
		t.Logf("retry (tailLive=%t): handled=%t err=%v", tailLive, handled, err)
	}
	got, _ := st.GetDynamicSecretLease(ctx, tenant, lease.ID)
	t.Logf("status after retry (tailLive=%t) = %q", tailLive, got.RevocationStatus)
	message.Attempts = 10
	if handled, err := dispatcher.DeliverTerminalFailure(ctx, message, errors.New("retry budget spent")); !handled || err != nil {
		t.Fatalf("terminal callback: handled=%t err=%v", handled, err)
	}
	after, _ := st.GetDynamicSecretLease(ctx, tenant, lease.ID)
	t.Logf("status after terminal callback (tailLive=%t) = %q, provider revocations = %d", tailLive, after.RevocationStatus, len(provider.Revocations()))
	if after.RevocationStatus != store.DynamicSecretRevocationCompleted {
		t.Errorf("VM164: lease ends %q, want completed", after.RevocationStatus)
	}
	// The tail (or a restart's boot catch-up) now applies the retained history.
	if err := projections.New(st).ProjectCatchUp(ctx, log); err != nil {
		t.Errorf("VM164: tail catch-up over the retained history fails (the live tail would stall on it): %v", err)
	}
}

func TestVM164TailLiveBetweenCrashAndRetry(t *testing.T) {
	vm164Flow(t, "6a110000-0000-4000-8000-000000000021", true)
}

func TestVM164TailBehindThroughRetryWindow(t *testing.T) {
	vm164Flow(t, "6a110000-0000-4000-8000-000000000022", false)
}
