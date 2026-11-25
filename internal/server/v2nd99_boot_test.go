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

// V2ND-99 (second verifier) for GAP-11-L1: run the serve boot path (Build,
// server.go:1258 -> catchUpReadModel -> ProjectCatchUp, server.go:1488) and the
// projection tail's start-up over the retained history. A second, healthy tenant
// is registered first, so the boot failure is shown to cost a tenant that never
// touched dynamic secrets. restartInsideWindow=true is the control: the process
// restarts after the crash but before the retry budget runs out.
func v2nd99Flow(t *testing.T, tenant, bystander string, restartInsideWindow bool) {
	t.Helper()
	ctx := context.Background()
	st, log, kek, outbox, provider, dispatcher := newDynamicSecretOutboxTestStack(t, tenant)
	if registered, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: bystander,
		Data: []byte(`{"name":"V2ND-99 bystander tenant"}`)}); err != nil {
		t.Fatalf("bystander tenant registration: %v", err)
	} else if err := projections.New(st).Apply(ctx, registered); err != nil {
		t.Fatalf("project bystander tenant registration: %v", err)
	}
	dispatcher.dynamicProviders = DynamicSecretProviderRegistry{tenant: {gap11MethodRevokingProvider{provider}}}
	srv, stop := startSecretIntegrationDispatcher(t, st, outbox, dispatcher)
	lifecycle, err := newDurableDynamicSecretLifecycle(tenant, []dynsecret.Provider{provider}, st, log, kek, outbox, srv.wakeOutbox)
	if err != nil {
		t.Fatal(err)
	}
	lease, credential, err := lifecycle.IssueBound(ctx, provider.name, "reader", 20*time.Minute, "v2nd99-issue", "sha256:v2nd99-issue")
	if err != nil {
		t.Fatal(err)
	}
	secret.Wipe(credential)
	stop()
	if _, err := lifecycle.RevokeBound(ctx, lease.ID, "v2nd99-revoke", "sha256:v2nd99-revoke"); err != nil {
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
	crash := errors.New("v2nd99: crash after canonical append")
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
	boot := func(label string) error {
		booted, err := Build(ctx, Deps{Store: st, Log: log, DefaultProfile: "tls-server"})
		if err == nil {
			// Shutdown closes the shared store pool; defer it so later steps still run.
			t.Cleanup(func() { _ = booted.Shutdown(context.Background()) })
		}
		t.Logf("V2ND-99 %s: serve boot (Build) err=%v", label, err)
		return err
	}
	if restartInsideWindow {
		if err := boot("restart inside the retry window"); err != nil {
			t.Fatalf("control: boot inside the window must succeed: %v", err)
		}
	}
	// Retries 2..9 of the 10-attempt budget, all while the read model is as the boot left it.
	conflicts := 0
	for attempt := 2; attempt <= 9; attempt++ {
		message.Attempts = attempt
		if _, err := dispatcher.Deliver(ctx, message); errors.Is(err, store.ErrIdempotencyConflict) {
			conflicts++
		} else if err != nil {
			t.Logf("retry %d: %v", attempt, err)
		}
	}
	message.Attempts = 10
	if handled, err := dispatcher.DeliverTerminalFailure(ctx, message, errors.New("retry budget spent")); !handled || err != nil {
		t.Fatalf("terminal callback: handled=%t err=%v", handled, err)
	}
	after, _ := st.GetDynamicSecretLease(ctx, tenant, lease.ID)
	t.Logf("V2ND-99 restartInsideWindow=%t: %d/8 retries were idempotency conflicts; status after terminal = %q; provider revocations = %d",
		restartInsideWindow, conflicts, after.RevocationStatus, len(provider.Revocations()))
	if after.RevocationStatus != store.DynamicSecretRevocationCompleted {
		t.Errorf("V2ND-99: lease ends %q although the provider revoked it, want completed", after.RevocationStatus)
	}
	for _, label := range []string{"first boot after the retry budget", "second boot (restart does not heal)"} {
		if err := boot(label); err != nil {
			t.Errorf("V2ND-99: %s fails for the whole deployment (bystander tenant %s included): %v", label, bystander, err)
		}
	}
	tailCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tail := projections.NewTailWorker(log, projections.New(st), nil, time.Second)
	if err := tail.Run(tailCtx); err != nil && tailCtx.Err() == nil {
		t.Errorf("V2ND-99: projection tail cannot start (no tenant's out-of-band events project): %v", err)
	}
}

func TestV2ND99ServeBootAfterRetryBudget(t *testing.T) {
	v2nd99Flow(t, "6a110000-0000-4000-8000-000000000031", "6a110000-0000-4000-8000-000000000032", false)
}

func TestV2ND99ControlRestartInsideRetryWindow(t *testing.T) {
	v2nd99Flow(t, "6a110000-0000-4000-8000-000000000033", "6a110000-0000-4000-8000-000000000034", true)
}
