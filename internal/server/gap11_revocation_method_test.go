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

// gap11MethodRevokingProvider reports how its credential ended, as AWS STS
// (deny_policy) and GitHub App/OAuth (token_revoked) providers do.
type gap11MethodRevokingProvider struct{ *issueOutboxProvider }

func (p gap11MethodRevokingProvider) RevokeMethod(ctx context.Context, ref string) (string, error) {
	if err := p.Revoke(ctx, ref); err != nil {
		return "", err
	}
	return "deny_policy", nil
}

var _ dynsecret.MethodRevoker = gap11MethodRevokingProvider{}

// GAP-11-L1: a revocation whose completed event was appended but not projected
// (crash, DB error or delivery deadline between Append and Apply) must finalize
// on the next delivery, as it does for a provider that reports no method.
func TestGAP11L1RevocationRecoveryKeepsProviderMethod(t *testing.T) {
	gap11RevocationRecovery(t, "6a110000-0000-4000-8000-000000000011", true)
}

// Control: the same append-then-crash flow with a provider that reports no method.
func TestGAP11L1ControlRevocationRecoveryWithoutMethod(t *testing.T) {
	gap11RevocationRecovery(t, "6a110000-0000-4000-8000-000000000012", false)
}

func gap11RevocationRecovery(t *testing.T, tenant string, withMethod bool) {
	t.Helper()
	ctx := context.Background()
	st, log, kek, outbox, provider, dispatcher := newDynamicSecretOutboxTestStack(t, tenant)
	if withMethod {
		dispatcher.dynamicProviders = DynamicSecretProviderRegistry{tenant: {gap11MethodRevokingProvider{provider}}}
	}
	srv, stop := startSecretIntegrationDispatcher(t, st, outbox, dispatcher)
	lifecycle, err := newDurableDynamicSecretLifecycle(tenant, []dynsecret.Provider{provider}, st, log, kek, outbox, srv.wakeOutbox)
	if err != nil {
		t.Fatal(err)
	}
	lease, credential, err := lifecycle.IssueBound(ctx, provider.name, "reader", 20*time.Minute, "gap11-issue", "sha256:gap11-issue")
	if err != nil {
		t.Fatal(err)
	}
	secret.Wipe(credential)
	stop()
	if _, err := lifecycle.RevokeBound(ctx, lease.ID, "gap11-revoke", "sha256:gap11-revoke"); err != nil {
		t.Fatal(err)
	}
	pending, err := st.GetDynamicSecretLease(ctx, tenant, lease.ID)
	if err != nil || pending.RevokeOutboxID == nil {
		t.Fatalf("load pending provider removal: %+v, %v", pending, err)
	}
	row, err := outbox.Get(ctx, tenant, *pending.RevokeOutboxID)
	if err != nil {
		t.Fatal(err)
	}
	message := orchestrator.Message{ID: row.ID, TenantID: tenant, Destination: row.Destination, IdempotencyKey: row.IdempotencyKey, Payload: row.Payload, Attempts: 1}
	crash := errors.New("gap11: crash after canonical append")
	dispatcher.afterCanonicalAppend = func(e events.Event) error {
		if e.Type == projections.EventDynamicSecretLeaseRevocationCompleted {
			return crash
		}
		return nil
	}
	if handled, err := dispatcher.Deliver(ctx, message); !handled || !errors.Is(err, crash) {
		t.Fatalf("first revocation must append and then crash: handled=%t err=%v", handled, err)
	}
	dispatcher.afterCanonicalAppend = nil
	message.Attempts = 2
	if handled, err := dispatcher.Deliver(ctx, message); !handled || err != nil {
		t.Errorf("GAP-11-L1: retry after append-then-crash must finalize the retained completed event; handled=%t err=%v", handled, err)
	}
	got, err := st.GetDynamicSecretLease(ctx, tenant, lease.ID)
	if err != nil || got.RevocationStatus != store.DynamicSecretRevocationCompleted {
		t.Errorf("GAP-11-L1: revocation status after retry = %q (err %v), want completed; provider revocations = %d", got.RevocationStatus, err, len(provider.Revocations()))
	}
	if got.RevocationStatus == store.DynamicSecretRevocationPending {
		// The retry budget runs out on the same conflict.
		message.Attempts = 10
		if handled, err := dispatcher.DeliverTerminalFailure(ctx, message, errors.New("retry budget spent")); !handled || err != nil {
			t.Fatalf("terminal callback: handled=%t err=%v", handled, err)
		}
		after, _ := st.GetDynamicSecretLease(ctx, tenant, lease.ID)
		t.Errorf("GAP-11-L1: after the retry budget the lease shows revocation %q although the provider revoked it %d time(s)", after.RevocationStatus, len(provider.Revocations()))
		if err := projections.New(st).Rebuild(ctx, log); err != nil {
			t.Errorf("GAP-11-L1: cold event replay fails on the retained double outcome: %v", err)
		}
	}
}
