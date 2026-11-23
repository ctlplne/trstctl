// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// VM98 / AR13: a first lease revoke whose revocation_requested event is retained but
// not projected, followed by a revoke under a different Idempotency-Key.
func TestVerifyAR13SecondKeyRevokeAfterRetainedFirst(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111198"
	ctx := context.Background()
	st, log, kek, outbox, provider, dispatcher := newDynamicSecretOutboxTestStack(t, tenant)
	srv, stop := startSecretIntegrationDispatcher(t, st, outbox, dispatcher)
	defer stop()
	lifecycle, err := newDurableDynamicSecretLifecycle(tenant, []dynsecret.Provider{provider}, st, log, kek, outbox, srv.wakeOutbox)
	if err != nil {
		t.Fatal(err)
	}
	lease, credential, err := lifecycle.IssueBound(ctx, provider.name, "reader", 20*time.Minute, "ar13-issue", "sha256:ar13-issue")
	if err != nil {
		t.Fatal(err)
	}
	secret.Wipe(credential)
	lifecycle.afterCanonicalAppend = func(e events.Event) error {
		if e.Type == projections.EventDynamicSecretLeaseRevocationRequested {
			return errors.New("injected: projection fault after canonical append")
		}
		return nil
	}
	if _, err := lifecycle.RevokeBound(ctx, lease.ID, "ar13-key-a", "sha256:ar13-a"); err == nil {
		t.Fatal("fault was not reached")
	}
	lifecycle.afterCanonicalAppend = nil
	if _, err := lifecycle.RevokeBound(ctx, lease.ID, "ar13-key-b", "sha256:ar13-b"); err != nil {
		t.Fatalf("second-key revoke: %v", err)
	}
	var retained int
	if err := log.Replay(ctx, 0, func(e events.Event) error {
		if e.TenantID == tenant && e.Type == projections.EventDynamicSecretLeaseRevocationRequested {
			retained++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Logf("retained lease-revocation-requested events for one lease: %d", retained)
	catchErr := projections.New(st).ProjectCatchUp(ctx, log)
	t.Logf("ProjectCatchUp error: %v", catchErr)
	time.Sleep(1500 * time.Millisecond)
	t.Logf("provider revocations: %v", provider.Revocations())
	if retained != 1 {
		t.Errorf("one lease produced %d retained revocation-requested events (want 1)", retained)
	}
	if catchErr != nil {
		t.Errorf("catch-up over the retained history failed: %v", catchErr)
	}
	if n := len(provider.Revocations()); n != 1 {
		t.Errorf("provider revoke calls=%d, want 1", n)
	}
}

// VM98 / AR13 without any injected fault: concurrent revokes of one lease under
// distinct Idempotency-Keys (what a client sending parallel requests does).
func TestVerifyAR13ConcurrentDistinctKeyRevokes(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111199"
	ctx := context.Background()
	st, log, kek, outbox, provider, dispatcher := newDynamicSecretOutboxTestStack(t, tenant)
	srv, stop := startSecretIntegrationDispatcher(t, st, outbox, dispatcher)
	defer stop()
	lifecycle, err := newDurableDynamicSecretLifecycle(tenant, []dynsecret.Provider{provider}, st, log, kek, outbox, srv.wakeOutbox)
	if err != nil {
		t.Fatal(err)
	}
	const leases, racers = 6, 8
	for i := 0; i < leases; i++ {
		lease, credential, err := lifecycle.IssueBound(ctx, provider.name, "reader", 20*time.Minute, fmt.Sprintf("ar13c-issue-%d", i), fmt.Sprintf("sha256:ar13c-issue-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		secret.Wipe(credential)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for j := 0; j < racers; j++ {
			wg.Add(1)
			go func(j int) {
				defer wg.Done()
				<-start
				_, _ = lifecycle.RevokeBound(ctx, lease.ID, fmt.Sprintf("ar13c-%d-%d", i, j), fmt.Sprintf("sha256:ar13c-%d-%d", i, j))
			}(j)
		}
		close(start)
		wg.Wait()
	}
	retained := 0
	if err := log.Replay(ctx, 0, func(e events.Event) error {
		if e.TenantID == tenant && e.Type == projections.EventDynamicSecretLeaseRevocationRequested {
			retained++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	catchErr := projections.New(st).ProjectCatchUp(ctx, log)
	t.Logf("leases=%d revocation-requested events=%d ProjectCatchUp error: %v", leases, retained, catchErr)
	if retained != leases {
		t.Errorf("revocation-requested events=%d for %d leases", retained, leases)
	}
	if catchErr != nil {
		t.Errorf("catch-up failed: %v", catchErr)
	}
}
