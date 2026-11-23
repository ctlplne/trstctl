// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// VH40 / AR13: what one tenant's parallel distinct-key lease revokes (no fault
// injected) do to the served projection tail loop, the /readyz projection probe,
// an unrelated tenant's out-of-band event, and the boot read-model catch-up that
// Build runs (catchUpReadModel, server.go:1258 -> :1475).
func TestVerifyVH40BootTailReadinessCrossTenant(t *testing.T) {
	const tenantA = "11111111-1111-4111-8111-111111111140"
	const tenantB = "22222222-2222-4222-8222-222222222240"
	const tenantC = "33333333-3333-4333-8333-333333333340"
	ctx := context.Background()
	st, log, kek, outbox, provider, dispatcher := newDynamicSecretOutboxTestStack(t, tenantA)
	srv, stop := startSecretIntegrationDispatcher(t, st, outbox, dispatcher)
	defer stop()
	lifecycle, err := newDurableDynamicSecretLifecycle(tenantA, []dynsecret.Provider{provider}, st, log, kek, outbox, srv.wakeOutbox)
	if err != nil {
		t.Fatal(err)
	}

	// The served loop (Server.RunProjectionTail): re-run the worker after each error with a 1s backoff.
	tailCtx, cancelTail := context.WithCancel(ctx)
	defer cancelTail()
	tail := projections.NewTailWorker(log, projections.New(st), nil, 0)
	var mu sync.Mutex
	var tailErrs []string
	tailDone := make(chan struct{})
	go func() {
		defer close(tailDone)
		for tailCtx.Err() == nil {
			if err := tail.Run(tailCtx); err != nil && tailCtx.Err() == nil {
				mu.Lock()
				tailErrs = append(tailErrs, err.Error())
				mu.Unlock()
				select {
				case <-tailCtx.Done():
				case <-time.After(time.Second):
				}
			}
		}
	}()
	probe := &Server{store: st, log: log}
	registerOutOfBand := func(tenant string) {
		data, err := json.Marshal(map[string]string{"name": "VH40 other tenant " + tenant[:8]})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenant, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	projectedWithin := func(tenant string, d time.Duration) error {
		deadline := time.Now().Add(d)
		for {
			_, err := st.GetTenant(ctx, tenant)
			if err == nil || time.Now().After(deadline) {
				return err
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Control: before the race the tail projects another tenant's out-of-band event and readiness is clean.
	registerOutOfBand(tenantB)
	if err := projectedWithin(tenantB, 15*time.Second); err != nil {
		t.Fatalf("control: tail did not project tenant B's out-of-band registration: %v", err)
	}
	if err := probe.probeProjectionTail(ctx); err != nil {
		t.Fatalf("control: projection readiness before the race: %v", err)
	}
	t.Logf("control: tenant B out-of-band registration projected by the tail; projection readiness clean")

	// Tenant A: one lease, 8 parallel revokes, each with its own Idempotency-Key.
	lease, credential, err := lifecycle.IssueBound(ctx, provider.name, "reader", 20*time.Minute, "vh40-issue", "sha256:vh40-issue")
	if err != nil {
		t.Fatal(err)
	}
	secret.Wipe(credential)
	start := make(chan struct{})
	var wg sync.WaitGroup
	okRevokes := 0
	for j := 0; j < 8; j++ {
		wg.Add(1)
		go func(j int) {
			defer wg.Done()
			<-start
			if _, err := lifecycle.RevokeBound(ctx, lease.ID, fmt.Sprintf("vh40-%d", j), fmt.Sprintf("sha256:vh40-%d", j)); err == nil {
				mu.Lock()
				okRevokes++
				mu.Unlock()
			}
		}(j)
	}
	close(start)
	wg.Wait()
	t.Logf("tenant A: revoke calls that returned success: %d of 8", okRevokes)

	var readyErr error
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if readyErr = probe.probeProjectionTail(ctx); readyErr != nil {
			break
		}
	}
	t.Logf("/readyz projection probe after tenant A's revokes: %v", readyErr)

	// Tenant C (unrelated) appends out of band after the race.
	registerOutOfBand(tenantC)
	tenantCErr := projectedWithin(tenantC, 10*time.Second)
	t.Logf("tenant C out-of-band registration projected within 10s: err=%v", tenantCErr)
	cancelTail()
	<-tailDone
	mu.Lock()
	if n := len(tailErrs); n > 0 {
		t.Logf("tail worker errors: %d; first: %s", n, tailErrs[0])
		t.Logf("tail worker errors: %d; last: %s", n, tailErrs[n-1])
	} else {
		t.Logf("tail worker errors: 0")
	}
	mu.Unlock()
	var seqTypes []string
	if err := log.Replay(ctx, 0, func(e events.Event) error {
		seqTypes = append(seqTypes, fmt.Sprintf("%d:%s", e.Sequence, e.Type))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Logf("retained history: %v", seqTypes)

	// Restart: the boot read-model catch-up Build runs.
	_, bootErr := catchUpReadModel(ctx, Deps{Store: st, Log: log})
	t.Logf("boot catchUpReadModel: %v", bootErr)

	if readyErr != nil {
		t.Errorf("projection readiness (shared DB row, every replica) failed: %v", readyErr)
	}
	if tenantCErr != nil {
		t.Errorf("an unrelated tenant's out-of-band event was not projected: %v", tenantCErr)
	}
	if bootErr != nil {
		t.Errorf("boot read-model catch-up failed: %v", bootErr)
	}
}
