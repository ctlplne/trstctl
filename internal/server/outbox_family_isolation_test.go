// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// TestOutboxConnectorSaturationDoesNotStarveOtherFamilies is the adversarial
// AN-7 proof against real PostgreSQL. Two connector calls occupy every connector
// worker. External-CA and notification rows for the SAME tenant must still
// finish, a third connector sweep must shed promptly, and PostgreSQL
// must grant an ACCESS EXCLUSIVE table lock while the calls are blocked. That
// last assertion proves the claim transaction committed before external I/O.
func TestOutboxConnectorSaturationDoesNotStarveOtherFamilies(t *testing.T) {
	if testing.Short() {
		t.Skip("starts embedded PostgreSQL and NATS")
	}
	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}

	set := bulkhead.NewSet(
		bulkhead.Config{Name: bulkhead.SubsystemAPI, Workers: 2, Queue: 8},
		bulkhead.Config{Name: bulkhead.SubsystemOutbox, Workers: 1, Queue: 4},
		bulkhead.Config{Name: bulkhead.SubsystemOutboxExternalCA, Workers: 1, Queue: 4},
		bulkhead.Config{Name: bulkhead.SubsystemOutboxConnectors, Workers: 2, Queue: 0},
		bulkhead.Config{Name: bulkhead.SubsystemOutboxSecrets, Workers: 1, Queue: 4},
		bulkhead.Config{Name: bulkhead.SubsystemOutboxSecretSync, Workers: 1, Queue: 4},
		bulkhead.Config{Name: bulkhead.SubsystemOutboxManagedKeys, Workers: 1, Queue: 4},
		bulkhead.Config{Name: bulkhead.SubsystemOutboxTransparency, Workers: 1, Queue: 4},
		bulkhead.Config{Name: bulkhead.SubsystemOutboxCodeSigning, Workers: 1, Queue: 4},
		bulkhead.Config{Name: bulkhead.SubsystemOutboxNotifications, Workers: 1, Queue: 4},
		bulkhead.Config{Name: bulkhead.SubsystemOutboxTenantSeal, Workers: 1, Queue: 4},
		bulkhead.Config{Name: bulkhead.SubsystemOutboxFleet, Workers: 1, Queue: 4},
	)

	connectorStarted := make(chan string, 2)
	delivered := make(chan string, 8)
	releaseConnectors := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseConnectors) }) }

	handler := orchestrator.HandlerFunc(func(callCtx context.Context, message orchestrator.Message) error {
		if strings.HasPrefix(message.Destination, "connector.") {
			connectorStarted <- message.Destination
			select {
			case <-releaseConnectors:
				return nil
			case <-callCtx.Done():
				return callCtx.Err()
			}
		}
		delivered <- message.Destination
		return nil
	})

	srv, err := Build(ctx, Deps{Store: st, Log: log, Bulkhead: set, OutboxHandler: handler})
	if err != nil {
		release()
		set.Close()
		_ = log.Close()
		t.Fatalf("build control plane: %v", err)
	}
	t.Cleanup(func() {
		release()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	})

	const tenantID = "11111111-1111-1111-1111-111111111111"
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "outbox-family-isolation"}); err != nil {
		t.Fatalf("upsert tenant: %v", err)
	}
	entries := []orchestrator.Entry{
		{TenantID: tenantID, Destination: "connector.deploy", IdempotencyKey: "family-connector-deploy", Payload: []byte(`{}`)},
		{TenantID: tenantID, Destination: "connector.right_size", IdempotencyKey: "family-connector-right-size", Payload: []byte(`{}`)},
		{TenantID: tenantID, Destination: "external-ca.issue", IdempotencyKey: "family-external-ca", Payload: []byte(`{}`)},
		{TenantID: tenantID, Destination: "notification.test", IdempotencyKey: "family-notification", Payload: []byte(`{}`)},
	}
	connectorIDs := make([]int64, 0, 2)
	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		for _, entry := range entries {
			id, enqueueErr := srv.outbox.Enqueue(ctx, tx, entry)
			if enqueueErr != nil {
				return enqueueErr
			}
			if strings.HasPrefix(entry.Destination, "connector.") {
				connectorIDs = append(connectorIDs, id)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("enqueue family rows: %v", err)
	}

	// One dispatcher tick must fan out to both configured connector workers. The
	// old test called dispatchOnce every 10ms while waiting, which also submitted
	// empty sweeps to every OTHER family on every iteration. Under race/coverage
	// that test-generated database storm could delay the second connector claim
	// or keep unrelated pools non-quiescent, measuring the polling loop instead
	// of the production dispatcher (whose wake channel coalesces bursts).
	//
	// Requiring one tick is stronger: if worker-count fan-out or SKIP LOCKED claim
	// concurrency breaks, right_size never starts and this fails directly.
	srv.dispatchOnce(ctx)
	started := map[string]bool{}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for len(started) < 2 {
		select {
		case destination := <-connectorStarted:
			started[destination] = true
		case <-deadline.C:
			t.Fatalf("only connector calls %v started; want deploy and right_size occupying both workers", started)
		}
	}

	wantFast := map[string]bool{
		"external-ca.issue": false,
		"notification.test": false,
	}
	fastDeadline := time.NewTimer(2 * time.Second)
	defer fastDeadline.Stop()
	for remaining := len(wantFast); remaining > 0; {
		select {
		case destination := <-delivered:
			seen, expected := wantFast[destination]
			if !expected {
				t.Fatalf("unexpected non-connector delivery %q", destination)
			}
			if !seen {
				wantFast[destination] = true
				remaining--
			}
		case <-fastDeadline.C:
			t.Fatalf("connector saturation starved other families; delivery state = %#v", wantFast)
		}
	}

	connectorPool := set.Pool(bulkhead.SubsystemOutboxConnectors)
	beforeRejected := connectorPool.Stats().Rejected
	start := time.Now()
	srv.dispatchOnce(ctx)
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("saturated connector tick blocked for %v; want prompt bounded-queue rejection", elapsed)
	}
	if got := connectorPool.Stats().Rejected; got <= beforeRejected {
		t.Fatalf("connector pool rejected count = %d, want > %d after saturated tick", got, beforeRejected)
	}

	// Wait until every non-connector sweep has completed, leaving only the two
	// blocked connector handlers. ACCESS EXCLUSIVE conflicts with every outbox
	// claim/update transaction, so NOWAIT succeeding proves no SQL transaction is
	// held across either external call.
	waitForNonConnectorOutboxPools(t, set)
	lockCtx, cancel := context.WithTimeout(ctx, time.Second)
	tx, err := st.SystemPool().Begin(lockCtx)
	if err != nil {
		cancel()
		t.Fatalf("begin no-open-transaction probe: %v", err)
	}
	if _, err := tx.Exec(lockCtx, `LOCK TABLE outbox IN ACCESS EXCLUSIVE MODE NOWAIT`); err != nil {
		_ = tx.Rollback(context.Background())
		cancel()
		t.Fatalf("outbox transaction remained open during blocked external calls: %v", err)
	}
	for _, id := range connectorIDs {
		var status string
		if err := tx.QueryRow(lockCtx, `SELECT status FROM outbox WHERE id = $1`, id).Scan(&status); err != nil {
			_ = tx.Rollback(context.Background())
			cancel()
			t.Fatalf("read connector row %d under lock: %v", id, err)
		}
		if status != "processing" {
			_ = tx.Rollback(context.Background())
			cancel()
			t.Fatalf("connector row %d status = %q, want processing while external call is blocked", id, status)
		}
	}
	if err := tx.Rollback(lockCtx); err != nil {
		cancel()
		t.Fatalf("rollback no-open-transaction probe: %v", err)
	}
	cancel()

	release()
	for _, id := range connectorIDs {
		waitForOutboxStatus(t, srv.outbox, tenantID, id, "delivered")
	}
}

func waitForNonConnectorOutboxPools(t *testing.T, set *bulkhead.Set) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		allDone := true
		for _, name := range []string{
			bulkhead.SubsystemOutbox,
			bulkhead.SubsystemOutboxExternalCA,
			bulkhead.SubsystemOutboxSecrets,
			bulkhead.SubsystemOutboxManagedKeys,
			bulkhead.SubsystemOutboxTransparency,
			bulkhead.SubsystemOutboxNotifications,
			bulkhead.SubsystemOutboxFleet,
		} {
			stats := set.Pool(name).Stats()
			if stats.Completed != stats.Submitted || stats.Queued != 0 {
				allDone = false
				break
			}
		}
		if allDone {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("non-connector outbox sweeps did not quiesce")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForOutboxStatus(t *testing.T, outbox *orchestrator.Outbox, tenantID string, id int64, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		record, err := outbox.Get(context.Background(), tenantID, id)
		if err != nil {
			t.Fatalf("get outbox row %d: %v", id, err)
		}
		if record.Status == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("outbox row %d status = %q, want %q", id, record.Status, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestOutboxDispatchFamiliesAreDisjointAndComplete(t *testing.T) {
	cases := map[string]string{
		"external-ca.issue":               bulkhead.SubsystemOutboxExternalCA,
		"connector.deploy":                bulkhead.SubsystemOutboxConnectors,
		"connector.right_size":            bulkhead.SubsystemOutboxConnectors,
		"dynsecret.issue":                 bulkhead.SubsystemOutboxSecrets,
		"secret.sync.vault":               bulkhead.SubsystemOutboxSecretSync,
		"managedkey.command":              bulkhead.SubsystemOutboxManagedKeys,
		"transparency.rekor":              bulkhead.SubsystemOutboxTransparency,
		"codesign.command":                bulkhead.SubsystemOutboxCodeSigning,
		"notification.expiry":             bulkhead.SubsystemOutboxNotifications,
		"tenantseal.seal":                 bulkhead.SubsystemOutboxTenantSeal,
		"incident.fleet_reissuance.batch": bulkhead.SubsystemOutboxFleet,
		"revocation.publish":              bulkhead.SubsystemOutbox,
		"acme.dns01.present":              bulkhead.SubsystemOutbox,
		"third-party.destination":         bulkhead.SubsystemOutbox,
	}
	for destination, wantPool := range cases {
		matches := make([]string, 0, 1)
		for _, family := range outboxDispatchFamilies {
			if family.scopeMatches(destination) {
				matches = append(matches, family.pool)
			}
		}
		if len(matches) != 1 || matches[0] != wantPool {
			t.Errorf("destination %q matched pools %v, want only %q", destination, matches, wantPool)
		}
	}
}

func TestOutboxDrainHonorsConfiguredFamilyWorkerLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("starts embedded PostgreSQL and NATS")
	}
	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	set := bulkhead.NewSet(
		bulkhead.Config{Name: bulkhead.SubsystemOutbox, Workers: 2, Queue: 8},
		bulkhead.Config{Name: bulkhead.SubsystemOutboxExternalCA, Workers: 1, Queue: 8},
	)
	started := make(chan string, 3)
	release := make(chan struct{})
	handler := orchestrator.HandlerFunc(func(ctx context.Context, message orchestrator.Message) error {
		started <- message.EffectLane
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	srv, err := Build(ctx, Deps{Store: st, Log: log, Bulkhead: set, OutboxHandler: handler})
	if err != nil {
		close(release)
		set.Close()
		_ = log.Close()
		t.Fatalf("build control plane: %v", err)
	}
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	})

	const tenantID = "11111111-1111-1111-1111-111111111111"
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "drain-family-limit"}); err != nil {
		t.Fatalf("upsert tenant: %v", err)
	}
	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		for index, lane := range []string{"external-ca.issue:authority:a", "external-ca.issue:authority:b", "external-ca.issue:authority:c"} {
			if _, err := srv.outbox.Enqueue(ctx, tx, orchestrator.Entry{
				TenantID: tenantID, Destination: "external-ca.issue", EffectLane: lane,
				IdempotencyKey: fmt.Sprintf("drain-limit-%d", index), Payload: []byte(`{}`),
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("enqueue drain rows: %v", err)
	}

	drained := make(chan error, 1)
	go func() { drained <- srv.Drain(ctx) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("configured external-CA drain worker did not start")
	}
	select {
	case lane := <-started:
		t.Fatalf("configured one-worker external-CA drain started a concurrent second lane %q", lane)
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	if err := <-drained; err != nil {
		t.Fatalf("drain: %v", err)
	}
	if got := len(started); got != 2 {
		t.Fatalf("remaining sequential deliveries = %d, want 2", got)
	}
}

func (f outboxDispatchFamily) scopeMatches(destination string) bool {
	included := len(f.scope.IncludePrefixes) == 0
	for _, prefix := range f.scope.IncludePrefixes {
		included = included || strings.HasPrefix(destination, prefix)
	}
	if !included {
		return false
	}
	for _, prefix := range f.scope.ExcludePrefixes {
		if strings.HasPrefix(destination, prefix) {
			return false
		}
	}
	return true
}
