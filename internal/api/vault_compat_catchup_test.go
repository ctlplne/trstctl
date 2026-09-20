// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	configpkg "trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

// TestSnapshotCatchesUpIncrementallyAfterUnrelatedAppends is the regression
// guard for AUD-201 follow-up F3/V27a. The memo key (LastSequence) is GLOBAL —
// one JetStream stream — while entries are per-tenant, so ANY tenant's append
// invalidated every tenant's entry and the rebuild replayed from sequence
// zero. On a busy deployment the hit rate tends to zero and the authorization
// path of every Vault-compat request still pays O(entire log). The fix folds
// only the events after the cached sequence onto a COPY of the cached
// snapshot.
func TestSnapshotCatchesUpIncrementallyAfterUnrelatedAppends(t *testing.T) {
	ctx := context.Background()
	log, err := events.Open(ctx, configpkg.NATS{Mode: configpkg.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatalf("open embedded log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	s := newVaultCompatState(log)
	const tenantEvents = 40
	for i := 0; i < tenantEvents; i++ {
		if _, err := s.append(ctx, "tenant-a", vaultPolicyPutEventType,
			vaultCompatPolicy{Name: fmt.Sprintf("p-%02d", i), Policy: "path {}"}); err != nil {
			t.Fatal(err)
		}
	}
	first, err := s.snapshot(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(first.policies) != tenantEvents {
		t.Fatalf("warm snapshot has %d policies, want %d", len(first.policies), tenantEvents)
	}

	// An UNRELATED tenant moves the global head.
	const unrelated = 5
	for i := 0; i < unrelated; i++ {
		if _, err := s.append(ctx, "tenant-b", vaultPolicyPutEventType,
			vaultCompatPolicy{Name: fmt.Sprintf("b-%02d", i), Policy: "path {}"}); err != nil {
			t.Fatal(err)
		}
	}

	before := s.memo.scannedEvents.Load()
	again, err := s.snapshot(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	scanned := s.memo.scannedEvents.Load() - before
	if scanned > unrelated {
		t.Fatalf("the catch-up scanned %d events after %d unrelated appends; it replayed from zero instead of from the cached sequence", scanned, unrelated)
	}

	// And the caught-up projection must EQUAL what a from-zero replay builds.
	fresh, err := newVaultCompatState(log).snapshot(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again.policies, fresh.policies) || !reflect.DeepEqual(again.mounts, fresh.mounts) {
		t.Fatal("incrementally caught-up snapshot disagrees with a from-zero replay")
	}

	// The catch-up folds onto a copy: the previously returned snapshot must be
	// untouched by later appends for this tenant.
	if _, err := s.append(ctx, "tenant-a", vaultPolicyPutEventType,
		vaultCompatPolicy{Name: "late", Policy: "path {}"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.snapshot(ctx, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if _, leaked := first.policies["late"]; leaked {
		t.Fatal("a later catch-up mutated a snapshot already returned to a caller")
	}
}
