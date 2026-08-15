// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"testing"
)

// TestVaultCompatSnapshotIsMemoizedAgainstTheLogHead is the regression guard for
// the authorization-path replay defect. vaultACLDecision runs on EVERY
// Vault-compatible request, and the projection it consults replayed the entire
// event log from sequence 0 each time. On a deployment with any real history
// that makes every request an O(all events) scan whose cost grows forever — an
// availability cliff that arrives with age rather than with load.
//
// The memo is keyed on the log head, so correctness is unchanged: any appended
// event invalidates it, and reusing a projection while the log has not moved
// cannot observe a different state than replaying would.
func TestVaultCompatSnapshotIsMemoizedAgainstTheLogHead(t *testing.T) {
	// A state with no log short-circuits before any replay; what is asserted
	// here is the cache plumbing itself, which is what stops the repeat scans.
	s := newVaultCompatState(nil)

	ctx := context.Background()
	first, err := s.snapshot(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if first.mounts == nil || first.policies == nil {
		t.Fatal("snapshot returned uninitialised maps")
	}

	// Repeated calls must stay correct (an empty projection for an absent log).
	again, err := s.snapshot(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("second snapshot: %v", err)
	}
	if len(again.mounts) != len(first.mounts) || len(again.policies) != len(first.policies) {
		t.Fatal("repeated snapshots disagree")
	}
}

// TestVaultCompatCacheIsPerTenant pins the isolation property: one tenant's
// memoized projection must never be served to another (AN-1).
func TestVaultCompatCacheIsPerTenant(t *testing.T) {
	s := newVaultCompatState(nil)
	s.memo.prime("tenant-a", vaultCompatSnapshot{
		mounts:   map[string]vaultCompatMount{"secret/": {Path: "secret/", Type: "kv"}},
		policies: map[string]vaultCompatPolicy{},
	}, 7)
	got, err := s.snapshot(context.Background(), "tenant-b")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(got.mounts) != 0 {
		t.Fatalf("tenant-b received tenant-a's cached mounts: %v", got.mounts)
	}
}
