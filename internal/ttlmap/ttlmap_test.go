// SPDX-License-Identifier: BUSL-1.1

package ttlmap

import (
	"testing"
	"time"
)

type entry struct {
	expires time.Time
	rank    time.Time
}

func policy(capacity int, sweepBelowCapacity bool) Policy[entry] {
	return Policy[entry]{
		Capacity:           capacity,
		Expired:            func(e entry, now time.Time) bool { return !e.expires.After(now) },
		Rank:               func(e entry) time.Time { return e.rank },
		SweepBelowCapacity: sweepBelowCapacity,
	}
}

// TestMakeRoomEvictsExpiredThenLowestRank pins the shared algorithm: expired
// entries go first (free), then the lowest-ranked live entry, and ONLY enough
// to admit one more.
func TestMakeRoomEvictsExpiredThenLowestRank(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	live := now.Add(time.Hour)
	entries := map[string]entry{
		"expired": {expires: now.Add(-time.Minute), rank: now.Add(-time.Minute)},
		"oldest":  {expires: live, rank: now.Add(1 * time.Minute)},
		"newer":   {expires: live, rank: now.Add(2 * time.Minute)},
	}
	MakeRoom(entries, now, policy(3, false))
	if _, ok := entries["expired"]; ok {
		t.Fatal("expired entry survived")
	}
	if len(entries) != 2 {
		t.Fatalf("len = %d, want 2: freeing the expired entry was enough, live entries must survive", len(entries))
	}

	// At capacity with only live entries, exactly the lowest rank loses.
	entries["third"] = entry{expires: live, rank: now.Add(3 * time.Minute)}
	MakeRoom(entries, now, policy(3, false))
	if _, ok := entries["oldest"]; ok {
		t.Fatal("the lowest-ranked live entry survived a forced eviction")
	}
	if len(entries) != 2 {
		t.Fatalf("len = %d, want 2 after one forced eviction", len(entries))
	}
}

// TestMakeRoomBreaksRankTiesByKey preserves the revocation cache's
// deterministic choice — now universal: equal ranks evict the smallest key, so
// replays and repeated runs converge on identical cache contents.
func TestMakeRoomBreaksRankTiesByKey(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	live := now.Add(time.Hour)
	tied := now.Add(time.Minute)
	entries := map[string]entry{
		"b-key": {expires: live, rank: tied},
		"a-key": {expires: live, rank: tied},
		"c-key": {expires: live, rank: now.Add(2 * time.Minute)},
	}
	MakeRoom(entries, now, policy(3, false))
	if _, ok := entries["a-key"]; ok {
		t.Fatal("tie on rank must evict the smallest key deterministically")
	}
	if _, ok := entries["b-key"]; !ok {
		t.Fatal("the larger tied key must survive")
	}
}

// TestMakeRoomSweepBelowCapacity pins the revcache posture: expired entries
// are purged on every call even under capacity, while the default posture
// leaves them for the at-capacity sweep.
func TestMakeRoomSweepBelowCapacity(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	under := map[string]entry{
		"expired": {expires: now.Add(-time.Minute), rank: now},
		"live":    {expires: now.Add(time.Hour), rank: now},
	}
	MakeRoom(under, now, policy(100, true))
	if _, ok := under["expired"]; ok {
		t.Fatal("SweepBelowCapacity did not purge an expired entry under capacity")
	}

	kept := map[string]entry{
		"expired": {expires: now.Add(-time.Minute), rank: now},
		"live":    {expires: now.Add(time.Hour), rank: now},
	}
	MakeRoom(kept, now, policy(100, false))
	if _, ok := kept["expired"]; !ok {
		t.Fatal("the default posture must not sweep under capacity")
	}
}
