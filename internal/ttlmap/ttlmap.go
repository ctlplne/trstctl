// SPDX-License-Identifier: BUSL-1.1

// Package ttlmap provides bounded eviction for maps with caller-defined expiry
// and ranking rules. Callers pass their wall clock explicitly: using a new
// entry's future expiry as the clock once flushed still-valid responses.
// The public OCSP response cache uses an indexed expiry heap to retain this
// policy without scanning a full map for every distinct serial.
package ttlmap

import "time"

// Policy describes one cache's eviction behavior. Expired is the cache's own
// staleness predicate (boundary semantics differ between caches and are
// preserved bit-for-bit); Rank orders live entries for forced eviction — the
// smallest rank is the cheapest victim (soonest expiry, oldest fetch, oldest
// validation). Ties on rank break deterministically by smallest key,
// preserving the revocation cache's replay-stable choice for every caller.
type Policy[V any] struct {
	Capacity           int
	Expired            func(entry V, now time.Time) bool
	Rank               func(entry V) time.Time
	SweepBelowCapacity bool // purge expired entries even when the map is under capacity
}

// MakeRoom evicts from entries so one more entry can be inserted without
// exceeding p.Capacity: expired entries first (free), then the lowest-ranked
// live entry while the map is still at or over capacity. now is explicit —
// callers pass their real wall clock, never a derived future instant.
func MakeRoom[V any](entries map[string]V, now time.Time, p Policy[V]) {
	if len(entries) < p.Capacity && !p.SweepBelowCapacity {
		return
	}
	for key, entry := range entries {
		if p.Expired(entry, now) {
			delete(entries, key)
		}
	}
	for len(entries) >= p.Capacity {
		var victimKey string
		var victimRank time.Time
		found := false
		for key, entry := range entries {
			rank := p.Rank(entry)
			if !found || rank.Before(victimRank) || (rank.Equal(victimRank) && key < victimKey) {
				victimKey, victimRank = key, rank
				found = true
			}
		}
		if !found {
			return
		}
		delete(entries, victimKey)
	}
}
