// SPDX-License-Identifier: MPL-2.0

// Package ttlmap holds the ONE bounded-TTL-map eviction algorithm the
// control plane's request-path caches share. The same shape used to be
// hand-written three times — the served OCSP response cache, the licensed
// white-label resolver, and the agent's revocation cache — differing only in
// expiry representation, and that divergence is exactly where one copy's
// future-timestamp bug lived (AUD-201 follow-up F2/V28, after F1/V7): a sweep
// judged against the wrong clock mass-flushed live entries. Sharing the
// algorithm and taking the clock as an EXPLICIT argument makes that bug
// unrepresentable at the call site.
package ttlmap

import "time"

// Policy describes one cache's eviction behaviour. Expired is the cache's own
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
