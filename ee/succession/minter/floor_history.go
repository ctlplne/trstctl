// SPDX-License-Identifier: LicenseRef-trstctl-EE

package minter

import "sync"

// HistoryFloorStore is a counter-free FloorStore (PCAS-claim-48 / INV-16): it retains
// the recorded per-identity succession history and DERIVES the epoch floor from
// it (the highest recorded epoch) rather than storing a separate counter. Its
// observable behavior — what the minter refuses — is identical to a stored
// counter, which is the whole point: monotonicity must not depend on the storage
// form of the counter.
type HistoryFloorStore struct {
	mu      sync.Mutex
	history map[string][]uint64
}

// NewHistoryFloorStore returns an empty counter-free floor store.
func NewHistoryFloorStore() *HistoryFloorStore {
	return &HistoryFloorStore{history: map[string][]uint64{}}
}

// Load derives the epoch floor for each identity as the highest epoch in its
// recorded history.
func (s *HistoryFloorStore) Load() (map[string]uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]uint64, len(s.history))
	for id, hist := range s.history {
		var max uint64
		for _, e := range hist {
			if e > max {
				max = e
			}
		}
		out[id] = max
	}
	return out, nil
}

// Advance records epoch in the identity's history.
func (s *HistoryFloorStore) Advance(identityID string, epoch uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.history[identityID] = append(s.history[identityID], epoch)
	return nil
}

// RecordedTransition reports, by history determination, whether epoch would
// duplicate or precede a recorded transition for identityID (PCAS-claim-48). This is
// the counter-free equivalent of the "epoch <= floor" comparison.
func (s *HistoryFloorStore) RecordedTransition(identityID string, epoch uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.history[identityID] {
		if e >= epoch {
			return true
		}
	}
	return false
}
