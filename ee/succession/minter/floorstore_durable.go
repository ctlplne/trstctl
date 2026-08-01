// SPDX-License-Identifier: LicenseRef-trstctl-EE

package minter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// DurableFloorStore is a file-backed, restart-surviving epoch-floor store held within
// the signer's custody directory (INT-05, PCAS-claim-21). It persists the per-identity
// algorithm-epoch floor to a file with atomic writes and MONOTONIC advances — a lower
// or equal epoch never regresses the stored value — so a signer restart cannot lower
// the floor and a stale-epoch mint is refused after restart. This is the software-
// durable floor on which rollback resistance depends; the hardware-counter, quorum,
// and ledger-reconcile embodiments (HighWater, PCAS-18) layer stronger anti-rollback
// on top for restore-from-backup scenarios.
type DurableFloorStore struct {
	mu   sync.Mutex
	path string
	m    map[string]uint64
}

// NewDurableFloorStore opens (or creates) the durable floor file under dir. dir is
// the signer's own custody directory (the signer opens no control-plane store). The
// file is created 0600 in a 0700 directory.
func NewDurableFloorStore(dir string) (*DurableFloorStore, error) {
	if dir == "" {
		return nil, fmt.Errorf("minter: durable floor store requires a directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("minter: create floor dir: %w", err)
	}
	s := &DurableFloorStore{path: filepath.Join(dir, "pcas-epoch-floors.json"), m: map[string]uint64{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *DurableFloorStore) load() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no floors yet
		}
		return fmt.Errorf("minter: read floor file: %w", err)
	}
	if len(b) == 0 {
		return nil
	}
	m := map[string]uint64{}
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("minter: decode floor file: %w", err)
	}
	s.m = m
	return nil
}

// Load returns a copy of the persisted per-identity floor map (minter.FloorStore).
func (s *DurableFloorStore) Load() (map[string]uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]uint64, len(s.m))
	for k, v := range s.m {
		out[k] = v
	}
	return out, nil
}

// Advance persists a strictly-greater floor for identityID and is monotonic: an epoch
// less than or equal to the stored floor is a no-op (idempotent, retry-safe), never a
// regression. The write is atomic (temp file + rename + fsync), so a crash mid-write
// leaves either the old or the new floor, never a torn file.
func (s *DurableFloorStore) Advance(identityID string, epoch uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if epoch <= s.m[identityID] {
		return nil // monotonic: never lower the floor
	}
	next := make(map[string]uint64, len(s.m)+1)
	for k, v := range s.m {
		next[k] = v
	}
	next[identityID] = epoch
	if err := s.writeAtomic(next); err != nil {
		return err
	}
	s.m = next
	return nil
}

func (s *DurableFloorStore) writeAtomic(m map[string]uint64) error {
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("minter: encode floors: %w", err)
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("minter: open floor tmp: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return fmt.Errorf("minter: write floor tmp: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("minter: fsync floor tmp: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("minter: close floor tmp: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("minter: rename floor file: %w", err)
	}
	return nil
}
