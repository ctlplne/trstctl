// SPDX-License-Identifier: LicenseRef-trstctl-EE

package minter

import (
	"encoding/json"
	"fmt"
	"os"
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
	mu  sync.Mutex
	dir string
	m   map[string]uint64
}

// floorFileName is the fixed basename of the floor file inside the custody directory.
// The name is a constant and never derived from a request, so the only variable part
// of the location is the operator-configured directory the store is rooted at.
const floorFileName = "pcas-epoch-floors.json"

// NewDurableFloorStore opens (or creates) the durable floor file under dir. dir is
// the signer's own custody directory (the signer opens no control-plane store). The
// file is created 0600 in a 0700 directory.
//
// Every read and write goes through an os.Root opened on dir, so the floor file, its
// temp file, and the rename are all resolved inside the custody directory by the
// kernel: a symlink or ".." planted in that directory cannot redirect the signer's
// floor state to a path outside its own custody.
func NewDurableFloorStore(dir string) (*DurableFloorStore, error) {
	if dir == "" {
		return nil, fmt.Errorf("minter: durable floor store requires a directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("minter: create floor dir: %w", err)
	}
	s := &DurableFloorStore{dir: dir, m: map[string]uint64{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *DurableFloorStore) load() error {
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return fmt.Errorf("minter: open floor dir: %w", err)
	}
	defer func() { _ = root.Close() }()

	b, err := root.ReadFile(floorFileName)
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
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return fmt.Errorf("minter: open floor dir: %w", err)
	}
	defer func() { _ = root.Close() }()

	tmp := floorFileName + ".tmp"
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
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
	if err := root.Rename(tmp, floorFileName); err != nil {
		return fmt.Errorf("minter: rename floor file: %w", err)
	}
	return nil
}
