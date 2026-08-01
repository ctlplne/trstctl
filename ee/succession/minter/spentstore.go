// SPDX-License-Identifier: LicenseRef-trstctl-EE

package minter

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// SpentStore records consumed single-use token nonces so a replayed token is refused
// (PCAS-claim-5). Consume atomically records a nonce and reports whether it was ALREADY
// spent. A durable implementation makes single-use survive a signer restart (INT-06).
type SpentStore interface {
	Consume(nonce string) (alreadySpent bool, err error)
}

// memSpentStore is an in-memory SpentStore; spent nonces do not survive a restart.
type memSpentStore struct {
	mu   sync.Mutex
	seen map[string]bool
}

// NewMemSpentStore returns an in-memory SpentStore.
func NewMemSpentStore() SpentStore { return &memSpentStore{seen: map[string]bool{}} }

func (s *memSpentStore) Consume(nonce string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen[nonce] {
		return true, nil
	}
	s.seen[nonce] = true
	return false, nil
}

// DurableSpentStore is a file-backed SpentStore in the signer custody dir: each
// consumed nonce is appended (fsync'd) to a file and reloaded on construction, so
// single-use survives a signer restart (INT-06, PCAS-claim-5). Nonces are newline-free
// random strings.
type DurableSpentStore struct {
	mu   sync.Mutex
	path string
	seen map[string]bool
}

// NewDurableSpentStore opens (or creates) the spent-nonce file `name` under dir (the
// signer's own custody dir) and loads any previously consumed nonces.
func NewDurableSpentStore(dir, name string) (*DurableSpentStore, error) {
	if dir == "" {
		return nil, fmt.Errorf("minter: durable spent store requires a directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("minter: create spent dir: %w", err)
	}
	s := &DurableSpentStore{path: filepath.Join(dir, name), seen: map[string]bool{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *DurableSpentStore) load() error {
	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("minter: open spent file: %w", err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if n := sc.Text(); n != "" {
			s.seen[n] = true
		}
	}
	return sc.Err()
}

// Consume records nonce durably (append + fsync) before returning not-already-spent,
// so a token counts as consumed the moment it is accepted — a replay after restart is
// refused even if the mint that used it did not complete.
func (s *DurableSpentStore) Consume(nonce string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen[nonce] {
		return true, nil
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return false, fmt.Errorf("minter: open spent file: %w", err)
	}
	if _, err := f.WriteString(nonce + "\n"); err != nil {
		_ = f.Close()
		return false, fmt.Errorf("minter: append spent nonce: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return false, fmt.Errorf("minter: fsync spent file: %w", err)
	}
	if err := f.Close(); err != nil {
		return false, fmt.Errorf("minter: close spent file: %w", err)
	}
	s.seen[nonce] = true
	return false, nil
}
