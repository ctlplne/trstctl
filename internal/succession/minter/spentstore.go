// SPDX-License-Identifier: BUSL-1.1

package minter

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"trstctl.com/trstctl/internal/crypto"
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

// DurableSpentStore is a file-backed SpentStore in the signer custody dir. New
// consumes atomically create one fsync'd file per nonce, so two signer instances
// sharing custody cannot both accept the same token. The old append-only file
// remains readable after upgrade and is included with the claim directory in
// the signer's full backup.
type DurableSpentStore struct {
	mu        sync.Mutex
	path      string
	claimsDir string
	seen      map[string]bool // legacy append-only entries loaded once at startup
}

// NewDurableSpentStore reads the legacy spent-nonce file `name` under dir and
// creates the atomic claim directory beside it in the signer's custody tree.
func NewDurableSpentStore(dir, name string) (*DurableSpentStore, error) {
	if dir == "" || name == "" || filepath.Base(name) != name {
		return nil, fmt.Errorf("minter: durable spent store requires a directory and one filename")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("minter: create spent dir: %w", err)
	}
	s := &DurableSpentStore{path: filepath.Join(dir, name), claimsDir: filepath.Join(dir, name+".claims"), seen: map[string]bool{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(s.claimsDir, 0o700); err != nil {
		return nil, fmt.Errorf("minter: create spent claims dir: %w", err)
	}
	parent, err := os.Open(dir) // #nosec G304 -- signer-owned custody directory selected at signer startup (CWE-22).
	if err != nil {
		return nil, fmt.Errorf("minter: open spent custody dir: %w", err)
	}
	if err := parent.Sync(); err != nil {
		_ = parent.Close()
		return nil, fmt.Errorf("minter: fsync spent custody dir: %w", err)
	}
	if err := parent.Close(); err != nil {
		return nil, fmt.Errorf("minter: close spent custody dir: %w", err)
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

// Consume records a nonce durably before returning not-already-spent. The
// filesystem's exclusive create is the cross-process claim; the instance-local
// lock only serializes this object's callers. A failed sync conservatively leaves
// the claim in place, so uncertainty cannot authorize a second use.
func (s *DurableSpentStore) Consume(nonce string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen[nonce] {
		return true, nil
	}
	claim := filepath.Join(s.claimsDir, crypto.SHA256Hex([]byte(nonce))+".spent")
	f, err := os.OpenFile(claim, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- claim path is signer-owned custody dir plus a fixed SHA-256 hex nonce digest (CWE-22).
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return true, nil
		}
		return false, fmt.Errorf("minter: create spent claim: %w", err)
	}
	if _, err := f.WriteString("spent\n"); err != nil {
		_ = f.Close()
		return false, fmt.Errorf("minter: write spent claim: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return false, fmt.Errorf("minter: fsync spent claim: %w", err)
	}
	if err := f.Close(); err != nil {
		return false, fmt.Errorf("minter: close spent claim: %w", err)
	}
	directory, err := os.Open(s.claimsDir)
	if err != nil {
		return false, fmt.Errorf("minter: open spent claims dir: %w", err)
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return false, fmt.Errorf("minter: fsync spent claims dir: %w", err)
	}
	if err := directory.Close(); err != nil {
		return false, fmt.Errorf("minter: close spent claims dir: %w", err)
	}
	return false, nil
}
