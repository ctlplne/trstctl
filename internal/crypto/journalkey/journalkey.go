// SPDX-License-Identifier: BUSL-1.1

// Package journalkey holds the target-local ingress integrity key outside the
// event log, PostgreSQL and backup artifacts. Provision is an explicit setup
// operation; recovery only reads keys already installed on the target.
package journalkey

import (
	"crypto/rand"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
)

const keySize = 32

// Files selects one active producer-MAC key and keeps older paths available
// until every journal row using their version has a verified terminal outcome.
// It stores only version IDs and paths, never key bytes.
type Files struct {
	ActiveID string
	Paths    map[string]string
}

// Provision creates one new key only during controlled deployment setup. It
// refuses to overwrite an existing file, so a restart or recovery cannot
// silently replace the key that authenticates a pending journal row.
func Provision(path string) error {
	key, err := secret.NewProtected(keySize)
	if err != nil {
		return fmt.Errorf("journalkey: protect new integrity key: %w", err)
	}
	defer key.Destroy()
	return key.Use(func(held []byte) error {
		if _, err := rand.Read(held); err != nil {
			return fmt.Errorf("journalkey: generate integrity key: %w", err)
		}
		return secretfile.Create(path, held)
	})
}

// WithActiveKey borrows the configured active version for one MAC operation.
func (f Files) WithActiveKey(fn func(string, []byte) error) error {
	if fn == nil || f.ActiveID == "" {
		return errors.New("journalkey: active key is unavailable")
	}
	return f.WithKey(f.ActiveID, func(key []byte) error { return fn(f.ActiveID, key) })
}

// WithKey reads one exact version into protected memory for one bounded use.
// A missing version or file is a refusal, including during recovery. The
// callback must not retain the borrowed bytes after it returns.
func (f Files) WithKey(id string, fn func([]byte) error) error {
	if id == "" || fn == nil || f.Paths == nil || f.Paths[id] == "" {
		return errors.New("journalkey: requested key version is unavailable")
	}
	key, err := secretfile.LoadProtectedExact(f.Paths[id], keySize)
	if err != nil {
		return fmt.Errorf("journalkey: load configured version: %w", err)
	}
	defer key.Destroy()
	if err := key.Use(fn); err != nil {
		return fmt.Errorf("journalkey: use configured version: %w", err)
	}
	return nil
}
