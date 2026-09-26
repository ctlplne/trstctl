// SPDX-License-Identifier: BUSL-1.1

// Package reportstate retains one terminal observation until the control plane
// acknowledges it. The agent has one execution worker and drains this record
// before claiming more work, so storage and memory have a fixed bound.
package reportstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
	"trstctl.com/trstctl/internal/custody"
)

const maxRecordBytes = 4 << 20

// Observation contains the original execution facts, without a timestamp or
// signature for a later transmission. Detail can contain untrusted device text;
// it stays byte-backed and is encrypted on disk, never written to a plain file.
type Observation struct {
	JobID                 int64           `json:"job_id"`
	Attempt               int             `json:"attempt"`
	Outcome               string          `json:"outcome"`
	Detail                []byte          `json:"detail"`
	EvidenceDigest        string          `json:"evidence_digest"`
	CredentialFingerprint string          `json:"credential_fingerprint"`
	Custody               *custody.Record `json:"custody,omitempty"`
}

func (o *Observation) Destroy() {
	if o != nil {
		secret.Wipe(o.Detail)
		o.Detail = nil
	}
}

type diskRecord struct {
	Version int         `json:"version"`
	Value   Observation `json:"value"`
}

// Store holds a process lock for its entire lifetime. Binding commits to the
// server trust, tenant registration and agent identity; changing any of them
// cannot silently send an old observation under new authority.
type Store struct {
	mu      sync.Mutex
	root    *os.Root
	path    string
	binding string
	lock    *os.File
	closed  bool
	fault   error
}

func Open(path, binding string) (*Store, error) {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) || path == string(os.PathSeparator) || binding == "" {
		return nil, errors.New("reportstate: an absolute private directory and identity binding are required")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, err
	}
	if err := secretfile.SecurePrivateDirectory(path); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("reportstate: directory is not a real private directory")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	s := &Store{root: root, path: path, binding: binding}
	ok := false
	defer func() {
		if !ok {
			_ = s.Close()
		}
	}()
	if info, err := root.Lstat("agent.lock"); err == nil && !info.Mode().IsRegular() {
		return nil, errors.New("reportstate: lock is not a regular file")
	}
	s.lock, err = root.OpenFile("agent.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(s.lock); err != nil {
		return nil, fmt.Errorf("reportstate: another process owns this agent report store: %w", err)
	}
	keyPath := filepath.Join(path, "sealing.key")
	if _, err := root.Lstat("pending.state"); err == nil {
		if _, err := root.Lstat("sealing.key"); err != nil {
			return nil, errors.New("reportstate: pending result has no accessible sealing key; preserve the state for recovery")
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	key, err := secretfile.LoadOrCreate(keyPath, func() ([]byte, error) { return crypto.RandomBytes(32) })
	if err != nil {
		return nil, err
	}
	validKey := len(key) == 32
	secret.Wipe(key)
	if !validKey {
		return nil, errors.New("reportstate: invalid sealing key length")
	}
	keyFile, err := root.OpenFile("sealing.key", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	err = keyFile.Sync()
	closeErr := keyFile.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if err := syncDirectory(root); err != nil {
		return nil, err
	}
	pending, err := s.read()
	if pending != nil {
		pending.Destroy()
	}
	if err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.lock != nil {
		err = s.lock.Close()
	}
	return errors.Join(err, s.root.Close())
}

func (s *Store) Pending() (*Observation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fs.ErrClosed
	}
	if s.fault != nil {
		return nil, s.fault
	}
	return s.read()
}

// Put must finish before the first network report. A write failure latches a
// local refusal so this process cannot silently claim another job after losing
// a result that it could not persist.
func (s *Store) Put(value Observation) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fs.ErrClosed
	}
	if s.fault != nil {
		return s.fault
	}
	defer func() {
		if err != nil {
			s.fault = fmt.Errorf("reportstate: result persistence failed; further work is refused: %w", err)
		}
	}()
	if err := validate(value); err != nil {
		return err
	}
	encoded, err := json.Marshal(diskRecord{Version: 1, Value: value})
	if err != nil {
		return err
	}
	defer secret.Wipe(encoded)
	if len(encoded) > maxRecordBytes {
		return errors.New("reportstate: terminal result exceeds the local size bound")
	}
	existing, err := s.read()
	if err != nil {
		return err
	}
	if existing != nil {
		defer existing.Destroy()
		if !same(*existing, value) {
			return errors.New("reportstate: an unacknowledged original result already exists")
		}
		return nil
	}
	var ciphertext []byte
	if err := s.withKey(func(key []byte) error {
		var err error
		ciphertext, err = crypto.AESGCMSeal(key, encoded, s.aad())
		return err
	}); err != nil {
		return err
	}
	defer secret.Wipe(ciphertext)
	if info, err := s.root.Lstat("pending.next"); err == nil && !info.Mode().IsRegular() {
		return errors.New("reportstate: staging path is not a regular file")
	}
	f, err := s.root.OpenFile("pending.next", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := secretfile.SecurePrivateFile(filepath.Join(s.path, "pending.next")); err != nil {
		return err
	}
	if _, err := f.Write(ciphertext); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := s.root.Rename("pending.next", "pending.state"); err != nil {
		return err
	}
	return syncDirectory(s.root)
}

// Acknowledge removes only the exact observation the caller successfully sent.
func (s *Store) Acknowledge(value Observation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fs.ErrClosed
	}
	if s.fault != nil {
		return s.fault
	}
	pending, err := s.read()
	if err != nil {
		return err
	}
	if pending == nil {
		return nil
	}
	defer pending.Destroy()
	if !same(*pending, value) {
		return errors.New("reportstate: acknowledgement does not match pending result")
	}
	if err := s.root.Remove("pending.state"); err != nil {
		return err
	}
	if err := syncDirectory(s.root); err != nil {
		s.fault = err
		return err
	}
	return nil
}

func (s *Store) read() (*Observation, error) {
	info, err := s.root.Lstat("pending.state")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxRecordBytes+64 {
		return nil, errors.New("reportstate: invalid or oversized pending result")
	}
	ciphertext, err := secretfile.Load(filepath.Join(s.path, "pending.state"))
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(ciphertext)
	var plain []byte
	if err := s.withKey(func(key []byte) error {
		var err error
		plain, err = crypto.AESGCMOpen(key, ciphertext, s.aad())
		return err
	}); err != nil {
		return nil, fmt.Errorf("reportstate: pending result authentication failed: %w", err)
	}
	defer secret.Wipe(plain)
	var record diskRecord
	if err := json.Unmarshal(plain, &record); err != nil {
		record.Value.Destroy()
		return nil, errors.New("reportstate: invalid pending result encoding")
	}
	if record.Version != 1 {
		record.Value.Destroy()
		return nil, errors.New("reportstate: unsupported pending result version")
	}
	if err := validate(record.Value); err != nil {
		record.Value.Destroy()
		return nil, err
	}
	return &record.Value, nil
}

func (s *Store) withKey(fn func([]byte) error) error {
	raw, err := secretfile.Load(filepath.Join(s.path, "sealing.key"))
	if err != nil {
		return err
	}
	key, err := secret.NewFrom(raw)
	secret.Wipe(raw)
	if err != nil {
		return err
	}
	defer key.Destroy()
	if key.Len() != 32 {
		return errors.New("reportstate: invalid sealing key length")
	}
	return key.Use(fn)
}

func (s *Store) aad() []byte { return []byte("trstctl.agent.terminal-result.v1\x00" + s.binding) }

func validate(o Observation) error {
	if o.JobID <= 0 || o.Attempt <= 0 {
		return errors.New("reportstate: original job and attempt are required")
	}
	switch o.Outcome {
	case "executed", "verified", "verify_failed", "failed":
		return nil
	}
	return errors.New("reportstate: only terminal observations may be retained")
}

func same(a, b Observation) bool {
	if a.JobID != b.JobID || a.Attempt != b.Attempt || a.Outcome != b.Outcome || !bytes.Equal(a.Detail, b.Detail) || a.EvidenceDigest != b.EvidenceDigest || a.CredentialFingerprint != b.CredentialFingerprint {
		return false
	}
	if a.Custody == nil || b.Custody == nil {
		return a.Custody == nil && b.Custody == nil
	}
	return *a.Custody == *b.Custody
}
