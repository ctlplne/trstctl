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
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
	"trstctl.com/trstctl/internal/custody"
)

const maxRecordBytes = 4 << 20

const (
	setAsidePrefix = "set-aside-"
	// setAsideLimit bounds the reports kept aside, so the directory keeps a
	// fixed size however often an operator sets one aside.
	setAsideLimit = 4
)

// ErrUnopenable marks a retained report this store cannot open under its
// binding and sealing key: it was sealed under another registration or server
// trust, its sealing key is missing, or its bytes were damaged. Open refuses
// it and leaves it in place; SetAsideUnopenable moves it aside, intact, on an
// operator's decision.
var ErrUnopenable = errors.New("reportstate: pending report cannot be opened")

// ErrInvalidPending marks a retained report that is not a record this build
// can use: not a regular file, over the size bound, or an encoding, version
// or outcome it does not read. Open refuses it like ErrUnopenable.
var ErrInvalidPending = errors.New("reportstate: pending report is not a valid record")

// Observation contains the original execution facts, without a timestamp or
// signature for a later transmission. Detail can contain untrusted device text;
// it stays byte-backed and is encrypted on disk, never written to a plain file.
type Observation struct {
	JobID                 int64             `json:"job_id"`
	Attempt               int               `json:"attempt"`
	Outcome               string            `json:"outcome"`
	Detail                []byte            `json:"detail"`
	EvidenceDigest        string            `json:"evidence_digest"`
	CredentialFingerprint string            `json:"credential_fingerprint"`
	Custody               *custody.Record   `json:"custody,omitempty"`
	HostRenew             *HostRenewCleanup `json:"host_renew,omitempty"`
	// AdoptedPredecessorFingerprint and AdoptedPredecessorPEM carry the pair a
	// first host deploy found installed and retained for rollback (A45). The
	// PEM is the public leaf only.
	AdoptedPredecessorFingerprint string `json:"adopted_predecessor_fingerprint,omitempty"`
	AdoptedPredecessorPEM         []byte `json:"adopted_predecessor_pem,omitempty"`
}

// HostRenewCleanup is local-only recovery metadata. It is sealed with the
// terminal observation and never included in the signed wire report.
type HostRenewCleanup struct {
	Connector string `json:"connector"`
	TargetID  string `json:"target_id"`
	Binding   string `json:"binding"`
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

// Open takes the directory's process lock and refuses a retained report it
// cannot open (ErrUnopenable, ErrInvalidPending) without changing its bytes or
// replacing a missing sealing key.
func Open(path, binding string) (*Store, error) {
	s, err := lockStore(path, binding)
	if err != nil {
		return nil, err
	}
	if err := s.load(); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// SetAsideUnopenable is an operator's explicit decision about a retained report
// this registration cannot deliver, one Open refuses as ErrUnopenable or
// ErrInvalidPending: it is renamed, intact and still sealed, to
// set-aside-<UTC>.state in the same directory and is never sent under the
// current binding. It returns that path, or "" when nothing needed moving; a
// report that opens stays in place for the agent to send. At most
// setAsideLimit reports are kept aside. The agent must not be running.
func SetAsideUnopenable(path, binding string) (string, error) {
	s, err := lockStore(path, binding)
	if err != nil {
		return "", err
	}
	defer func() { _ = s.Close() }()
	err = s.load()
	if err == nil || (!errors.Is(err, ErrUnopenable) && !errors.Is(err, ErrInvalidPending)) {
		return "", err
	}
	return s.setAside(time.Now())
}

// lockStore checks the private directory and takes its process lock.
func lockStore(path, binding string) (*Store, error) {
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
	ok = true
	return s, nil
}

// load creates the sealing key when nothing is retained and checks that a
// retained report opens. A report without its key is refused before a new
// key could replace the one that sealed it.
func (s *Store) load() error {
	keyPath := filepath.Join(s.path, "sealing.key")
	if _, err := s.root.Lstat("pending.state"); err == nil {
		if _, err := s.root.Lstat("sealing.key"); err != nil {
			return fmt.Errorf("%w: it has no accessible sealing key; preserve the state for recovery", ErrUnopenable)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	key, err := secretfile.LoadOrCreate(keyPath, func() ([]byte, error) { return crypto.RandomBytes(32) })
	if err != nil {
		return err
	}
	validKey := len(key) == 32
	secret.Wipe(key)
	if !validKey {
		return errors.New("reportstate: invalid sealing key length")
	}
	keyFile, err := s.root.OpenFile("sealing.key", os.O_RDWR, 0)
	if err != nil {
		return err
	}
	err = keyFile.Sync()
	closeErr := keyFile.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := syncDirectory(s.root); err != nil {
		return err
	}
	pending, err := s.read()
	if pending != nil {
		pending.Destroy()
	}
	return err
}

// setAside renames the retained report, without reading or rewriting it, so
// the bytes (or a symbolic link) stay exactly as they were.
func (s *Store) setAside(now time.Time) (string, error) {
	dir, err := s.root.Open(".")
	if err != nil {
		return "", err
	}
	names, err := dir.Readdirnames(-1)
	closeErr := dir.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	kept := 0
	for _, name := range names {
		if strings.HasPrefix(name, setAsidePrefix) {
			kept++
		}
	}
	if kept >= setAsideLimit {
		return "", fmt.Errorf("reportstate: %d reports are already set aside in %s; review and remove the ones no longer needed before setting aside another", kept, s.path)
	}
	name := setAsidePrefix + now.UTC().Format("20060102T150405.000000000Z") + ".state"
	if _, err := s.root.Lstat(name); err == nil {
		return "", fmt.Errorf("reportstate: %s already exists", name)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if err := s.root.Rename("pending.state", name); err != nil {
		return "", err
	}
	if err := syncDirectory(s.root); err != nil {
		return "", err
	}
	return filepath.Join(s.path, name), nil
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
		return nil, fmt.Errorf("%w: not a regular file, or over the size bound", ErrInvalidPending)
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
		return nil, fmt.Errorf("%w under this registration and sealing key: %w", ErrUnopenable, err)
	}
	defer secret.Wipe(plain)
	var record diskRecord
	if err := json.Unmarshal(plain, &record); err != nil {
		record.Value.Destroy()
		return nil, fmt.Errorf("%w: invalid encoding", ErrInvalidPending)
	}
	if record.Version != 1 {
		record.Value.Destroy()
		return nil, fmt.Errorf("%w: unsupported version %d", ErrInvalidPending, record.Version)
	}
	if err := validate(record.Value); err != nil {
		record.Value.Destroy()
		return nil, fmt.Errorf("%w: %w", ErrInvalidPending, err)
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
	if o.HostRenew != nil {
		if (o.Outcome != "verified" && o.Outcome != "executed") || o.Custody == nil || o.CredentialFingerprint == "" ||
			o.HostRenew.Connector == "" || o.HostRenew.TargetID == "" || len(o.HostRenew.Binding) != 64 {
			return errors.New("reportstate: invalid host renewal cleanup binding")
		}
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
		if a.Custody != nil || b.Custody != nil {
			return false
		}
	} else if *a.Custody != *b.Custody {
		return false
	}
	if a.HostRenew == nil || b.HostRenew == nil {
		return a.HostRenew == nil && b.HostRenew == nil
	}
	return *a.HostRenew == *b.HostRenew
}
