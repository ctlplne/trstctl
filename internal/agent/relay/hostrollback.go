// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
)

const (
	hostRollbackStateVersion = 1
	hostRollbackKeyFile      = "sealing.key"
)

var (
	// ErrHostRollbackPredecessorMissing is terminal: this host has no bounded
	// predecessor matching the requested fingerprint. Retrying cannot create
	// historical key material that was never retained here.
	ErrHostRollbackPredecessorMissing = errors.New("relay: requested host rollback predecessor is not retained on this agent")
	// ErrHostRollbackStateMismatch means the durable file belongs to a
	// different connector/target or carries an unsupported format. It is
	// refused before any host file is changed.
	ErrHostRollbackStateMismatch = errors.New("relay: host rollback state does not match the requested target")
)

// HostRollbackStore is the host agent's two-generation predecessor ledger.
//
// The control plane cannot restore a host certificate because it deliberately
// does not retain the subject key. The enrolled host agent can: immediately
// after a successful deploy it keeps the active bundle and the one bundle it
// replaced. The whole ledger is AES-GCM encrypted under a 0600 machine-local
// key. No key is kept resident between operations.
//
// Each target has its own mutex. The outbox effect lane provides the matching
// exclusion across agents/processes; this mutex closes the in-process window
// between opening the predecessor, writing files, reloading, verifying, and
// atomically rotating the ledger.
type HostRollbackStore struct {
	root     string
	tenantID string
	locks    sync.Map // map[tenant\x00connector\x00targetID]*sync.Mutex
}

type hostRollbackSnapshot struct {
	Fingerprint string `json:"fingerprint"`
	CertPEM     []byte `json:"cert_pem"`
	KeyPEM      []byte `json:"key_pem"`
}

type hostRollbackState struct {
	Version   int                   `json:"version"`
	TenantID  string                `json:"tenant_id"`
	Connector string                `json:"connector"`
	TargetID  string                `json:"target_id"`
	Active    *hostRollbackSnapshot `json:"active,omitempty"`
	Previous  *hostRollbackSnapshot `json:"previous,omitempty"`
}

// NewHostRollbackStore prepares and validates one machine-local ledger root.
// It loads the sealing key only long enough to prove custody and length, then
// wipes it; operations load it into locked memory for milliseconds.
func NewHostRollbackStore(root, tenantID string) (*HostRollbackStore, error) {
	clean := filepath.Clean(strings.TrimSpace(root))
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errors.New("relay: host rollback store requires the enrolled tenant id")
	}
	if clean == "." || clean == string(os.PathSeparator) || !filepath.IsAbs(clean) {
		return nil, fmt.Errorf("relay: host rollback directory must be an absolute non-root path")
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return nil, fmt.Errorf("relay: create host rollback directory: %w", err)
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return nil, fmt.Errorf("relay: inspect host rollback directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("relay: host rollback directory is not a real directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("relay: host rollback directory mode %o exposes predecessor state", info.Mode().Perm())
	}
	keyPath := filepath.Join(clean, hostRollbackKeyFile)
	raw, err := secretfile.LoadOrCreate(keyPath, func() ([]byte, error) {
		return trstcrypto.RandomBytes(32)
	})
	if err != nil {
		return nil, fmt.Errorf("relay: initialize host rollback sealing key: %w", err)
	}
	defer secret.Wipe(raw)
	if len(raw) != 32 {
		return nil, errors.New("relay: host rollback sealing key has the wrong length")
	}
	return &HostRollbackStore{root: clean, tenantID: tenantID}, nil
}

// RecordDeploy advances the bounded ledger after a host connector mutated the
// target successfully. A redelivery of the active fingerprint refreshes that
// slot without shifting generations; a new fingerprint moves active to the
// sole predecessor slot.
func (s *HostRollbackStore) RecordDeploy(connectorName, targetID, fingerprint string, certPEM, keyPEM []byte) error {
	connectorName, targetID, fingerprint, err := normalizeHostRollbackIdentity(connectorName, targetID, fingerprint)
	if err != nil {
		return err
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return errors.New("relay: host rollback state requires certificate and private-key bytes")
	}
	lock := s.targetLock(connectorName, targetID)
	lock.Lock()
	defer lock.Unlock()

	state, err := s.load(connectorName, targetID)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if state == nil {
		state = &hostRollbackState{
			Version: hostRollbackStateVersion, TenantID: s.tenantID,
			Connector: connectorName, TargetID: targetID,
		}
	}
	defer wipeHostRollbackState(state)
	next := &hostRollbackSnapshot{
		Fingerprint: fingerprint,
		CertPEM:     append([]byte(nil), certPEM...),
		KeyPEM:      append([]byte(nil), keyPEM...),
	}
	if state.Active != nil && state.Active.Fingerprint == fingerprint {
		wipeHostRollbackSnapshot(state.Active)
		state.Active = next
	} else {
		wipeHostRollbackSnapshot(state.Previous)
		state.Previous = state.Active
		state.Active = next
	}
	return s.save(state)
}

// Restore borrows the requested predecessor, under the per-target lock, for a
// caller that writes it, reloads the service, and reverifies the listener.
// Returning commit=true means that entire sequence succeeded, so the durable
// active/previous slots are swapped. A failed verification leaves the ledger
// unchanged so a retry can attempt the same known predecessor again.
func (s *HostRollbackStore) Restore(connectorName, targetID, fingerprint string, fn func(certPEM, keyPEM []byte) (commit bool, err error)) error {
	if fn == nil {
		return errors.New("relay: host rollback restore callback is required")
	}
	connectorName, targetID, fingerprint, err := normalizeHostRollbackIdentity(connectorName, targetID, fingerprint)
	if err != nil {
		return err
	}
	lock := s.targetLock(connectorName, targetID)
	lock.Lock()
	defer lock.Unlock()

	state, err := s.load(connectorName, targetID)
	if errors.Is(err, fs.ErrNotExist) {
		return ErrHostRollbackPredecessorMissing
	}
	if err != nil {
		return err
	}
	defer wipeHostRollbackState(state)

	selected := state.Previous
	alreadyActive := state.Active != nil && state.Active.Fingerprint == fingerprint
	if alreadyActive {
		selected = state.Active
	}
	if selected == nil || selected.Fingerprint != fingerprint {
		return ErrHostRollbackPredecessorMissing
	}
	commit, err := fn(selected.CertPEM, selected.KeyPEM)
	if err != nil || !commit {
		return err
	}
	if alreadyActive {
		return nil
	}
	state.Active, state.Previous = state.Previous, state.Active
	return s.save(state)
}

func normalizeHostRollbackIdentity(connectorName, targetID, fingerprint string) (string, string, string, error) {
	connectorName = strings.TrimSpace(connectorName)
	targetID = strings.TrimSpace(targetID)
	fingerprint = strings.ToLower(strings.TrimSpace(fingerprint))
	fingerprint = strings.TrimPrefix(fingerprint, "sha256:")
	fingerprint = strings.ReplaceAll(fingerprint, ":", "")
	if connectorName == "" || targetID == "" || fingerprint == "" {
		return "", "", "", errors.New("relay: host rollback state requires connector, target id, and fingerprint")
	}
	return connectorName, targetID, fingerprint, nil
}

func (s *HostRollbackStore) targetLock(connectorName, targetID string) *sync.Mutex {
	value, _ := s.locks.LoadOrStore(s.tenantID+"\x00"+connectorName+"\x00"+targetID, &sync.Mutex{})
	return value.(*sync.Mutex)
}

func (s *HostRollbackStore) statePath(connectorName, targetID string) string {
	name := trstcrypto.SHA256Hex([]byte(s.tenantID + "\x00" + connectorName + "\x00" + targetID))
	return filepath.Join(s.root, name+".state")
}

func (s *HostRollbackStore) aad(connectorName, targetID string) []byte {
	return []byte("trstctl.host.rollback.v1\x00" + s.tenantID + "\x00" + connectorName + "\x00" + targetID)
}

func (s *HostRollbackStore) load(connectorName, targetID string) (*hostRollbackState, error) {
	ciphertext, err := secretfile.Load(s.statePath(connectorName, targetID))
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(ciphertext)
	var plaintext []byte
	if err := s.withKey(func(key []byte) error {
		var openErr error
		plaintext, openErr = trstcrypto.AESGCMOpen(key, ciphertext, s.aad(connectorName, targetID))
		return openErr
	}); err != nil {
		return nil, fmt.Errorf("relay: open host rollback state: %w", err)
	}
	defer secret.Wipe(plaintext)
	var state hostRollbackState
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return nil, fmt.Errorf("relay: decode host rollback state: %w", err)
	}
	if state.Version != hostRollbackStateVersion || state.TenantID != s.tenantID ||
		state.Connector != connectorName || state.TargetID != targetID || state.Active == nil {
		wipeHostRollbackState(&state)
		return nil, ErrHostRollbackStateMismatch
	}
	return &state, nil
}

func (s *HostRollbackStore) save(state *hostRollbackState) error {
	plaintext, err := json.Marshal(state)
	if err != nil {
		return err
	}
	defer secret.Wipe(plaintext)
	var ciphertext []byte
	if err := s.withKey(func(key []byte) error {
		var sealErr error
		ciphertext, sealErr = trstcrypto.AESGCMSeal(key, plaintext, s.aad(state.Connector, state.TargetID))
		return sealErr
	}); err != nil {
		return fmt.Errorf("relay: seal host rollback state: %w", err)
	}
	defer secret.Wipe(ciphertext)
	return writeHostRollbackStateAtomic(s.statePath(state.Connector, state.TargetID), ciphertext)
}

func (s *HostRollbackStore) withKey(fn func([]byte) error) error {
	raw, err := secretfile.Load(filepath.Join(s.root, hostRollbackKeyFile))
	if err != nil {
		return err
	}
	buf, err := secret.NewFrom(raw)
	secret.Wipe(raw)
	if err != nil {
		return err
	}
	defer buf.Destroy()
	if buf.Len() != 32 {
		return errors.New("relay: host rollback sealing key has the wrong length")
	}
	return buf.Use(fn)
}

func writeHostRollbackStateAtomic(path string, ciphertext []byte) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".host-rollback-*") // #nosec G304 -- validated agent-local state directory (CWE-22)
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(ciphertext); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil { // #nosec G703 -- both paths are inside the validated agent-local state directory (CWE-22)
		return err
	}
	return nil
}

func wipeHostRollbackSnapshot(snapshot *hostRollbackSnapshot) {
	if snapshot == nil {
		return
	}
	secret.Wipe(snapshot.CertPEM)
	secret.Wipe(snapshot.KeyPEM)
	snapshot.CertPEM = nil
	snapshot.KeyPEM = nil
}

func wipeHostRollbackState(state *hostRollbackState) {
	if state == nil {
		return
	}
	wipeHostRollbackSnapshot(state.Active)
	if state.Previous != state.Active {
		wipeHostRollbackSnapshot(state.Previous)
	}
}
