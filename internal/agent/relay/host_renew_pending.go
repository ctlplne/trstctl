// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
)

// hostRenewPending is separate from the predecessor ledger: first issuance has
// no Active predecessor, but its key must be durable before the first CSR RPC.
// A target has one pending job at a time; the outbox effect lane owns that order.
type hostRenewPending struct {
	JobID       int64  `json:"job_id"`
	Binding     string `json:"binding"`
	CSRDER      []byte `json:"csr_der"`
	KeyPEM      []byte `json:"key_pem"`
	CertPEM     []byte `json:"cert_pem,omitempty"`
	ChainPEM    []byte `json:"chain_pem,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

func wipeHostRenewPending(p *hostRenewPending) {
	if p == nil {
		return
	}
	secret.Wipe(p.CSRDER)
	secret.Wipe(p.KeyPEM)
	secret.Wipe(p.CertPEM)
	secret.Wipe(p.ChainPEM)
}

func (s *HostRollbackStore) hostRenewPath(connectorName, targetID string) string {
	name := trstcrypto.SHA256Hex([]byte(s.tenantID + "\x00" + connectorName + "\x00" + targetID))
	return filepath.Join(s.root, name+".renew")
}

func (s *HostRollbackStore) hostRenewAAD(connectorName, targetID string) []byte {
	return []byte("trstctl.host.renew.v1\x00" + s.tenantID + "\x00" + connectorName + "\x00" + targetID)
}

func (s *HostRollbackStore) loadHostRenew(connectorName, targetID string) (*hostRenewPending, error) {
	ciphertext, err := secretfile.Load(s.hostRenewPath(connectorName, targetID))
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(ciphertext)
	var plaintext []byte
	if err := s.withKey(func(key []byte) error {
		var openErr error
		plaintext, openErr = trstcrypto.AESGCMOpen(key, ciphertext, s.hostRenewAAD(connectorName, targetID))
		return openErr
	}); err != nil {
		return nil, fmt.Errorf("relay: open pending host renewal: %w", err)
	}
	defer secret.Wipe(plaintext)
	var pending hostRenewPending
	if err := json.Unmarshal(plaintext, &pending); err != nil {
		return nil, fmt.Errorf("relay: decode pending host renewal: %w", err)
	}
	if pending.JobID <= 0 || len(pending.Binding) != 64 || len(pending.CSRDER) == 0 || len(pending.KeyPEM) == 0 {
		wipeHostRenewPending(&pending)
		return nil, ErrHostRollbackStateMismatch
	}
	return &pending, nil
}

func (s *HostRollbackStore) sealHostRenew(connectorName, targetID string, p *hostRenewPending) ([]byte, error) {
	plaintext, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(plaintext)
	var ciphertext []byte
	err = s.withKey(func(key []byte) error {
		var sealErr error
		ciphertext, sealErr = trstcrypto.AESGCMSeal(key, plaintext, s.hostRenewAAD(connectorName, targetID))
		return sealErr
	})
	return ciphertext, err
}

// LoadHostRenewPending returns owned, wipeable bytes. A different job or
// reviewed payload cannot borrow a key retained for the prior command.
func (s *HostRollbackStore) LoadHostRenewPending(connectorName, targetID string, jobID int64, binding string) (*hostRenewPending, error) {
	if connectorName == "" || targetID == "" || jobID <= 0 || len(binding) != 64 {
		return nil, ErrHostRollbackStateMismatch
	}
	lock := s.targetLock(connectorName, targetID)
	lock.Lock()
	defer lock.Unlock()
	p, err := s.loadHostRenew(connectorName, targetID)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if p.JobID != jobID || p.Binding != binding {
		wipeHostRenewPending(p)
		return nil, ErrHostRollbackStateMismatch
	}
	return p, nil
}

// RecordHostRenewKey is the first-writer fence before asking the signer. The
// temporary file is fully synced, then hard-linked into the unique target slot;
// an existing slot cannot be replaced by a second process's different key.
func (s *HostRollbackStore) RecordHostRenewKey(connectorName, targetID string, jobID int64, binding string, csrDER, keyPEM []byte) error {
	if connectorName == "" || targetID == "" || jobID <= 0 || len(binding) != 64 || len(csrDER) == 0 || len(keyPEM) == 0 {
		return ErrHostRollbackStateMismatch
	}
	lock := s.targetLock(connectorName, targetID)
	lock.Lock()
	defer lock.Unlock()
	prior, err := s.loadHostRenew(connectorName, targetID)
	if err == nil {
		defer wipeHostRenewPending(prior)
		if prior.JobID != jobID || prior.Binding != binding || !bytes.Equal(prior.CSRDER, csrDER) || !bytes.Equal(prior.KeyPEM, keyPEM) {
			return ErrHostRollbackStateMismatch
		}
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	p := &hostRenewPending{JobID: jobID, Binding: binding, CSRDER: csrDER, KeyPEM: keyPEM}
	ciphertext, err := s.sealHostRenew(connectorName, targetID, p)
	if err != nil {
		return err
	}
	defer secret.Wipe(ciphertext)
	tmp, err := os.CreateTemp(s.root, ".host-renew-*") // #nosec G304 -- validated agent-local state directory
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(ciphertext); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmp.Name(), s.hostRenewPath(connectorName, targetID)); err != nil { // #nosec G703 -- both paths are agent-owned fixed state paths
		if errors.Is(err, fs.ErrExist) {
			return ErrHostRollbackStateMismatch
		}
		return err
	}
	return syncHostRenewDirectory(s.root)
}

func (s *HostRollbackStore) RecordHostRenewCertificate(connectorName, targetID string, jobID int64, binding string, certPEM, chainPEM []byte, fingerprint string) error {
	if len(certPEM) == 0 || fingerprint == "" {
		return ErrHostRollbackStateMismatch
	}
	lock := s.targetLock(connectorName, targetID)
	lock.Lock()
	defer lock.Unlock()
	p, err := s.loadHostRenew(connectorName, targetID)
	if err != nil {
		return err
	}
	defer wipeHostRenewPending(p)
	if p.JobID != jobID || p.Binding != binding {
		return ErrHostRollbackStateMismatch
	}
	if len(p.CertPEM) != 0 {
		if !bytes.Equal(p.CertPEM, certPEM) || !bytes.Equal(p.ChainPEM, chainPEM) || p.Fingerprint != fingerprint {
			return ErrHostRollbackStateMismatch
		}
		return nil
	}
	p.CertPEM, p.ChainPEM, p.Fingerprint = append([]byte(nil), certPEM...), append([]byte(nil), chainPEM...), fingerprint
	ciphertext, err := s.sealHostRenew(connectorName, targetID, p)
	if err != nil {
		return err
	}
	defer secret.Wipe(ciphertext)
	if err := writeHostRollbackStateAtomic(s.hostRenewPath(connectorName, targetID), ciphertext); err != nil {
		return err
	}
	return syncHostRenewDirectory(s.root)
}

func (s *HostRollbackStore) ClearHostRenewPending(connectorName, targetID string, jobID int64, binding, fingerprint string) error {
	lock := s.targetLock(connectorName, targetID)
	lock.Lock()
	defer lock.Unlock()
	p, err := s.loadHostRenew(connectorName, targetID)
	// A report may be accepted, the slot cleared, and the process stopped
	// before its encrypted terminal observation is acknowledged. Retrying
	// that exact report must be able to finish this cleanup again.
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer wipeHostRenewPending(p)
	if p.JobID != jobID || p.Binding != binding || p.Fingerprint != fingerprint {
		return ErrHostRollbackStateMismatch
	}
	if err := os.Remove(s.hostRenewPath(connectorName, targetID)); err != nil { // #nosec G703 -- derived agent-owned state path
		return err
	}
	return syncHostRenewDirectory(s.root)
}

func syncHostRenewDirectory(root string) error {
	dir, err := os.Open(root) // #nosec G304 -- validated agent-local state directory
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
