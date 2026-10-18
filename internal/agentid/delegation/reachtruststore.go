// SPDX-License-Identifier: BUSL-1.1

package delegation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

const durableReachVerdictDir = "agid-reach-verdict-keys"

var ErrReachabilityTrustConflict = signing.ErrAgentReachabilityConflict

// DurableReachabilityTrustStore is the AN-4-safe signer provisioning store for trusted
// reachability-verdict public keys. The control plane writes public DER into the signer
// keystore/floor directory; the isolated signer reads it dynamically and links no SQL,
// NATS, HTTP, or control-plane graph code.
type DurableReachabilityTrustStore struct {
	floorDir string
}

// NewDurableReachabilityTrustStore builds a durable verdict-key trust store rooted at
// floorDir.
func NewDurableReachabilityTrustStore(floorDir string) *DurableReachabilityTrustStore {
	return &DurableReachabilityTrustStore{floorDir: floorDir}
}

// PutVerdictSigner writes one trusted reachability-verdict public key. The bytes are
// public SubjectPublicKeyInfo DER; mode 0600 keeps the signer floor operator-controlled.
func (s *DurableReachabilityTrustStore) PutVerdictSigner(_ context.Context, keyID string, publicDER []byte) error {
	path, err := s.path(keyID)
	if err != nil {
		return err
	}
	if err := crypto.ValidatePublicKeyDER(publicDER); err != nil {
		return fmt.Errorf("delegation: invalid reachability verdict public key: %w", err)
	}
	dirPath := filepath.Dir(path)
	if err := os.MkdirAll(dirPath, 0o700); err != nil {
		return fmt.Errorf("delegation: create reachability trust directory: %w", err)
	}
	// Publish only a fully synced public key. Link is an atomic first-writer fence:
	// concurrent provisioners cannot replace each other's signer trust.
	tmp, err := os.CreateTemp(dirPath, ".reach-verdict-*")
	if err != nil {
		return fmt.Errorf("delegation: stage verdict public key: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(publicDER); err != nil {
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
	if err := os.Link(tmp.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("delegation: publish verdict public key: %w", err)
	}
	stored, err := readUnderRoot(path)
	if err != nil {
		return fmt.Errorf("delegation: read verdict public key: %w", err)
	}
	if !bytes.Equal(stored, publicDER) {
		return ErrReachabilityTrustConflict
	}
	dir, err := os.Open(dirPath) // #nosec G304 -- signer-owned floor and validated key ID; open only to fsync the published directory
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("delegation: sync verdict trust directory: %w", err)
	}
	return nil
}

// TrustLookup implements reach.VerdictTrustLookup. It reads the requested key from disk
// on each verification, so keys provisioned after signer start are visible on the next
// issuance and remain visible after signer restart.
func (s *DurableReachabilityTrustStore) TrustLookup(keyID string) ([]byte, bool) {
	publicDER, err := s.ReadVerdictSigner(context.Background(), keyID)
	if err != nil || len(publicDER) == 0 {
		return nil, false
	}
	return append([]byte(nil), publicDER...), true
}

// ReadVerdictSigner is the independent signer-local readback used after RPC
// provisioning and after a cold restart. Missing or unreadable material is an
// error, never an inferred match from the control-plane file.
func (s *DurableReachabilityTrustStore) ReadVerdictSigner(_ context.Context, keyID string) ([]byte, error) {
	path, err := s.path(keyID)
	if err != nil {
		return nil, err
	}
	publicDER, err := readUnderRoot(path)
	if err != nil {
		return nil, err
	}
	if err := crypto.ValidatePublicKeyDER(publicDER); err != nil {
		return nil, err
	}
	return append([]byte(nil), publicDER...), nil
}

func (s *DurableReachabilityTrustStore) path(keyID string) (string, error) {
	if s == nil || s.floorDir == "" {
		return "", errors.New("delegation: reachability trust store floor directory is not configured")
	}
	if !safeAnchorSegment(keyID) {
		return "", fmt.Errorf("delegation: unsafe reachability verdict key id %q", keyID)
	}
	return filepath.Join(s.floorDir, durableReachVerdictDir, keyID+".der"), nil
}
