// SPDX-License-Identifier: BUSL-1.1

package delegation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const durableReachVerdictDir = "agid-reach-verdict-keys"

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
	if len(publicDER) == 0 {
		return errors.New("delegation: reachability verdict public DER is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("delegation: create reachability trust directory: %w", err)
	}
	if err := os.WriteFile(path, append([]byte(nil), publicDER...), 0o600); err != nil {
		return fmt.Errorf("delegation: write reachability verdict public key: %w", err)
	}
	return nil
}

// TrustLookup implements reach.VerdictTrustLookup. It reads the requested key from disk
// on each verification, so keys provisioned after signer start are visible on the next
// issuance and remain visible after signer restart.
func (s *DurableReachabilityTrustStore) TrustLookup(keyID string) ([]byte, bool) {
	path, err := s.path(keyID)
	if err != nil {
		return nil, false
	}
	publicDER, err := readUnderRoot(path)
	if err != nil || len(publicDER) == 0 {
		return nil, false
	}
	return append([]byte(nil), publicDER...), true
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
