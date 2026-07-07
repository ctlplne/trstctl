// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const durableAnchorDir = "agid-root-anchors"

// DurableAnchorStore is the AN-4-safe signer provisioning store for AGID root
// anchors. It is file-backed under the signer keystore/floor directory, so the
// isolated signer links no SQL, NATS, or HTTP while trust roots survive restart.
type DurableAnchorStore struct {
	floorDir string
}

// NewDurableAnchorStore builds a durable root-anchor store rooted at floorDir.
func NewDurableAnchorStore(floorDir string) *DurableAnchorStore {
	return &DurableAnchorStore{floorDir: floorDir}
}

// PutRootAnchor writes one tenant-scoped anchor into the signer provisioning
// directory. The material is public key DER plus a non-secret auth reference; file
// mode 0600 still keeps the signer floor operator-controlled.
func (s *DurableAnchorStore) PutRootAnchor(_ context.Context, tenantID, keyID string, anchor RootAnchor) error {
	pemPath, authRefPath, err := s.paths(tenantID, keyID)
	if err != nil {
		return err
	}
	if len(anchor.PublicDER) == 0 {
		return errors.New("delegation: root anchor public DER is required")
	}
	if anchor.AuthRef == "" {
		return errors.New("delegation: root anchor auth_ref is required")
	}
	if err := os.MkdirAll(filepath.Dir(pemPath), 0o700); err != nil {
		return fmt.Errorf("delegation: create root-anchor directory: %w", err)
	}
	if err := os.WriteFile(pemPath, EncodeRootAnchorPEM(anchor.PublicDER), 0o600); err != nil {
		return fmt.Errorf("delegation: write root-anchor public key: %w", err)
	}
	if err := os.WriteFile(authRefPath, []byte(anchor.AuthRef+"\n"), 0o600); err != nil {
		return fmt.Errorf("delegation: write root-anchor auth ref: %w", err)
	}
	return nil
}

// Anchor implements RootAnchorSource for the signer gate. It reads the one
// requested tenant/key pair from disk so a just-registered anchor is visible on
// the next issuance and still survives process restart.
func (s *DurableAnchorStore) Anchor(tenantID, keyID string) (RootAnchor, bool) {
	anchor, err := s.GetRootAnchor(tenantID, keyID)
	if err != nil {
		return RootAnchor{}, false
	}
	return anchor, true
}

// GetRootAnchor reads one tenant-scoped anchor from disk.
func (s *DurableAnchorStore) GetRootAnchor(tenantID, keyID string) (RootAnchor, error) {
	pemPath, authRefPath, err := s.paths(tenantID, keyID)
	if err != nil {
		return RootAnchor{}, err
	}
	pubPEM, err := os.ReadFile(pemPath)
	if err != nil {
		return RootAnchor{}, err
	}
	publicDER, err := DecodeRootAnchorPEM(pubPEM)
	if err != nil {
		return RootAnchor{}, err
	}
	authRef, err := os.ReadFile(authRefPath)
	if err != nil {
		return RootAnchor{}, err
	}
	return RootAnchor{PublicDER: publicDER, AuthRef: strings.TrimSpace(string(authRef))}, nil
}

// Load returns every tenant-scoped anchor currently provisioned on disk.
func (s *DurableAnchorStore) Load() (map[string]map[string]RootAnchor, error) {
	out := map[string]map[string]RootAnchor{}
	root := s.rootDir()
	tenants, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("delegation: read root-anchor directory: %w", err)
	}
	for _, tenantEntry := range tenants {
		if !tenantEntry.IsDir() {
			continue
		}
		tenantID := tenantEntry.Name()
		files, err := os.ReadDir(filepath.Join(root, tenantID))
		if err != nil {
			return nil, fmt.Errorf("delegation: read tenant root-anchor directory: %w", err)
		}
		for _, entry := range files {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pem") {
				continue
			}
			keyID := strings.TrimSuffix(entry.Name(), ".pem")
			anchor, err := s.GetRootAnchor(tenantID, keyID)
			if err != nil {
				return nil, err
			}
			if out[tenantID] == nil {
				out[tenantID] = map[string]RootAnchor{}
			}
			out[tenantID][keyID] = anchor
		}
	}
	return out, nil
}

// EncodeRootAnchorPEM wraps public DER in a standard PUBLIC KEY PEM block.
func EncodeRootAnchorPEM(publicDER []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: append([]byte(nil), publicDER...)})
}

// DecodeRootAnchorPEM accepts either PEM-wrapped public key bytes or raw DER.
func DecodeRootAnchorPEM(data []byte) ([]byte, error) {
	if block, _ := pem.Decode(data); block != nil {
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("delegation: unsupported root-anchor PEM block %q", block.Type)
		}
		return append([]byte(nil), block.Bytes...), nil
	}
	if len(data) == 0 {
		return nil, errors.New("delegation: empty root-anchor public key")
	}
	return append([]byte(nil), data...), nil
}

func (s *DurableAnchorStore) paths(tenantID, keyID string) (string, string, error) {
	if s == nil || s.floorDir == "" {
		return "", "", errors.New("delegation: root-anchor store floor directory is not configured")
	}
	if !safeAnchorSegment(tenantID) {
		return "", "", fmt.Errorf("delegation: unsafe tenant id %q for root-anchor path", tenantID)
	}
	if !safeAnchorSegment(keyID) {
		return "", "", fmt.Errorf("delegation: unsafe key id %q for root-anchor path", keyID)
	}
	base := filepath.Join(s.rootDir(), tenantID, keyID)
	return base + ".pem", base + ".authref", nil
}

func (s *DurableAnchorStore) rootDir() string {
	return filepath.Join(s.floorDir, durableAnchorDir)
}

func safeAnchorSegment(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.' || r == ':' || r == '@':
		default:
			return false
		}
	}
	return true
}
