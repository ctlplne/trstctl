// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// MigrateLegacySigningKeyFile moves a historical plaintext PKCS#8 PEM into the
// signer's sealed keystore. It is intentionally a Server method so the only
// production caller can be cmd/trstctl-signer: legacy private bytes never enter
// the control-plane address space. The plaintext is removed only after the sealed
// key and parent directory have been synced (AUD-63 / AN-4 / AN-8).
func (s *Server) MigrateLegacySigningKeyFile(path, handle string, allowedPurposes []KeyPurpose) (bool, error) {
	if path == "" {
		return false, nil
	}
	if s == nil || s.store == nil {
		return false, errors.New("signing: legacy key migration requires a persistent signer")
	}
	if handle == "" || sanitizeHandle(handle) != handle {
		return false, fmt.Errorf("signing: invalid legacy key handle %q", handle)
	}
	pemBytes, err := os.ReadFile(path) // #nosec G304 -- signer operator supplies the one legacy migration path
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("signing: read legacy key: %w", err)
	}
	defer secret.Wipe(pemBytes)

	legacy, err := crypto.LockedKeyFromPKCS8PEM(pemBytes)
	if err != nil {
		return false, fmt.Errorf("signing: import legacy key: %w", err)
	}
	keepLegacy := false
	defer func() {
		if !keepLegacy {
			legacy.Destroy()
		}
	}()
	if legacy.Algorithm() != crypto.RSA2048 && legacy.Algorithm() != crypto.RSA3072 && legacy.Algorithm() != crypto.RSA4096 {
		return false, fmt.Errorf("signing: legacy audit key is %s, want RSA", legacy.Algorithm())
	}
	constraints, err := constraintsFromGenerate(&signerpb.GenerateKeyRequest{AllowedPurposes: allowedPurposes})
	if err != nil {
		return false, err
	}
	if len(constraints.purposes) == 0 {
		return false, errors.New("signing: legacy audit key migration requires an allowed purpose")
	}

	s.mu.Lock()
	existing := s.keys[handle]
	if existing != nil {
		if !bytes.Equal(existing.signer.Public().DER, legacy.Public().DER) {
			s.mu.Unlock()
			return false, errors.New("signing: legacy key does not match the persisted handle")
		}
		if !sameKeyConstraints(existing.constraints, constraints) {
			s.mu.Unlock()
			return false, errors.New("signing: persisted legacy handle has different usage constraints")
		}
		s.mu.Unlock()
	} else {
		if err := s.store.Save(handle, legacy, constraints); err != nil {
			s.mu.Unlock()
			return false, fmt.Errorf("signing: seal legacy key: %w", err)
		}
		if err := s.store.syncHandle(handle); err != nil {
			s.mu.Unlock()
			return false, fmt.Errorf("signing: sync sealed legacy key: %w", err)
		}
		s.keys[handle] = &heldKey{signer: legacy, constraints: constraints}
		keepLegacy = true
		s.mu.Unlock()
	}

	if err := os.Remove(path); err != nil {
		return true, fmt.Errorf("signing: remove migrated legacy key: %w", err)
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return true, fmt.Errorf("signing: sync legacy key directory: %w", err)
	}
	return true, nil
}

func sameKeyConstraints(a, b keyConstraints) bool {
	if a.requireAuth != b.requireAuth || len(a.purposes) != len(b.purposes) || len(a.hashes) != len(b.hashes) {
		return false
	}
	for purpose := range a.purposes {
		if !b.purposes[purpose] {
			return false
		}
	}
	for hash := range a.hashes {
		if !b.hashes[hash] {
			return false
		}
	}
	return true
}

func (ks *KeyStore) syncHandle(handle string) error {
	file, err := os.Open(ks.path(sanitizeHandle(handle)))
	if err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return syncDirectory(ks.dir)
}
