// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// The transit keyring used to live only in memory, so every key vanished on
// restart and anything encrypted with it became undecryptable — a data-loss bug
// wearing the costume of a cache. This file gives it durability with the same
// custody discipline the signer's keystore already uses: sealed under the
// deployment KEK at rest (AN-8), never written in the clear, and re-derived into
// locked memory on load.
//
// Key BYTES are sealed on disk rather than event-sourced. That is deliberate and
// matches internal/signing/keystore.go: an event log is replayable, exportable
// and auditable by design, which is precisely what secret material must not be.
// The lifecycle FACTS — a key was created, a key was rotated — are audited
// through the auditor the keyring already holds.

const (
	transitStateFile   = "transit-keyring.sealed"
	transitStateFormat = "trstctl.transit.keyring.v1"
	// transitSealDomain separates these bytes from every other sealed artifact, so
	// a keyring blob cannot be opened as, say, a signer key even under the same KEK.
	transitSealDomain = "trstctl/transit-keyring"
)

// persistedKey is one named key's full version history. Versions are 1-based and
// dense, mirroring the in-memory representation.
type persistedKey struct {
	Kind   Kind     `json:"kind"`
	Latest int      `json:"latest"`
	AEAD   [][]byte `json:"aead,omitempty"`
	HMAC   [][]byte `json:"hmac,omitempty"`
	// SignPKCS8 holds each signing version as PKCS#8 DER. LockedSigner is not
	// serialisable, so the key is exported once here and re-locked on load.
	SignPKCS8 [][]byte `json:"sign_pkcs8,omitempty"`
}

type persistedState struct {
	Format string                             `json:"format"`
	Rings  map[string]map[string]persistedKey `json:"rings"`
}

// Store seals a transit keyring under the deployment KEK.
type Store struct {
	dir     string
	wrapper seal.KeyWrapper
}

// NewStore returns a keyring store rooted at dir. A nil wrapper disables
// persistence entirely rather than writing key material in the clear.
func NewStore(dir string, wrapper seal.KeyWrapper) *Store {
	if strings.TrimSpace(dir) == "" || wrapper == nil {
		return nil
	}
	return &Store{dir: dir, wrapper: wrapper}
}

func (s *Store) path() string { return filepath.Join(s.dir, transitStateFile) }

// Save seals the whole service state. It writes atomically: a torn keyring is
// worse than no keyring, because half a version history still looks loadable.
func (s *Store) Save(svc *Service) error {
	if s == nil || svc == nil {
		return nil
	}
	state := persistedState{Format: transitStateFormat, Rings: map[string]map[string]persistedKey{}}

	svc.mu.Lock()
	tenants := make([]string, 0, len(svc.rings))
	for tenantID := range svc.rings {
		tenants = append(tenants, tenantID)
	}
	sort.Strings(tenants)
	rings := make([]*Keyring, 0, len(tenants))
	for _, tenantID := range tenants {
		rings = append(rings, svc.rings[tenantID])
	}
	svc.mu.Unlock()

	for i, tenantID := range tenants {
		ring := rings[i]
		exported, err := ring.export()
		if err != nil {
			return fmt.Errorf("transit: export keyring for tenant %s: %w", tenantID, err)
		}
		if len(exported) > 0 {
			state.Rings[tenantID] = exported
		}
	}

	plaintext, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("transit: encode keyring: %w", err)
	}
	defer secret.Wipe(plaintext)

	sealed, err := seal.SealDomain(s.wrapper, plaintext, []byte(transitStateFormat), []byte(transitSealDomain))
	if err != nil {
		return fmt.Errorf("transit: seal keyring: %w", err)
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("transit: create keyring dir: %w", err)
	}
	tmp := s.path() + ".tmp"
	if err := os.WriteFile(tmp, sealed, 0o600); err != nil {
		return fmt.Errorf("transit: write sealed keyring: %w", err)
	}
	if err := os.Rename(tmp, s.path()); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("transit: commit sealed keyring: %w", err)
	}
	return nil
}

// Load restores the sealed keyring into svc. A missing file is not an error —
// that is a deployment that has never created a transit key.
func (s *Store) Load(svc *Service) error {
	if s == nil || svc == nil {
		return nil
	}
	sealed, err := os.ReadFile(s.path()) // #nosec G304 -- the store's own sealed state file (CWE-22)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("transit: read sealed keyring: %w", err)
	}
	plaintext, err := seal.OpenDomain(s.wrapper, sealed, []byte(transitStateFormat), []byte(transitSealDomain))
	if err != nil {
		return fmt.Errorf("transit: unseal keyring: %w", err)
	}
	defer secret.Wipe(plaintext)

	var state persistedState
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return fmt.Errorf("transit: decode keyring: %w", err)
	}
	if state.Format != transitStateFormat {
		return fmt.Errorf("transit: sealed keyring has format %q, want %q", state.Format, transitStateFormat)
	}
	for tenantID, keys := range state.Rings {
		ring := svc.ring(tenantID)
		if err := ring.restore(keys); err != nil {
			return fmt.Errorf("transit: restore keyring for tenant %s: %w", tenantID, err)
		}
	}
	return nil
}

// export renders the ring's keys for sealing. Signing keys are exported as
// PKCS#8 because a LockedSigner cannot be serialised; the caller seals the
// result immediately and wipes the plaintext.
func (k *Keyring) export() (map[string]persistedKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make(map[string]persistedKey, len(k.keys))
	for name, nk := range k.keys {
		p := persistedKey{Kind: nk.kind, Latest: nk.latest}
		p.AEAD = append(p.AEAD, nk.aead...)
		p.HMAC = append(p.HMAC, nk.hmac...)
		for _, signer := range nk.sign {
			if signer == nil {
				p.SignPKCS8 = append(p.SignPKCS8, nil)
				continue
			}
			der, err := signer.PKCS8()
			if err != nil {
				return nil, fmt.Errorf("export signing key %q: %w", name, err)
			}
			p.SignPKCS8 = append(p.SignPKCS8, der)
		}
		out[name] = p
	}
	return out, nil
}

// restore rebuilds the ring's keys, re-locking signing keys into protected
// memory (AN-8) rather than leaving them on the ordinary heap.
func (k *Keyring) restore(keys map[string]persistedKey) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.keys == nil {
		k.keys = map[string]*namedKey{}
	}
	for name, p := range keys {
		nk := &namedKey{kind: p.Kind, latest: p.Latest}
		nk.aead = append(nk.aead, p.AEAD...)
		nk.hmac = append(nk.hmac, p.HMAC...)
		for i, der := range p.SignPKCS8 {
			if len(der) == 0 {
				nk.sign = append(nk.sign, nil)
				continue
			}
			ls, err := crypto.LockedKeyFromPKCS8(der)
			if err != nil {
				return fmt.Errorf("restore signing key %q version %d: %w", name, i+1, err)
			}
			nk.sign = append(nk.sign, ls)
		}
		k.keys[name] = nk
	}
	return nil
}
