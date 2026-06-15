// Package secrets stores upstream CA and connector credentials encrypted at rest
// (R3.1). It wires the envelope-encryption boundary (internal/crypto/seal) to the
// credentials store: callers hand the Vault plaintext, the store only ever sees
// ciphertext. Identifiers (tenant, scope, ref, name) are ordinary strings; the
// secret values are []byte and the cryptography lives behind the boundary.
package secrets

import (
	"context"
	"os"
	"path/filepath"

	"trustctl.io/trustctl/internal/crypto"
	"trustctl.io/trustctl/internal/crypto/kek"
	"trustctl.io/trustctl/internal/crypto/seal"
	"trustctl.io/trustctl/internal/store"
)

// KEK is the key-encryption key that wraps each credential's data key. It is a
// local key today; an HSM/KMS seal.KeyWrapper can replace it without touching
// callers.
type KEK = seal.LocalKEK

// Store is the persistence the Vault needs. *store.Store satisfies it.
type Store interface {
	PutCredential(ctx context.Context, c store.Credential) error
	GetCredential(ctx context.Context, tenantID, scope, ref, name string) (store.Credential, error)
}

// Vault seals credentials before they are stored and opens them on read, so the
// store holds only ciphertext. Plaintext returned by Get is []byte the caller
// should wipe when done.
type Vault struct {
	wrapper seal.KeyWrapper
	store   Store
}

// NewVault wires a key wrapper (the KEK) to a credential store.
func NewVault(w seal.KeyWrapper, s Store) *Vault {
	return &Vault{wrapper: w, store: s}
}

// aad binds a sealed credential to its tenant and identity, so a blob cannot be
// moved to another row and still open.
func aad(tenantID, scope, ref, name string) []byte {
	return []byte(tenantID + "/" + scope + "/" + ref + "/" + name)
}

// Put seals plaintext and stores the ciphertext for (tenant, scope, ref, name).
func (v *Vault) Put(ctx context.Context, tenantID, scope, ref, name string, plaintext []byte) error {
	sealed, err := seal.Seal(v.wrapper, plaintext, aad(tenantID, scope, ref, name))
	if err != nil {
		return err
	}
	return v.store.PutCredential(ctx, store.Credential{
		TenantID: tenantID, Scope: scope, Ref: ref, Name: name, Sealed: sealed,
	})
}

// Get loads and opens the credential for (tenant, scope, ref, name).
func (v *Vault) Get(ctx context.Context, tenantID, scope, ref, name string) ([]byte, error) {
	c, err := v.store.GetCredential(ctx, tenantID, scope, ref, name)
	if err != nil {
		return nil, err
	}
	return seal.Open(v.wrapper, c.Sealed, aad(tenantID, scope, ref, name))
}

// LoadOrCreateKEK loads a 32-byte key-encryption key from path, creating one
// (random, 0600) if absent. The KEK is the root of trust for credentials at rest;
// back it up with the same care as the audit signing key (see the DR runbook), or
// supply it from an HSM/KMS in production. It delegates to internal/crypto/kek so
// the same loader is reused by the signer (which must not import this package).
func LoadOrCreateKEK(path string) (*KEK, error) {
	return kek.LoadOrCreate(path)
}

// authSecretSize is the length of the served machine-login HMAC key (256 bits).
const authSecretSize = 32

// LoadOrCreateAuthSecret loads the served machine-login HMAC key from path, creating
// one (random, 0600) if absent (GAP-006 / authmethod F58). It is the key the served
// TokenMethod verifies a workload token's MAC against, so it must be stable across
// restarts and backed up like the KEK. The returned key is []byte the caller holds
// for the process lifetime and never logs (AN-8); random generation routes through
// the crypto boundary (AN-3).
func LoadOrCreateAuthSecret(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		return raw, nil
	case os.IsNotExist(err):
		fresh, gerr := crypto.RandomBytes(authSecretSize)
		if gerr != nil {
			return nil, gerr
		}
		if mderr := os.MkdirAll(filepath.Dir(path), 0o700); mderr != nil {
			return nil, mderr
		}
		if werr := os.WriteFile(path, fresh, 0o600); werr != nil {
			return nil, werr
		}
		return fresh, nil
	default:
		return nil, err
	}
}
