// SPDX-License-Identifier: MPL-2.0

package azurekv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"trstctl.com/trstctl/internal/crypto"
)

var _ crypto.RemoteKeyLifecycle = (*Backend)(nil)

// GenerateManagedKey creates an Azure Key Vault / Managed HSM signing key and
// returns the opaque provider key id. The private key never leaves Azure; only the
// public SPKI travels back through the crypto boundary.
func (b *Backend) GenerateManagedKey(ctx context.Context, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	signer, err := b.GenerateKeyContext(ctx, alg)
	if err != nil {
		return nil, crypto.KeyRef{}, err
	}
	ks, ok := signer.(*kvSigner)
	if !ok {
		return nil, crypto.KeyRef{}, fmt.Errorf("azure-key-vault: unexpected signer type %T", signer)
	}
	return signer, crypto.KeyRef{ID: b.vaultURL + keyPath(ks.name, ks.version), Algorithm: alg}, nil
}

// RotateKey mints a successor Azure key. The caller re-points issuance before it
// retires the superseded key, matching the other remote-custody backends.
func (b *Backend) RotateKey(ctx context.Context, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	if ref.ID == "" {
		return nil, crypto.KeyRef{}, fmt.Errorf("azure-key-vault: rotate requires a key ref")
	}
	return b.GenerateManagedKey(ctx, ref.Algorithm)
}

// RevokeKey disables the Azure key version so the provider refuses future signing
// operations with it.
func (b *Backend) RevokeKey(ctx context.Context, ref crypto.KeyRef) error {
	name, version, err := parseRef(ref)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{"attributes": map[string]bool{"enabled": false}})
	if err != nil {
		return err
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	var out map[string]any
	if err := b.call(ctx, http.MethodPatch, keyPath(name, version), body, &out); err != nil {
		return fmt.Errorf("azure-key-vault: disable (revoke) key: %w", err)
	}
	return nil
}

// ZeroizeKey deletes the Azure key so the provider schedules destruction of the
// remotely custodied material. The provider enforces its configured recovery/purge
// policy; after this call the active key can no longer sign.
func (b *Backend) ZeroizeKey(ctx context.Context, ref crypto.KeyRef) error {
	name, _, err := parseRef(ref)
	if err != nil {
		return err
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	var out map[string]any
	if err := b.call(ctx, http.MethodDelete, keyPath(name, ""), nil, &out); err != nil {
		return fmt.Errorf("azure-key-vault: delete (zeroize) key: %w", err)
	}
	return nil
}

func parseRef(ref crypto.KeyRef) (name, version string, err error) {
	if ref.ID == "" {
		return "", "", fmt.Errorf("azure-key-vault: key ref is required")
	}
	name, version = keyNameAndVersion(ref.ID, "")
	if name == "" {
		return "", "", fmt.Errorf("azure-key-vault: key ref %q does not contain a key name", ref.ID)
	}
	return name, version, nil
}
