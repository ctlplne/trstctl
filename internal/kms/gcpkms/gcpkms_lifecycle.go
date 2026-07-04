// SPDX-License-Identifier: MPL-2.0

package gcpkms

import (
	"context"
	"fmt"
	"net/http"

	"trstctl.com/trstctl/internal/crypto"
)

var _ crypto.RemoteKeyLifecycle = (*Backend)(nil)

// GenerateManagedKey creates an asymmetric signing key version in Cloud KMS and
// returns the opaque cryptoKeyVersion resource name. The private key never leaves
// Cloud KMS.
func (b *Backend) GenerateManagedKey(ctx context.Context, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	signer, err := b.GenerateKeyContext(ctx, alg)
	if err != nil {
		return nil, crypto.KeyRef{}, err
	}
	ks, ok := signer.(*kmsSigner)
	if !ok {
		return nil, crypto.KeyRef{}, fmt.Errorf("gcp-kms: unexpected signer type %T", signer)
	}
	return signer, crypto.KeyRef{ID: ks.versionName, Algorithm: alg}, nil
}

// RotateKey mints a successor Cloud KMS signing key. The old version stays intact
// until the caller re-points issuance and explicitly revokes or zeroizes it.
func (b *Backend) RotateKey(ctx context.Context, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	if ref.ID == "" {
		return nil, crypto.KeyRef{}, fmt.Errorf("gcp-kms: rotate requires a key ref")
	}
	return b.GenerateManagedKey(ctx, ref.Algorithm)
}

// RevokeKey disables the Cloud KMS key version so asymmetricSign fails closed at
// the provider.
func (b *Backend) RevokeKey(ctx context.Context, ref crypto.KeyRef) error {
	if ref.ID == "" {
		return fmt.Errorf("gcp-kms: revoke requires a key ref")
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	var out map[string]any
	if err := b.call(ctx, http.MethodPatch, ref.ID+"?updateMask=state", map[string]string{"state": "DISABLED"}, &out); err != nil {
		return fmt.Errorf("gcp-kms: disable (revoke) key version: %w", err)
	}
	return nil
}

// ZeroizeKey asks Cloud KMS to destroy the key version. Cloud KMS moves it into a
// destroy-scheduled state and then removes the material after its provider window.
func (b *Backend) ZeroizeKey(ctx context.Context, ref crypto.KeyRef) error {
	if ref.ID == "" {
		return fmt.Errorf("gcp-kms: zeroize requires a key ref")
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	var out map[string]any
	if err := b.call(ctx, http.MethodPost, ref.ID+":destroy", map[string]any{}, &out); err != nil {
		return fmt.Errorf("gcp-kms: destroy (zeroize) key version: %w", err)
	}
	return nil
}
