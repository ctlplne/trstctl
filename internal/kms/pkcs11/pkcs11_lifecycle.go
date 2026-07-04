// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
)

var _ crypto.RemoteKeyLifecycle = (*Backend)(nil)

// LifecycleSession is the optional token-side lifecycle seam used by served
// managed-key custody. Real PKCS#11 modules implement this by disabling or
// destroying token objects; tests implement it with a stateful token double. The
// private key stays behind the session either way.
type LifecycleSession interface {
	RevokeKey(handle string) error
	ZeroizeKey(handle string) error
}

// GenerateManagedKey creates a non-extractable managed key on the token and returns
// both a signer and the opaque object handle used for later lifecycle operations.
func (b *Backend) GenerateManagedKey(ctx context.Context, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	if err := ctx.Err(); err != nil {
		return nil, crypto.KeyRef{}, err
	}
	handle, publicDER, err := b.session.GenerateKey(alg)
	if err != nil {
		return nil, crypto.KeyRef{}, fmt.Errorf("pkcs11: generate managed key: %w", err)
	}
	return &signer{
		session: b.session,
		handle:  handle,
		pub:     crypto.PublicKey{Algorithm: alg, DER: publicDER},
		alg:     alg,
	}, crypto.KeyRef{ID: handle, Algorithm: alg}, nil
}

// RotateKey mints a successor key of the same algorithm. The old token object is
// left intact until the caller explicitly revokes or zeroizes it.
func (b *Backend) RotateKey(ctx context.Context, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	if ref.ID == "" {
		return nil, crypto.KeyRef{}, fmt.Errorf("pkcs11: rotate requires a key ref")
	}
	return b.GenerateManagedKey(ctx, ref.Algorithm)
}

// RevokeKey disables the token object so future signatures fail closed.
func (b *Backend) RevokeKey(ctx context.Context, ref crypto.KeyRef) error {
	if ref.ID == "" {
		return fmt.Errorf("pkcs11: revoke requires a key ref")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	lc, ok := b.session.(LifecycleSession)
	if !ok {
		return fmt.Errorf("pkcs11: session does not support lifecycle revoke")
	}
	if err := lc.RevokeKey(ref.ID); err != nil {
		return fmt.Errorf("pkcs11: revoke key: %w", err)
	}
	return nil
}

// ZeroizeKey destroys the token object. This is the PKCS#11 analogue of wiping a
// local locked buffer: the provider removes the material and signing fails closed.
func (b *Backend) ZeroizeKey(ctx context.Context, ref crypto.KeyRef) error {
	if ref.ID == "" {
		return fmt.Errorf("pkcs11: zeroize requires a key ref")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	lc, ok := b.session.(LifecycleSession)
	if !ok {
		return fmt.Errorf("pkcs11: session does not support lifecycle zeroize")
	}
	if err := lc.ZeroizeKey(ref.ID); err != nil {
		return fmt.Errorf("pkcs11: zeroize key: %w", err)
	}
	return nil
}
