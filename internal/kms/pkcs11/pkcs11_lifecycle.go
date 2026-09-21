// SPDX-License-Identifier: BUSL-1.1

package pkcs11

import (
	"context"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
)

var _ crypto.RemoteKeyLifecycle = (*Backend)(nil)
var _ crypto.OperationAwareRemoteKeyLifecycle = (*Backend)(nil)
var _ crypto.RemoteKeyDigestSigner = (*Backend)(nil)

// LifecycleSession is the optional token-side lifecycle seam used by served
// managed-key custody. Real PKCS#11 modules implement this by disabling or
// destroying token objects; tests implement it with a stateful token double. The
// private key stays behind the session either way.
type LifecycleSession interface {
	RevokeKey(handle string) error
	ZeroizeKey(handle string) error
}

// OperationSession binds token-side effects to the signer's durable operation
// identity. A real module maps operationID to a deterministic CKA_ID and looks
// that object up before generating. Destructive methods read back the requested
// terminal state, so retrying after a lost response is safe.
type OperationSession interface {
	GenerateKeyForOperation(operationID string, alg crypto.Algorithm) (handle string, publicDER []byte, err error)
	RevokeKeyForOperation(operationID, handle string) error
	ZeroizeKeyForOperation(operationID, handle string) error
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
	return b.managedSigner(handle, publicDER, alg)
}

func (b *Backend) managedSigner(handle string, publicDER []byte, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	if handle == "" || len(publicDER) == 0 {
		return nil, crypto.KeyRef{}, fmt.Errorf("pkcs11: token returned an incomplete managed key")
	}
	return &signer{
		session: b.session,
		handle:  handle,
		pub:     crypto.PublicKey{Algorithm: alg, DER: publicDER},
		alg:     alg,
	}, crypto.KeyRef{ID: handle, Algorithm: alg}, nil
}

func (b *Backend) GenerateManagedKeyForOperation(ctx context.Context, operationID string, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	if err := validateOperation(ctx, operationID); err != nil {
		return nil, crypto.KeyRef{}, err
	}
	session, ok := b.session.(OperationSession)
	if !ok {
		return nil, crypto.KeyRef{}, fmt.Errorf("pkcs11: session does not support durable operation reconciliation")
	}
	handle, publicDER, err := session.GenerateKeyForOperation(operationID, alg)
	if err != nil {
		return nil, crypto.KeyRef{}, fmt.Errorf("pkcs11: reconcile managed-key generation: %w", err)
	}
	return b.managedSigner(handle, publicDER, alg)
}

// RotateKey mints a successor key of the same algorithm. The old token object is
// left intact until the caller explicitly revokes or zeroizes it.
func (b *Backend) RotateKey(ctx context.Context, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	if ref.ID == "" {
		return nil, crypto.KeyRef{}, fmt.Errorf("pkcs11: rotate requires a key ref")
	}
	return b.GenerateManagedKey(ctx, ref.Algorithm)
}

func (b *Backend) RotateKeyForOperation(ctx context.Context, operationID string, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	if ref.ID == "" {
		return nil, crypto.KeyRef{}, fmt.Errorf("pkcs11: rotate requires a key ref")
	}
	return b.GenerateManagedKeyForOperation(ctx, operationID, ref.Algorithm)
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

func (b *Backend) RevokeKeyForOperation(ctx context.Context, operationID string, ref crypto.KeyRef) error {
	if err := validateOperation(ctx, operationID); err != nil {
		return err
	}
	if ref.ID == "" {
		return fmt.Errorf("pkcs11: revoke requires a key ref")
	}
	session, ok := b.session.(OperationSession)
	if !ok {
		return fmt.Errorf("pkcs11: session does not support durable operation reconciliation")
	}
	if err := session.RevokeKeyForOperation(operationID, ref.ID); err != nil {
		return fmt.Errorf("pkcs11: reconcile revoke: %w", err)
	}
	return nil
}

// ZeroizeKey destroys the token object. This is the PKCS#11 analog of wiping a
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

func (b *Backend) ZeroizeKeyForOperation(ctx context.Context, operationID string, ref crypto.KeyRef) error {
	if err := validateOperation(ctx, operationID); err != nil {
		return err
	}
	if ref.ID == "" {
		return fmt.Errorf("pkcs11: zeroize requires a key ref")
	}
	session, ok := b.session.(OperationSession)
	if !ok {
		return fmt.Errorf("pkcs11: session does not support durable operation reconciliation")
	}
	if err := session.ZeroizeKeyForOperation(operationID, ref.ID); err != nil {
		return fmt.Errorf("pkcs11: reconcile zeroize: %w", err)
	}
	return nil
}

func validateOperation(ctx context.Context, operationID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if operationID == "" || len(operationID) > 256 {
		return fmt.Errorf("pkcs11: durable operation id is required and must be at most 256 bytes")
	}
	return nil
}

func (b *Backend) SignManagedDigest(ctx context.Context, ref crypto.KeyRef, digest []byte, opts crypto.SignOptions) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ref.ID == "" {
		return nil, fmt.Errorf("pkcs11: sign requires a key ref")
	}
	return b.session.SignDigest(ref.ID, digest, opts)
}
