package awskms

// This file implements crypto.RemoteKeyLifecycle for AWS KMS (EXC-CRYPTO-01): the
// BYOK/HSM lifecycle for a key whose private material never leaves KMS. Rotate
// mints a successor KMS key; Revoke calls DisableKey so KMS refuses further
// signatures; Zeroize calls ScheduleKeyDeletion so KMS destroys the material after
// the (provider-enforced) pending window. The private key is never exported, so
// there is no local buffer to zeroize — the device/provider is the custodian, and
// this is the durable-custody story the in-process secret.Buffer path documents as
// its residual. Every op routes through the same signed AWS JSON 1.1 transport and
// the AN-3 crypto boundary (no crypto/*).

import (
	"context"
	"fmt"

	"trustctl.io/trustctl/internal/crypto"
)

var _ crypto.RemoteKeyLifecycle = (*Backend)(nil)

// pendingDeletionWindowDays is the KMS-enforced waiting period before a scheduled
// key deletion takes effect. KMS requires 7..30; trustctl asks for the minimum so
// a zeroize is as prompt as the provider allows while still being recoverable
// within the window (an operator can CancelKeyDeletion if a zeroize was in error).
const pendingDeletionWindowDays = 7

// GenerateManagedKey creates an asymmetric signing key in KMS and returns a Signer
// plus a KeyRef for lifecycle management. It is the BYOK/HSM on-ramp: the key is
// born in KMS and never leaves it.
func (b *Backend) GenerateManagedKey(ctx context.Context, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	signer, err := b.GenerateKeyContext(ctx, alg)
	if err != nil {
		return nil, crypto.KeyRef{}, err
	}
	ks, ok := signer.(*kmsSigner)
	if !ok {
		return nil, crypto.KeyRef{}, fmt.Errorf("aws-kms: unexpected signer type %T", signer)
	}
	return signer, crypto.KeyRef{ID: ks.keyID, Algorithm: alg}, nil
}

// RotateKey mints a successor key in KMS of the same algorithm and returns a Signer
// and KeyRef for it. The prior key (ref) is left intact so the caller can re-point
// issuance before revoking/zeroizing it — the same supersede-then-retire ordering
// the in-process rotation uses.
func (b *Backend) RotateKey(ctx context.Context, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	if ref.ID == "" {
		return nil, crypto.KeyRef{}, fmt.Errorf("aws-kms: rotate requires a key ref")
	}
	return b.GenerateManagedKey(ctx, ref.Algorithm)
}

// RevokeKey disables the KMS key so KMS refuses further Sign calls with it
// (fail-closed at the provider). It is reversible (EnableKey) until the key is
// zeroized, mirroring the in-process revoked-then-zeroized two-step.
func (b *Backend) RevokeKey(ctx context.Context, ref crypto.KeyRef) error {
	if ref.ID == "" {
		return fmt.Errorf("aws-kms: revoke requires a key ref")
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	if err := b.call(ctx, "TrentService.DisableKey", map[string]string{"KeyId": ref.ID}, nil); err != nil {
		return fmt.Errorf("aws-kms: disable (revoke) key: %w", err)
	}
	return nil
}

// ZeroizeKey schedules deletion of the KMS key material. KMS destroys the key after
// the pending-deletion window; until then the key is in PendingDeletion and cannot
// sign. This is the remote analogue of wiping a locked buffer — the operator no
// longer holds, and cannot recover after the window, the private material.
func (b *Backend) ZeroizeKey(ctx context.Context, ref crypto.KeyRef) error {
	if ref.ID == "" {
		return fmt.Errorf("aws-kms: zeroize requires a key ref")
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	req := map[string]any{"KeyId": ref.ID, "PendingWindowInDays": pendingDeletionWindowDays}
	if err := b.call(ctx, "TrentService.ScheduleKeyDeletion", req, nil); err != nil {
		return fmt.Errorf("aws-kms: schedule key deletion (zeroize): %w", err)
	}
	return nil
}
