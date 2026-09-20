// SPDX-License-Identifier: BUSL-1.1

package awskms

// This file implements crypto.RemoteKeyLifecycle for AWS KMS (EXC-CRYPTO-01): the
// BYOK/HSM lifecycle for a key whose private material never leaves KMS. Rotate
// mints a successor KMS key; Revoke calls DisableKey so KMS refuses further
// signatures; Zeroize calls ScheduleKeyDeletion so KMS destroys the material after
// the (provider-enforced) pending window. The private key is never exported, so
// there is no local buffer to zeroize — the device/provider is the custodian, and
// this is the durable-custody story the in-process secret.Buffer path documents as
// its residual. Every op routes through the official AWS SDK v2 KMS client and the
// AN-3 crypto boundary (no crypto/*).

import (
	"context"
	"errors"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awskmssdk "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"

	"trstctl.com/trstctl/internal/crypto"
)

var _ crypto.RemoteKeyLifecycle = (*Backend)(nil)
var _ crypto.OperationAwareRemoteKeyLifecycle = (*Backend)(nil)
var _ crypto.RemoteKeyDigestSigner = (*Backend)(nil)

// pendingDeletionWindowDays is the KMS-enforced waiting period before a scheduled
// key deletion takes effect. KMS requires 7..30; trstctl asks for the minimum so
// a zeroize is as prompt as the provider allows while still being recoverable
// within the window (an operator can CancelKeyDeletion if a zeroize was in error).
const pendingDeletionWindowDays = 7

// operationTagKey is stamped in the same CreateKey request that creates the key.
// AWS KMS does not accept an idempotency token for CreateKey, so the tag is the
// durable recovery anchor: after an ambiguous response the replay scans KMS and
// binds the already-created key instead of issuing another CreateKey.
const operationTagKey = "trstctl-managed-key-operation"

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

// GenerateManagedKeyForOperation creates exactly one KMS key for a durable signer
// command. The operation tag is part of CreateKey (not a later TagResource call),
// so even a process death immediately after the provider effect leaves enough
// provider state for the next process to find the key.
func (b *Backend) GenerateManagedKeyForOperation(ctx context.Context, operationID string, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	return b.managedKeyForOperation(ctx, "generate", operationID, "", alg)
}

// RotateKeyForOperation uses the same tagged-create recovery path, with the
// predecessor ref included in the tag digest so a rotate command cannot collide
// with a generate command that happens to reuse an operation id.
func (b *Backend) RotateKeyForOperation(ctx context.Context, operationID string, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	if ref.ID == "" {
		return nil, crypto.KeyRef{}, fmt.Errorf("aws-kms: rotate requires a key ref")
	}
	return b.managedKeyForOperation(ctx, "rotate", operationID, ref.ID, ref.Algorithm)
}

func (b *Backend) managedKeyForOperation(ctx context.Context, kind, operationID, source string, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	if strings.TrimSpace(operationID) == "" {
		return nil, crypto.KeyRef{}, fmt.Errorf("aws-kms: durable operation id is required")
	}
	spec, err := keySpec(alg)
	if err != nil {
		return nil, crypto.KeyRef{}, err
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	tagValue := crypto.SHA256Hex([]byte(kind + "\x00" + operationID + "\x00" + source + "\x00" + string(alg)))
	keyID, found, err := b.findKeyByOperationTag(ctx, tagValue)
	if err != nil {
		return nil, crypto.KeyRef{}, err
	}
	if !found {
		created, createErr := b.client.CreateKey(ctx, &awskmssdk.CreateKeyInput{
			KeySpec:  spec,
			KeyUsage: types.KeyUsageTypeSignVerify,
			Tags: []types.Tag{{
				TagKey:   awssdk.String(operationTagKey),
				TagValue: awssdk.String(tagValue),
			}},
		}, func(options *awskmssdk.Options) {
			// CreateKey has no idempotency token. A transparent SDK retry after the
			// provider applied the first request would create a second key before our
			// tag lookup could run, so durable creates are deliberately single-shot.
			options.Retryer = awssdk.NopRetryer{}
		})
		if createErr != nil {
			return nil, crypto.KeyRef{}, fmt.Errorf("aws-kms: create operation-owned key: %w", createErr)
		}
		if created.KeyMetadata == nil || awssdk.ToString(created.KeyMetadata.KeyId) == "" {
			return nil, crypto.KeyRef{}, fmt.Errorf("aws-kms: create operation-owned key returned no key id")
		}
		keyID = awssdk.ToString(created.KeyMetadata.KeyId)
	}
	metadata, err := b.describeKey(ctx, keyID)
	if err != nil {
		return nil, crypto.KeyRef{}, err
	}
	if metadata.KeySpec != spec || metadata.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, crypto.KeyRef{}, fmt.Errorf("aws-kms: operation-owned key %q has spec/usage %q/%q, want %q/%q", keyID, metadata.KeySpec, metadata.KeyUsage, spec, types.KeyUsageTypeSignVerify)
	}
	pub, err := b.publicKey(ctx, keyID, alg)
	if err != nil {
		return nil, crypto.KeyRef{}, err
	}
	signer := &kmsSigner{b: b, keyID: keyID, alg: alg, pub: pub}
	return signer, crypto.KeyRef{ID: keyID, Algorithm: alg}, nil
}

func (b *Backend) findKeyByOperationTag(ctx context.Context, value string) (string, bool, error) {
	keys := awskmssdk.NewListKeysPaginator(b.client, &awskmssdk.ListKeysInput{})
	match := ""
	for keys.HasMorePages() {
		page, err := keys.NextPage(ctx)
		if err != nil {
			return "", false, fmt.Errorf("aws-kms: list keys for operation reconciliation: %w", err)
		}
		for _, entry := range page.Keys {
			keyID := awssdk.ToString(entry.KeyId)
			if keyID == "" {
				continue
			}
			tags := awskmssdk.NewListResourceTagsPaginator(b.client, &awskmssdk.ListResourceTagsInput{KeyId: awssdk.String(keyID)})
			owned := false
			for tags.HasMorePages() {
				tagPage, err := tags.NextPage(ctx)
				if err != nil {
					return "", false, fmt.Errorf("aws-kms: list tags for key %q: %w", keyID, err)
				}
				for _, tag := range tagPage.Tags {
					if awssdk.ToString(tag.TagKey) == operationTagKey && awssdk.ToString(tag.TagValue) == value {
						owned = true
						break
					}
				}
			}
			if !owned {
				continue
			}
			if match != "" && match != keyID {
				return "", false, fmt.Errorf("aws-kms: operation tag resolved to multiple keys (%q and %q)", match, keyID)
			}
			match = keyID
		}
	}
	return match, match != "", nil
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
	if _, err := b.client.DisableKey(ctx, &awskmssdk.DisableKeyInput{KeyId: awssdk.String(ref.ID)}); err != nil {
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
	if _, err := b.client.ScheduleKeyDeletion(ctx, &awskmssdk.ScheduleKeyDeletionInput{
		KeyId:               awssdk.String(ref.ID),
		PendingWindowInDays: awssdk.Int32(pendingDeletionWindowDays),
	}); err != nil {
		return fmt.Errorf("aws-kms: schedule key deletion (zeroize): %w", err)
	}
	return nil
}

// RevokeKeyForOperation first reads provider state, applies DisableKey only when
// needed, and then reads it again. A replay after response loss observes Disabled
// (or the stronger deletion states) and does not repeat the mutation.
func (b *Backend) RevokeKeyForOperation(ctx context.Context, operationID string, ref crypto.KeyRef) error {
	if strings.TrimSpace(operationID) == "" {
		return fmt.Errorf("aws-kms: durable operation id is required")
	}
	if ref.ID == "" {
		return fmt.Errorf("aws-kms: revoke requires a key ref")
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	metadata, err := b.describeKey(ctx, ref.ID)
	if err != nil {
		if isAWSNotFound(err) {
			return nil
		}
		return err
	}
	if awsRevokedState(metadata.KeyState) {
		return nil
	}
	if _, err := b.client.DisableKey(ctx, &awskmssdk.DisableKeyInput{KeyId: awssdk.String(ref.ID)}, func(options *awskmssdk.Options) {
		options.Retryer = awssdk.NopRetryer{}
	}); err != nil {
		return fmt.Errorf("aws-kms: disable operation-owned key: %w", err)
	}
	metadata, err = b.describeKey(ctx, ref.ID)
	if err != nil {
		if isAWSNotFound(err) {
			return nil
		}
		return err
	}
	if !awsRevokedState(metadata.KeyState) {
		return fmt.Errorf("aws-kms: key %q state is %q after revoke, want Disabled or deletion terminal", ref.ID, metadata.KeyState)
	}
	return nil
}

// ZeroizeKeyForOperation confirms PendingDeletion (or completed deletion) before
// returning success. ScheduleKeyDeletion is single-shot for the same reason as
// CreateKey: an ambiguous response is reconciled by the next provider-state read.
func (b *Backend) ZeroizeKeyForOperation(ctx context.Context, operationID string, ref crypto.KeyRef) error {
	if strings.TrimSpace(operationID) == "" {
		return fmt.Errorf("aws-kms: durable operation id is required")
	}
	if ref.ID == "" {
		return fmt.Errorf("aws-kms: zeroize requires a key ref")
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	metadata, err := b.describeKey(ctx, ref.ID)
	if err != nil {
		if isAWSNotFound(err) {
			return nil
		}
		return err
	}
	if awsZeroizedState(metadata.KeyState) {
		return nil
	}
	if _, err := b.client.ScheduleKeyDeletion(ctx, &awskmssdk.ScheduleKeyDeletionInput{
		KeyId: awssdk.String(ref.ID), PendingWindowInDays: awssdk.Int32(pendingDeletionWindowDays),
	}, func(options *awskmssdk.Options) {
		options.Retryer = awssdk.NopRetryer{}
	}); err != nil {
		return fmt.Errorf("aws-kms: schedule deletion for operation-owned key: %w", err)
	}
	metadata, err = b.describeKey(ctx, ref.ID)
	if err != nil {
		if isAWSNotFound(err) {
			return nil
		}
		return err
	}
	if !awsZeroizedState(metadata.KeyState) {
		return fmt.Errorf("aws-kms: key %q state is %q after zeroize, want pending deletion", ref.ID, metadata.KeyState)
	}
	return nil
}

func (b *Backend) describeKey(ctx context.Context, keyID string) (*types.KeyMetadata, error) {
	out, err := b.client.DescribeKey(ctx, &awskmssdk.DescribeKeyInput{KeyId: awssdk.String(keyID)})
	if err != nil {
		return nil, fmt.Errorf("aws-kms: describe key %q: %w", keyID, err)
	}
	if out.KeyMetadata == nil {
		return nil, fmt.Errorf("aws-kms: describe key %q returned no metadata", keyID)
	}
	return out.KeyMetadata, nil
}

func awsRevokedState(state types.KeyState) bool {
	return state == types.KeyStateDisabled || awsZeroizedState(state)
}

func awsZeroizedState(state types.KeyState) bool {
	return state == types.KeyStatePendingDeletion || state == types.KeyStatePendingReplicaDeletion
}

func isAWSNotFound(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == "NotFoundException"
}

// SignManagedDigest signs a precomputed digest with an existing KMS key. It is
// called only inside trstctl-signer after tenant/provider ownership validation.
func (b *Backend) SignManagedDigest(ctx context.Context, ref crypto.KeyRef, digest []byte, opts crypto.SignOptions) ([]byte, error) {
	if ref.ID == "" {
		return nil, fmt.Errorf("aws-kms: sign requires a key ref")
	}
	sa, err := signingAlgorithm(ref.Algorithm, opts)
	if err != nil {
		return nil, err
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	out, err := b.client.Sign(ctx, &awskmssdk.SignInput{
		KeyId: awssdk.String(ref.ID), Message: append([]byte(nil), digest...),
		MessageType: types.MessageTypeDigest, SigningAlgorithm: sa,
	})
	if err != nil {
		return nil, fmt.Errorf("aws-kms: sign managed digest: %w", err)
	}
	if len(out.Signature) == 0 {
		return nil, fmt.Errorf("aws-kms: sign managed digest returned no signature")
	}
	return append([]byte(nil), out.Signature...), nil
}
