// SPDX-License-Identifier: BUSL-1.1

package awskms

import (
	"context"
	"errors"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awskmssdk "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// maxDataKey bounds the data key EncryptDataKey accepts; KMS Encrypt takes at
// most 4096 bytes of plaintext, and a data key is far smaller.
const maxDataKey = 1024

// maxDataKeyCiphertext bounds the ciphertext DecryptDataKey forwards to KMS.
const maxDataKeyCiphertext = 6144

// EncryptDataKey encrypts a data key under the symmetric KMS key keyID (a key
// ARN, key ID, alias name or alias ARN) with the KMS Encrypt API, binding
// encryptionContext, which DecryptDataKey must present again. The key that
// encrypts never leaves KMS.
func (b *Backend) EncryptDataKey(ctx context.Context, keyID string, dataKey []byte, encryptionContext map[string]string) ([]byte, error) {
	if strings.TrimSpace(keyID) == "" {
		return nil, errors.New("aws-kms: a key id is required")
	}
	if len(dataKey) == 0 || len(dataKey) > maxDataKey {
		return nil, fmt.Errorf("aws-kms: a data key must be 1 to %d bytes", maxDataKey)
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	out, err := b.client.Encrypt(ctx, &awskmssdk.EncryptInput{
		KeyId:               awssdk.String(keyID),
		Plaintext:           dataKey,
		EncryptionContext:   encryptionContext,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
	})
	if err != nil {
		return nil, fmt.Errorf("aws-kms: encrypt: %w", err)
	}
	if len(out.CiphertextBlob) == 0 {
		return nil, errors.New("aws-kms: encrypt returned no ciphertext")
	}
	return append([]byte(nil), out.CiphertextBlob...), nil
}

// DecryptDataKey reverses EncryptDataKey. Naming keyID makes KMS refuse a
// ciphertext that another key produced, so a substituted blob cannot steer the
// decryption to a key someone else controls. The caller wipes the result.
func (b *Backend) DecryptDataKey(ctx context.Context, keyID string, ciphertext []byte, encryptionContext map[string]string) ([]byte, error) {
	if strings.TrimSpace(keyID) == "" {
		return nil, errors.New("aws-kms: a key id is required")
	}
	if len(ciphertext) == 0 || len(ciphertext) > maxDataKeyCiphertext {
		return nil, fmt.Errorf("aws-kms: a wrapped data key must be 1 to %d bytes", maxDataKeyCiphertext)
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	out, err := b.client.Decrypt(ctx, &awskmssdk.DecryptInput{
		KeyId:               awssdk.String(keyID),
		CiphertextBlob:      ciphertext,
		EncryptionContext:   encryptionContext,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
	})
	if err != nil {
		return nil, fmt.Errorf("aws-kms: decrypt: %w", err)
	}
	if len(out.Plaintext) == 0 {
		return nil, errors.New("aws-kms: decrypt returned no data key")
	}
	return out.Plaintext, nil
}
