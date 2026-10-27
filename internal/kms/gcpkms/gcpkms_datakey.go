// SPDX-License-Identifier: BUSL-1.1

package gcpkms

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"hash/crc32"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// maxDataKey bounds the data key EncryptDataKey accepts; Cloud KMS takes at
// most 8 KiB of plaintext and associated data together for HSM keys.
const maxDataKey = 1024

// maxDataKeyCiphertext bounds the ciphertext DecryptDataKey forwards.
const maxDataKeyCiphertext = 6144

// cryptoKeyName is a Cloud KMS CryptoKey resource name. Decrypt takes the
// CryptoKey, never one of its versions: the service picks the version that
// encrypted.
var cryptoKeyName = regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$`)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// EncryptDataKey encrypts a data key under the ENCRYPT_DECRYPT CryptoKey
// cryptoKey with the Cloud KMS encrypt method, binding aad, which
// DecryptDataKey must present again. Every value carries a CRC32C the service
// verifies, and a response whose checksums or key do not match is refused.
func (b *Backend) EncryptDataKey(ctx context.Context, cryptoKey string, dataKey, aad []byte) ([]byte, error) {
	if !cryptoKeyName.MatchString(cryptoKey) {
		return nil, errors.New("gcp-kms: the key must be a CryptoKey name, projects/P/locations/L/keyRings/R/cryptoKeys/K")
	}
	if len(dataKey) == 0 || len(dataKey) > maxDataKey {
		return nil, fmt.Errorf("gcp-kms: a data key must be 1 to %d bytes", maxDataKey)
	}
	body := dataKeyRequest("plaintext", dataKey, aad)
	defer secret.Wipe(body)
	var out struct {
		Name                                      string `json:"name"`
		Ciphertext                                []byte `json:"ciphertext"`
		CiphertextCrc32c                          string `json:"ciphertextCrc32c"`
		VerifiedPlaintextCrc32c                   bool   `json:"verifiedPlaintextCrc32c"`
		VerifiedAdditionalAuthenticatedDataCrc32c bool   `json:"verifiedAdditionalAuthenticatedDataCrc32c"`
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	if err := b.send(ctx, http.MethodPost, cryptoKey+":encrypt", body, &out); err != nil {
		return nil, err
	}
	if !out.VerifiedPlaintextCrc32c || (len(aad) > 0 && !out.VerifiedAdditionalAuthenticatedDataCrc32c) {
		return nil, errors.New("gcp-kms: encrypt did not verify the request checksums")
	}
	if !strings.HasPrefix(out.Name, cryptoKey+"/cryptoKeyVersions/") {
		return nil, errors.New("gcp-kms: encrypt answered for another key")
	}
	if len(out.Ciphertext) == 0 || !crc32cMatches(out.Ciphertext, out.CiphertextCrc32c) {
		return nil, errors.New("gcp-kms: encrypt returned a ciphertext that fails its checksum")
	}
	return out.Ciphertext, nil
}

// DecryptDataKey reverses EncryptDataKey under the same CryptoKey and aad.
// The caller wipes the result.
func (b *Backend) DecryptDataKey(ctx context.Context, cryptoKey string, ciphertext, aad []byte) ([]byte, error) {
	if !cryptoKeyName.MatchString(cryptoKey) {
		return nil, errors.New("gcp-kms: the key must be a CryptoKey name, projects/P/locations/L/keyRings/R/cryptoKeys/K")
	}
	if len(ciphertext) == 0 || len(ciphertext) > maxDataKeyCiphertext {
		return nil, fmt.Errorf("gcp-kms: a wrapped data key must be 1 to %d bytes", maxDataKeyCiphertext)
	}
	body := dataKeyRequest("ciphertext", ciphertext, aad)
	defer secret.Wipe(body)
	var out struct {
		Plaintext       []byte `json:"plaintext"`
		PlaintextCrc32c string `json:"plaintextCrc32c"`
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	if err := b.send(ctx, http.MethodPost, cryptoKey+":decrypt", body, &out); err != nil {
		return nil, err
	}
	if len(out.Plaintext) == 0 || !crc32cMatches(out.Plaintext, out.PlaintextCrc32c) {
		secret.Wipe(out.Plaintext)
		return nil, errors.New("gcp-kms: decrypt returned a data key that fails its checksum")
	}
	return out.Plaintext, nil
}

// dataKeyRequest is the JSON body of an encrypt or decrypt call, built in one
// buffer the caller wipes: value under field, then the associated data, each
// with its CRC32C as the decimal string the API expects.
func dataKeyRequest(field string, value, aad []byte) []byte {
	enc := base64.StdEncoding
	body := make([]byte, 0, 160+enc.EncodedLen(len(value))+enc.EncodedLen(len(aad)))
	body = append(body, `{"`...)
	body = append(body, field...)
	body = append(body, `":"`...)
	body = enc.AppendEncode(body, value)
	body = append(body, `","`...)
	body = append(body, field...)
	body = append(body, `Crc32c":"`...)
	body = strconv.AppendUint(body, uint64(crc32.Checksum(value, castagnoli)), 10)
	body = append(body, '"')
	if len(aad) > 0 {
		body = append(body, `,"additionalAuthenticatedData":"`...)
		body = enc.AppendEncode(body, aad)
		body = append(body, `","additionalAuthenticatedDataCrc32c":"`...)
		body = strconv.AppendUint(body, uint64(crc32.Checksum(aad, castagnoli)), 10)
		body = append(body, '"')
	}
	return append(body, '}')
}

func crc32cMatches(value []byte, sum string) bool {
	want, err := strconv.ParseUint(sum, 10, 32)
	return err == nil && uint32(want) == crc32.Checksum(value, castagnoli)
}
