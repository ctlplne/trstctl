// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"encoding/pem"
	"errors"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// NormalizeDeploymentPrivateKeyPEM accepts exactly one parseable TLS private
// key block. The returned canonical PEM stays in locked memory until Destroy.
func NormalizeDeploymentPrivateKeyPEM(raw []byte) (*secret.Buffer, PrivateKeyInfo, error) {
	if len(raw) == 0 || len(raw) > 128<<10 {
		return nil, PrivateKeyInfo{}, errors.New("crypto: deployment private key exceeds its size limit or is empty")
	}
	trimmed := bytes.TrimSpace(raw)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) || bytes.Count(trimmed, []byte("-----BEGIN ")) != 1 {
		return nil, PrivateKeyInfo{}, errors.New("crypto: deployment private key is not one PEM block")
	}
	block, rest := pem.Decode(trimmed)
	if block != nil {
		defer secret.Wipe(block.Bytes)
	}
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, PrivateKeyInfo{}, errors.New("crypto: deployment private key is not one PEM block")
	}
	switch block.Type {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
	default:
		return nil, PrivateKeyInfo{}, errors.New("crypto: unsupported deployment private key PEM type")
	}
	canonical := pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes})
	defer secret.Wipe(canonical)
	if len(canonical) == 0 || len(canonical) > 128<<10 {
		return nil, PrivateKeyInfo{}, errors.New("crypto: canonical deployment private key exceeds its size limit")
	}
	info, err := InspectPrivateKey(canonical)
	if err != nil || info.Encrypted || info.FingerprintSHA256 == "" {
		return nil, PrivateKeyInfo{}, errors.New("crypto: deployment private key does not parse")
	}
	protected, err := secret.NewFrom(canonical)
	if err != nil {
		return nil, PrivateKeyInfo{}, err
	}
	return protected, info, nil
}
