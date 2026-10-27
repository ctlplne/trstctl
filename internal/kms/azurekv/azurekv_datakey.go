// SPDX-License-Identifier: BUSL-1.1

package azurekv

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// maxDataKey bounds the data key WrapDataKey accepts.
const maxDataKey = 1024

// maxDataKeyCiphertext bounds the wrapped value UnwrapDataKey forwards (an
// RSA-4096 OAEP block is 512 bytes).
const maxDataKeyCiphertext = 4096

// Data-key wrapping algorithms: RSA-OAEP-256 for a Key Vault RSA key, and the
// AES key wraps a Managed HSM AES key offers.
const (
	WrapRSAOAEP256       = "RSA-OAEP-256"
	WrapA256KW           = "A256KW"
	WrapAESKeyWrapPadded = "CKM_AES_KEY_WRAP_PAD"
)

// ValidWrapAlgorithm reports whether alg is a data-key wrapping algorithm this
// client sends.
func ValidWrapAlgorithm(alg string) bool {
	switch alg {
	case WrapRSAOAEP256, WrapA256KW, WrapAESKeyWrapPadded:
		return true
	}
	return false
}

// WrapDataKey wraps a data key with the Key Vault wrapkey operation under the
// key name at version, with alg. An empty version wraps under the key's
// current version, read first. It returns the version that wrapped, which
// UnwrapDataKey needs: Key Vault's wrapkey and unwrapkey name a version.
func (b *Backend) WrapDataKey(ctx context.Context, name, version, alg string, dataKey []byte) (string, []byte, error) {
	if !validKeyComponent(name) || (version != "" && !validKeyComponent(version)) {
		return "", nil, errors.New("azure-key-vault: invalid key name or version")
	}
	if !ValidWrapAlgorithm(alg) {
		return "", nil, fmt.Errorf("azure-key-vault: unsupported wrap algorithm %q", alg)
	}
	if len(dataKey) == 0 || len(dataKey) > maxDataKey {
		return "", nil, fmt.Errorf("azure-key-vault: a data key must be 1 to %d bytes", maxDataKey)
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	if version == "" {
		var resource keyResponse
		if err := b.call(ctx, http.MethodGet, keyPath(name, ""), nil, &resource); err != nil {
			return "", nil, fmt.Errorf("azure-key-vault: read the key's current version: %w", err)
		}
		resolvedName, resolvedVersion := keyNameAndVersion(resource.Key.Kid, "")
		if resolvedName != name || !validKeyComponent(resolvedVersion) {
			return "", nil, errors.New("azure-key-vault: the key's current version is unreadable")
		}
		version = resolvedVersion
	}
	body := keyOperationBody(alg, dataKey)
	defer secret.Wipe(body)
	var out struct {
		Kid   string         `json:"kid"`
		Value base64URLBytes `json:"value"`
	}
	if err := b.call(ctx, http.MethodPost, keyPath(name, version)+"/wrapkey", body, &out); err != nil {
		return "", nil, fmt.Errorf("azure-key-vault: wrapkey: %w", err)
	}
	if gotName, gotVersion := keyNameAndVersion(out.Kid, ""); gotName != name || gotVersion != version {
		return "", nil, errors.New("azure-key-vault: wrapkey answered for another key")
	}
	if len(out.Value) == 0 {
		return "", nil, errors.New("azure-key-vault: wrapkey returned no value")
	}
	return version, out.Value, nil
}

// UnwrapDataKey reverses WrapDataKey under the same key version and alg. The
// caller wipes the result.
func (b *Backend) UnwrapDataKey(ctx context.Context, name, version, alg string, wrapped []byte) ([]byte, error) {
	if !validKeyComponent(name) || !validKeyComponent(version) {
		return nil, errors.New("azure-key-vault: invalid key name or version")
	}
	if !ValidWrapAlgorithm(alg) {
		return nil, fmt.Errorf("azure-key-vault: unsupported wrap algorithm %q", alg)
	}
	if len(wrapped) == 0 || len(wrapped) > maxDataKeyCiphertext {
		return nil, fmt.Errorf("azure-key-vault: a wrapped data key must be 1 to %d bytes", maxDataKeyCiphertext)
	}
	body := keyOperationBody(alg, wrapped)
	defer secret.Wipe(body)
	var out struct {
		Kid   string         `json:"kid"`
		Value base64URLBytes `json:"value"`
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	if err := b.call(ctx, http.MethodPost, keyPath(name, version)+"/unwrapkey", body, &out); err != nil {
		return nil, fmt.Errorf("azure-key-vault: unwrapkey: %w", err)
	}
	if len(out.Value) == 0 {
		return nil, errors.New("azure-key-vault: unwrapkey returned no value")
	}
	return out.Value, nil
}

// keyOperationBody is {"alg":alg,"value":base64url(value)} in one buffer the
// caller wipes; alg is one of the constant algorithm names.
func keyOperationBody(alg string, value []byte) []byte {
	enc := base64.RawURLEncoding
	body := make([]byte, 0, 32+len(alg)+enc.EncodedLen(len(value)))
	body = append(body, `{"alg":"`...)
	body = append(body, alg...)
	body = append(body, `","value":"`...)
	body = enc.AppendEncode(body, value)
	return append(body, `"}`...)
}

// base64URLBytes decodes a JSON base64url string straight into bytes, so a
// data key never passes through a Go string. Key Vault sends base64url without
// padding; padded and standard-alphabet values are accepted too.
type base64URLBytes []byte

func (v *base64URLBytes) UnmarshalJSON(data []byte) error {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return errors.New("azure-key-vault: value is not a JSON string")
	}
	raw := data[1 : len(data)-1]
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		out := make([]byte, enc.DecodedLen(len(raw)))
		n, err := enc.Decode(out, raw)
		if err == nil {
			*v = out[:n]
			return nil
		}
		secret.Wipe(out)
	}
	return errors.New("azure-key-vault: value is not base64url")
}
