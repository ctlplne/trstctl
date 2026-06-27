package auth

import (
	"context"
	"errors"

	"trstctl.com/trstctl/internal/secrets"
)

const (
	// OIDCClientSecretScope is the tenant-scoped credential scope used for OIDC
	// confidential-client secrets.
	OIDCClientSecretScope = "auth.oidc"
	// OIDCClientSecretName is the stable credential name under an OIDC client ref.
	OIDCClientSecretName = "client_secret"
)

// StoreOIDCClientSecret seals an OIDC confidential-client secret through the
// shared credential vault. The durable store sees only ciphertext under
// (tenantID, auth.oidc, ref, client_secret).
func StoreOIDCClientSecret(ctx context.Context, vault *secrets.Vault, tenantID, ref string, plaintext []byte) error {
	if vault == nil {
		return errors.New("auth: OIDC client secret vault is required")
	}
	return vault.Put(ctx, tenantID, OIDCClientSecretScope, ref, OIDCClientSecretName, plaintext)
}

// LoadOIDCClientSecret opens the sealed OIDC client secret. The returned bytes
// belong to the caller and should be wiped as soon as the token exchange finishes.
func LoadOIDCClientSecret(ctx context.Context, vault *secrets.Vault, tenantID, ref string) ([]byte, error) {
	if vault == nil {
		return nil, errors.New("auth: OIDC client secret vault is required")
	}
	return vault.Get(ctx, tenantID, OIDCClientSecretScope, ref, OIDCClientSecretName)
}

// OIDCClientSecretSource returns a token-exchange secret source backed by the
// tenant-scoped credential vault.
func OIDCClientSecretSource(vault *secrets.Vault, tenantID, ref string) func(context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		return LoadOIDCClientSecret(ctx, vault, tenantID, ref)
	}
}
