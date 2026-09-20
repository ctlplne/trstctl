// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/tenantseal"
)

type tenantCipherContextKey struct{}

// withTenantCipher keeps one tenant-domain lease in the context so a complete
// request or worker delivery can hold the shared cross-replica fence while
// nested helpers seal/open individual values without acquiring a second lease.
func withTenantCipher(
	ctx context.Context,
	access tenantseal.Access,
	legacy seal.KeyWrapper,
	tenantID string,
	fn func(context.Context, tenantseal.Cipher) error,
) error {
	if fn == nil {
		return errors.New("server: tenant cipher callback is required")
	}
	if cipher, ok := ctx.Value(tenantCipherContextKey{}).(tenantseal.Cipher); ok {
		return fn(ctx, cipher)
	}
	if access != nil {
		return access.WithTenant(ctx, tenantID, func(cipher tenantseal.Cipher) error {
			return fn(context.WithValue(ctx, tenantCipherContextKey{}, cipher), cipher)
		})
	}
	if legacy == nil {
		return errors.New("server: tenant cryptographic access is not configured")
	}
	return fn(ctx, legacyTenantCipher{wrapper: legacy})
}

func sealTenantValue(ctx context.Context, access tenantseal.Access, legacy seal.KeyWrapper, tenantID string, plaintext, aad []byte) ([]byte, error) {
	var sealed []byte
	err := withTenantCipher(ctx, access, legacy, tenantID, func(_ context.Context, cipher tenantseal.Cipher) (err error) {
		sealed, err = cipher.Seal(plaintext, aad)
		return err
	})
	if err != nil {
		secret.Wipe(sealed)
		return nil, err
	}
	return sealed, nil
}

func openTenantValue(ctx context.Context, access tenantseal.Access, legacy seal.KeyWrapper, tenantID string, container, aad []byte) ([]byte, error) {
	var plaintext []byte
	err := withTenantCipher(ctx, access, legacy, tenantID, func(_ context.Context, cipher tenantseal.Cipher) (err error) {
		plaintext, err = cipher.Open(container, aad)
		return err
	})
	if err != nil {
		secret.Wipe(plaintext)
		return nil, err
	}
	return plaintext, nil
}

type legacyTenantCipher struct{ wrapper seal.KeyWrapper }

func (c legacyTenantCipher) Seal(plaintext, aad []byte) ([]byte, error) {
	return seal.Seal(c.wrapper, plaintext, aad)
}

func (c legacyTenantCipher) Open(container, aad []byte) ([]byte, error) {
	return seal.Open(c.wrapper, container, aad)
}
