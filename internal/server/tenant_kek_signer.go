// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/tenantseal"
)

// pkcs11WrapperRegistryFromConfig routes the operator's pkcs11 wrapper IDs to
// the isolated signer (A123): tenant domain KEKs under those wrappers are held
// by the signer under HSM keys and never reach this process. With no pkcs11
// wrappers configured the kind stays unrouted and a migration to it is refused
// as not configured.
func pkcs11WrapperRegistryFromConfig(wrappers []config.TenantSealPKCS11Wrapper, signer SignerProvider) (*tenantseal.SignerWrapperRegistry, error) {
	if len(wrappers) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(wrappers))
	for _, w := range wrappers {
		ids = append(ids, w.ID)
	}
	return tenantseal.NewSignerWrapperRegistry(ids, func() tenantseal.SignerTenantKEK {
		if signer == nil {
			return nil
		}
		client := signer.Client()
		if client == nil {
			return nil
		}
		return signerTenantKEK{client: client}
	})
}

// signerTenantKEK carries tenant KEK calls to the signer. A signer without the
// custody, or without the wrapper, is a wrapper that is not configured; the
// rest keep the tenant-wrap classes the signing client already reports.
type signerTenantKEK struct{ client *signing.Client }

var _ tenantseal.SignerTenantKEK = signerTenantKEK{}

func (s signerTenantKEK) CreateTenantDomainKEK(ctx context.Context, wrapperID string, binding []byte) ([]byte, error) {
	out, err := s.client.CreateTenantDomainKEK(ctx, wrapperID, binding)
	return out, signerTenantKEKError(err)
}

func (s signerTenantKEK) OpenTenantDomainKEK(ctx context.Context, wrapperID string, wrapped, binding []byte) error {
	return signerTenantKEKError(s.client.OpenTenantDomainKEK(ctx, wrapperID, wrapped, binding))
}

func (s signerTenantKEK) WrapTenantDataKey(ctx context.Context, wrapperID string, wrapped, binding, dataKey []byte) ([]byte, error) {
	out, err := s.client.WrapTenantDataKey(ctx, wrapperID, wrapped, binding, dataKey)
	return out, signerTenantKEKError(err)
}

func (s signerTenantKEK) UnwrapTenantDataKey(ctx context.Context, wrapperID string, wrapped, binding, wrappedDataKey []byte) ([]byte, error) {
	out, err := s.client.UnwrapTenantDataKey(ctx, wrapperID, wrapped, binding, wrappedDataKey)
	return out, signerTenantKEKError(err)
}

func signerTenantKEKError(err error) error {
	if errors.Is(err, signing.ErrNoTenantKEKCustody) || errors.Is(err, signing.ErrTenantKEKWrapperUnknown) {
		return fmt.Errorf("%w: %w", tenantseal.ErrWrapperNotConfigured, err)
	}
	return err
}
