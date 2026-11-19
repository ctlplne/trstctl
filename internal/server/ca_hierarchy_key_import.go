// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// Importing a CA with the private key it already has (A128). Two custodians
// approve an import_ca_key ceremony for the exact public chain, profile and
// parent. The signer then offers a one-time import key; the operator seals the
// private key to it on their own machine (trstctl-cli ca authorities
// wrap-key), and only the sealed bytes pass through here. The signer opens the
// key, holds it under the ceremony's own handle only if it matches the
// certificate, and the chain is bound to it exactly as an existing signer-held
// key is.

// approvedKeyImport validates an import_ca_key request against its ceremony
// and returns the certificate's public key and the signer handle the key is
// held under.
func (h *caHierarchyService) approvedKeyImport(ctx context.Context, tenantID, ceremonyID, certificatePEM, parentID string, spec api.CASpec) (expected []byte, handle string, err error) {
	if ceremonyID == "" {
		return nil, "", fmt.Errorf("%w: ceremony_id is required", api.ErrCAHierarchyInvalid)
	}
	chainDER, _, err := certificateChainPEM(certificatePEM)
	if err != nil {
		return nil, "", err
	}
	purpose, err := importCAKeyPurpose(chainDER, spec, parentID)
	if err != nil {
		return nil, "", err
	}
	if err := h.requirePendingCeremonyQuorum(ctx, tenantID, ceremonyID, purpose); err != nil {
		return nil, "", caHierarchyConflict(err)
	}
	expected, err = crypto.CertificateSubjectPublicKeyInfo(chainDER[0])
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
	}
	handle = hierarchySignerHandle(ceremonyID)
	if err := h.store.ClaimCASignerHandle(ctx, tenantID, ceremonyID, handle); err != nil {
		return nil, "", caHierarchyConflict(err)
	}
	return expected, handle, nil
}

// PrepareKeyImport relays the signer's authenticated one-time offer for an
// approved import_ca_key ceremony.
func (h *caHierarchyService) PrepareKeyImport(ctx context.Context, tenantID string, req api.CAKeyImportOfferRequest) (api.CAKeyImportOffer, error) {
	ceremonyID := strings.TrimSpace(req.CeremonyID)
	expected, handle, err := h.approvedKeyImport(ctx, tenantID, ceremonyID, req.CertificatePEM, req.ParentID, req.Spec)
	if err != nil {
		return api.CAKeyImportOffer{}, err
	}
	client := h.signer.Client()
	if client == nil {
		return api.CAKeyImportOffer{}, api.ErrCAHierarchyUnavailable
	}
	policy := crypto.CAKeyImportPolicy(tenantID, ceremonyID, expected)
	policy.Handle = handle
	offer, err := client.PrepareKeyImport(ctx, policy)
	switch status.Code(err) {
	case codes.OK:
	case codes.FailedPrecondition, codes.AlreadyExists:
		return api.CAKeyImportOffer{}, fmt.Errorf("%w: %s", api.ErrCAHierarchyConflict, status.Convert(err).Message())
	case codes.Unimplemented:
		return api.CAKeyImportOffer{}, api.ErrCAImportSignerUpgrade
	case codes.Unavailable, codes.ResourceExhausted:
		return api.CAKeyImportOffer{}, api.ErrCAImportSignerBusy
	default:
		return api.CAKeyImportOffer{}, err
	}
	return api.CAKeyImportOffer{
		CeremonyID: ceremonyID, AuthenticatedKeyImportOffer: offer,
	}, nil
}

// ImportKey takes the sealed private key into the signer, then binds the
// approved chain to it and consumes the ceremony.
func (h *caHierarchyService) ImportKey(ctx context.Context, tenantID string, req api.CAImportKeyRequest) (api.CAAuthority, error) {
	ceremonyID := strings.TrimSpace(req.CeremonyID)
	if len(req.SealedKey) != 0 || len(req.SealedKeyV2) == 0 {
		return api.CAAuthority{}, fmt.Errorf("%w: sealed_key_v2 is required; obtain a signed offer and use the upgraded trstctl-cli ca authorities wrap-key", api.ErrCAHierarchyInvalid)
	}
	expected, handle, err := h.approvedKeyImport(ctx, tenantID, ceremonyID, req.CertificatePEM, req.ParentID, req.Spec)
	if err != nil {
		return api.CAAuthority{}, err
	}
	client := h.signer.Client()
	if client == nil {
		return api.CAAuthority{}, api.ErrCAHierarchyUnavailable
	}
	policy := crypto.CAKeyImportPolicy(tenantID, ceremonyID, expected)
	policy.Handle = handle
	_, err = client.ImportDualControlKey(ctx, signing.KeyImport{Policy: policy, SealedKey: req.SealedKeyV2},
		signing.PurposeCASign, h.signAuthz)
	switch status.Code(err) {
	case codes.OK:
	case codes.InvalidArgument:
		return api.CAAuthority{}, fmt.Errorf("%w: %s", api.ErrCAHierarchyInvalid, status.Convert(err).Message())
	case codes.FailedPrecondition, codes.AlreadyExists:
		return api.CAAuthority{}, fmt.Errorf("%w: %s", api.ErrCAHierarchyConflict, status.Convert(err).Message())
	case codes.Unimplemented:
		return api.CAAuthority{}, api.ErrCAImportSignerUpgrade
	case codes.Unavailable, codes.ResourceExhausted:
		return api.CAAuthority{}, api.ErrCAImportSignerBusy
	default:
		return api.CAAuthority{}, err
	}
	return h.ImportExisting(ctx, tenantID, api.CAImportExistingRequest{
		CeremonyID: ceremonyID, CertificatePEM: req.CertificatePEM, SignerHandle: handle,
		ParentID: req.ParentID, Spec: req.Spec,
	})
}
