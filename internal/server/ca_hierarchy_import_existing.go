// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"fmt"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

func (h *caHierarchyService) claimCeremonyCASigner(ctx context.Context, tenantID, ceremonyID, purpose, handle string) error {
	if err := h.requirePendingCeremonyQuorum(ctx, tenantID, ceremonyID, purpose); err != nil {
		return caHierarchyConflict(err)
	}
	return caHierarchyConflict(h.store.ClaimCASignerHandle(ctx, tenantID, ceremonyID, handle))
}

func existingCAPurpose(chainDER [][]byte, signerHandle string, spec api.CASpec, parentID string) (string, error) {
	if signerHandle == "" {
		return "", fmt.Errorf("%w: signer_handle is required for import_existing_ca", api.ErrCAHierarchyInvalid)
	}
	rootPurpose, err := hierarchyPurpose("create_root", "", spec)
	if err != nil {
		return "", err
	}
	purpose := "import-existing-ca:" + signerHandle + ":" + crypto.SHA256Hex(flattenDERChain(chainDER)) + ":" + rootPurpose
	if parentID != "" {
		purpose += ":parent:" + parentID
	}
	return purpose, nil
}

func preparedExistingCAPurpose(issuerChainDER [][]byte, spec api.CASpec, parentID string) (string, error) {
	if len(issuerChainDER) == 0 {
		return "", fmt.Errorf("%w: issuer certificate chain is required", api.ErrCAHierarchyInvalid)
	}
	if _, err := crypto.VerifyExistingCAIssuerChain(issuerChainDER); err != nil {
		return "", fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
	}
	profilePurpose, err := hierarchyPurpose("create_root", "", spec)
	if err != nil {
		return "", err
	}
	purpose := "prepare-existing-ca:" + crypto.SHA256Hex(flattenDERChain(issuerChainDER)) + ":" + profilePurpose
	if parentID != "" {
		purpose += ":parent:" + parentID
	}
	return purpose, nil
}

func validatePreparedCAIssuerParent(parent store.CAAuthority, issuerChainDER [][]byte) error {
	if parent.Status != "active" {
		return fmt.Errorf("%w: selected issuer authority is not active", api.ErrCAHierarchyConflict)
	}
	if len(issuerChainDER) == 0 {
		return fmt.Errorf("%w: issuer chain is empty", api.ErrCAHierarchyInvalid)
	}
	parentDER, err := firstCertDER(parent.CertificatePEM)
	if err != nil {
		return err
	}
	if !bytes.Equal(parentDER, issuerChainDER[0]) {
		return fmt.Errorf("%w: selected issuer authority differs from reviewed issuer certificate", api.ErrCAHierarchyInvalid)
	}
	return nil
}

// validateImportedCAParent binds a reviewed parent to the next certificate in
// the supplied chain. A shared subject name or matching key identifier is not
// enough: the operator selected this exact registered certificate and tenant.
func validateImportedCAParent(parent store.CAAuthority, chainDER [][]byte) error {
	if len(chainDER) < 2 {
		return fmt.Errorf("%w: imported root cannot have a parent authority", api.ErrCAHierarchyInvalid)
	}
	if parent.Status != "active" {
		return fmt.Errorf("%w: selected parent authority is not active", api.ErrCAHierarchyConflict)
	}
	parentDER, err := firstCertDER(parent.CertificatePEM)
	if err != nil {
		return err
	}
	if !bytes.Equal(parentDER, chainDER[1]) {
		return fmt.Errorf("%w: selected parent certificate differs from the next certificate in the imported chain", api.ErrCAHierarchyInvalid)
	}
	return nil
}
