// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"fmt"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

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
