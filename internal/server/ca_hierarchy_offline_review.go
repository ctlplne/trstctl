// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"fmt"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// Preview and ceremony start share these public-only checks with execution so
// a ready review cannot send custodians an unusable certificate package.
func validateOfflineCeremonyPackage(authority store.CAAuthority, req api.CACeremonyStartRequest) error {
	switch req.Operation {
	case "import_offline_cross_sign":
		targetDER, _, err := singleCertificatePEM(req.TargetCertificatePEM)
		if err != nil {
			return err
		}
		crossDER, _, err := singleCertificatePEM(req.CrossCertificatePEM)
		if err != nil {
			return err
		}
		_, err = verifyOfflineCrossSignPackage(authority, targetDER, crossDER)
		return err
	case "rekey_offline_root":
		successorDER, _, err := singleCertificatePEM(req.CertificatePEM)
		if err != nil {
			return err
		}
		newByPreviousDER, _, err := singleCertificatePEM(req.CrossCertificatePEM)
		if err != nil {
			return err
		}
		previousByNewDER, _, err := singleCertificatePEM(req.ReverseCrossCertificatePEM)
		if err != nil {
			return err
		}
		if _, err := crypto.VerifyImportedOfflineRoot(successorDER, cryptoProfile(req.Spec)); err != nil {
			return fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
		}
		return verifyOfflineRootRekeyPackage(authority, successorDER, newByPreviousDER, previousByNewDER)
	default:
		return nil
	}
}

func verifyOfflineCrossSignPackage(authority store.CAAuthority, targetDER, crossDER []byte) ([]byte, error) {
	if authority.Kind != "root" || authority.SignerHandle != "" || authority.Status != "active" {
		return nil, fmt.Errorf("%w: issuer must be an active imported offline root", api.ErrCAHierarchyInvalid)
	}
	issuerDER, err := firstCertDER(authority.CertificatePEM)
	if err != nil {
		return nil, err
	}
	if err := crypto.VerifyCrossSignedCA(issuerDER, targetDER, crossDER); err != nil {
		return nil, fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
	}
	return issuerDER, nil
}

func verifyOfflineRootRekeyPackage(predecessor store.CAAuthority, successorDER, newByPreviousDER, previousByNewDER []byte) error {
	if predecessor.Kind != "root" || predecessor.SignerHandle != "" || predecessor.Status != "active" {
		return fmt.Errorf("%w: predecessor must be an active imported offline root", api.ErrCAHierarchyInvalid)
	}
	predecessorDER, err := firstCertDER(predecessor.CertificatePEM)
	if err != nil {
		return err
	}
	if err := crypto.VerifyCrossSignedCA(predecessorDER, successorDER, newByPreviousDER); err != nil {
		return fmt.Errorf("%w: new-by-previous cross-certificate: %v", api.ErrCAHierarchyInvalid, err)
	}
	if err := crypto.VerifyCrossSignedCA(successorDER, predecessorDER, previousByNewDER); err != nil {
		return fmt.Errorf("%w: previous-by-new cross-certificate: %v", api.ErrCAHierarchyInvalid, err)
	}
	return nil
}
