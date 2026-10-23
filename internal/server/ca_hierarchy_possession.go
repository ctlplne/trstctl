// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
)

// signerPossession proves that a signer-held CA key signs for the public key
// the certificate names (eMudhra, Part 4) and says how it was established. A
// key whose algorithm has no possession check is recorded as not proven.
func signerPossession(signer crypto.DigestSigner) (string, error) {
	err := crypto.ProvePossession(signer, signer.Public())
	switch {
	case errors.Is(err, crypto.ErrPossessionUnsupported):
		return api.CAPossessionNotProven, nil
	case err != nil:
		return "", fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
	default:
		return api.CAPossessionSignerChallenge, nil
	}
}

// offlineRootPossession checks an offline root's optional possession
// signature over its import ceremony's challenge. Without one, the import
// records that possession was not proven; a signature that is given must
// verify, and is checked before the ceremony is consumed.
func offlineRootPossession(rootDER []byte, req api.CAImportOfflineRootRequest) (string, error) {
	encoded := strings.TrimSpace(req.PossessionSignature)
	if encoded == "" {
		return api.CAPossessionNotProven, nil
	}
	signature, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("%w: possession_signature is not standard base64: %v", api.ErrCAHierarchyInvalid, err)
	}
	if err := crypto.VerifyOfflinePossession(rootDER, req.CeremonyID, signature); err != nil {
		if errors.Is(err, crypto.ErrPossessionUnsupported) {
			return "", fmt.Errorf("%w: trstctl cannot check a possession signature for this root's key algorithm; omit possession_signature to record that possession was not proven", api.ErrCAHierarchyInvalid)
		}
		return "", fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
	}
	return api.CAPossessionOfflineSignature, nil
}

func withPossession(authority api.CAAuthority, possession string) api.CAAuthority {
	authority.PossessionProof = possession
	return authority
}
