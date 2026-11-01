// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/pem"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// edgeTokenCustody applies a PKCS#11 token's own attestation to a mint (A175).
// The host TPM credential authenticates the host and the request; it cannot
// vouch for a key that lives in a separate token. When the request carries the
// token's attestation chain, it must reach a vendor root the segment pinned
// and certify exactly the CSR's key; then, and only then, the PKCS#11 key is
// recorded as hardware-attested. A segment that requires token attestation
// refuses a PKCS#11 request without it.
func edgeTokenCustody(provider string, custody edgeCustodyEvidence, policy store.EdgeSegmentPolicy, chain [][]byte, csrDER []byte, now time.Time) (*deviceattest.TokenAttestation, edgeCustodyEvidence, error) {
	if len(chain) == 0 {
		if provider == "pkcs11" && policy.RequirePKCS11Attestation {
			return nil, custody, fmt.Errorf("%w: segment %s requires the token's attestation of a PKCS#11 key (pkcs11_attestation_chain_der)",
				api.ErrEdgeDelegationRefused, policy.SegmentID)
		}
		return nil, custody, nil
	}
	if provider != "pkcs11" {
		return nil, custody, fmt.Errorf("%w: a token attestation chain applies only to the pkcs11 key provider", api.ErrEdgeDelegationInvalid)
	}
	roots := make([][]byte, 0, len(policy.PKCS11AttestationRootsPEM))
	for _, root := range policy.PKCS11AttestationRootsPEM {
		roots = append(roots, []byte(root))
	}
	attested, err := deviceattest.VerifyPKCS11TokenAttestation(chain, roots, csrDER, now)
	if err != nil {
		return nil, custody, edgeAttestationRefusal(err)
	}
	custody.assurance = "hardware_key_attested"
	return &attested, custody, nil
}

// validateEdgePEMRoots checks every pinned root is one PEM certificate.
func validateEdgePEMRoots(field string, roots []string) error {
	for i, root := range roots {
		block, _ := pem.Decode([]byte(root))
		if block == nil || block.Type != "CERTIFICATE" {
			return fmt.Errorf("%w: %s %d is not a PEM certificate", api.ErrEdgeDelegationInvalid, field, i)
		}
		if _, err := certinfo.Inspect(block.Bytes); err != nil {
			return fmt.Errorf("%w: %s %d: %v", api.ErrEdgeDelegationInvalid, field, i, err)
		}
	}
	return nil
}

// edgeTokenAttestationView is the recorded token attestation, if any.
func edgeTokenAttestationView(d store.EdgeDelegation) *api.EdgeTokenAttestation {
	if d.TokenAttestationRootSHA256 == "" {
		return nil
	}
	return &api.EdgeTokenAttestation{
		RootSHA256: d.TokenAttestationRootSHA256, Serial: d.TokenAttestationSerial,
		PINPolicy: d.TokenAttestationPINPolicy, TouchPolicy: d.TokenAttestationTouchPolicy,
	}
}

// edgeTokenAttestationRecord is the event's record of a verified token
// attestation.
func edgeTokenAttestationRecord(t *deviceattest.TokenAttestation) *projections.EdgeTokenAttestation {
	if t == nil {
		return nil
	}
	return &projections.EdgeTokenAttestation{RootSHA256: t.RootSHA256, Serial: t.Serial, PINPolicy: t.PINPolicy, TouchPolicy: t.TouchPolicy}
}
