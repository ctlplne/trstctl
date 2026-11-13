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
//
// A175-L3: a token that attests in card-verifiable certificates (a
// SmartCard-HSM, a Nitrokey HSM 2) sends its authenticated request and its
// device and device issuer CA certificates instead; they must chain to a CV
// root the segment pinned and attest exactly the CSR's key.
func edgeTokenCustody(provider string, custody edgeCustodyEvidence, policy store.EdgeSegmentPolicy, chain [][]byte, cvc *api.EdgeSmartCardHSMAttestation, csrDER []byte, now time.Time) (*deviceattest.TokenAttestation, edgeCustodyEvidence, error) {
	if len(chain) == 0 && cvc == nil {
		if provider == "pkcs11" && policy.RequirePKCS11Attestation {
			return nil, custody, fmt.Errorf("%w: segment %s requires the token's attestation of a PKCS#11 key (pkcs11_attestation_chain_der or smartcard_hsm_attestation)",
				api.ErrEdgeDelegationRefused, policy.SegmentID)
		}
		return nil, custody, nil
	}
	if provider != "pkcs11" {
		return nil, custody, fmt.Errorf("%w: a token attestation applies only to the pkcs11 key provider", api.ErrEdgeDelegationInvalid)
	}
	if len(chain) > 0 && cvc != nil {
		return nil, custody, fmt.Errorf("%w: send the token's attestation chain or its SmartCard-HSM attestation, not both", api.ErrEdgeDelegationInvalid)
	}
	roots := make([][]byte, 0, len(policy.PKCS11AttestationRootsPEM))
	for _, root := range policy.PKCS11AttestationRootsPEM {
		roots = append(roots, []byte(root))
	}
	var attested deviceattest.TokenAttestation
	var err error
	if cvc != nil {
		attested, err = deviceattest.VerifySmartCardHSMKeyAttestation(deviceattest.SmartCardHSMAttestation{
			AuthenticatedRequest: cvc.AuthenticatedRequest, DeviceCVC: cvc.DeviceCVC, DICACVC: cvc.DICACVC,
		}, roots, csrDER, now)
	} else {
		attested, err = deviceattest.VerifyPKCS11TokenAttestation(chain, roots, csrDER, now)
	}
	if err != nil {
		return nil, custody, edgeAttestationRefusal(err)
	}
	custody.assurance = "hardware_key_attested"
	return &attested, custody, nil
}

// validateEdgeTokenRoots checks a segment's pinned PKCS#11 token roots: an
// X.509 PEM certificate, or (A175-L3) a "CV CERTIFICATE" PEM block holding a
// self-signed card-verifiable root with its domain parameters.
func validateEdgeTokenRoots(field string, roots []string) error {
	for i, root := range roots {
		block, _ := pem.Decode([]byte(root))
		if block != nil && block.Type == deviceattest.PEMTypeCVCertificate {
			if n, err := deviceattest.ParsePinnedCVCertificateRoots([][]byte{[]byte(root)}); err != nil || n != 1 {
				return fmt.Errorf("%w: %s %d is not a self-signed CV certificate root: %v", api.ErrEdgeDelegationInvalid, field, i, err)
			}
			continue
		}
		if err := validateEdgePEMRoots(field, []string{root}); err != nil {
			return fmt.Errorf("%w: %s %d is not a PEM certificate or CV certificate", api.ErrEdgeDelegationInvalid, field, i)
		}
	}
	return nil
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
