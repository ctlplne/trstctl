// SPDX-License-Identifier: BUSL-1.1

package deviceattest

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	trstcrypto "trstctl.com/trstctl/internal/crypto"
)

// EdgeTPMAttestationAlgorithms are the COSE algorithms accepted from edge
// TPMs: ES256 (-7) and RS256 (-257), the WebAuthn TPM formats this package
// verifies.
var EdgeTPMAttestationAlgorithms = []int64{-7, -257}

var (
	// ErrEdgeAttestationRefused marks an edge credential that does not vouch
	// for the request: missing, unverifiable, for another key, or not
	// device-bound.
	ErrEdgeAttestationRefused = errors.New("edge attestation refused")
	// ErrEdgeCSRInvalid marks an edge CA CSR whose public key cannot be read.
	ErrEdgeCSRInvalid = errors.New("edge CSR invalid")
)

// EdgeAttestationError is a refusal with its reason, worded for the operator.
type EdgeAttestationError struct {
	kind error
	msg  string
}

func (e *EdgeAttestationError) Error() string { return e.msg }
func (e *EdgeAttestationError) Unwrap() error { return e.kind }

// EdgeCAAttestation is a verified edge host attestation for one CSR.
type EdgeCAAttestation struct {
	Attested     TPMDeviceAttestationResult
	CSRKeySHA256 []byte
}

// VerifyEdgeCAAttestation checks a host's TPM credential for an edge CA CSR. It
// must verify against the segment's pinned roots over the challenge that binds
// tenant, segment and this CSR. In the tpm2 custody lane the attested key must
// BE the CSR's key and be device-bound; the other lanes authenticate the host
// and the request only. A mint and a renewal both pass through here, so a
// renewal is held to exactly the mint's gate.
func VerifyEdgeCAAttestation(credentialJSON []byte, tenantID, segmentID string, csrDER []byte, rootsPEM [][]byte, provider string, now time.Time) (EdgeCAAttestation, error) {
	if len(credentialJSON) == 0 {
		return EdgeCAAttestation{}, &EdgeAttestationError{kind: ErrEdgeAttestationRefused, msg: "an un-attested host cannot receive a delegated CA"}
	}
	challenge := trstcrypto.EdgeAttestationChallenge(tenantID, segmentID, csrDER)
	attested, err := ParseAndVerifyTPMDeviceAttestation(credentialJSON, challenge, rootsPEM, EdgeTPMAttestationAlgorithms, now)
	if err != nil {
		return EdgeCAAttestation{}, &EdgeAttestationError{kind: ErrEdgeAttestationRefused, msg: fmt.Sprintf("attestation: %v", err)}
	}
	csrKey, err := CSRPublicKeySHA256(csrDER)
	if err != nil {
		return EdgeCAAttestation{}, &EdgeAttestationError{kind: ErrEdgeCSRInvalid, msg: fmt.Sprintf("csr: %v", err)}
	}
	if provider == "tpm2" {
		if len(attested.PublicKeySHA256) != len(csrKey) || subtle.ConstantTimeCompare(attested.PublicKeySHA256, csrKey) != 1 {
			return EdgeCAAttestation{}, &EdgeAttestationError{kind: ErrEdgeAttestationRefused,
				msg: "the attested key is not the CSR's key; a TPM vouching for a different key vouches for nothing here"}
		}
		if !attested.DeviceBound {
			return EdgeCAAttestation{}, &EdgeAttestationError{kind: ErrEdgeAttestationRefused,
				msg: "the attested TPM key could leave the TPM (fixedTPM, fixedParent and sensitiveDataOrigin are not all set), so it is not device-bound custody"}
		}
	}
	return EdgeCAAttestation{Attested: attested, CSRKeySHA256: bytes.Clone(csrKey)}, nil
}
