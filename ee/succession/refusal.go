// SPDX-License-Identifier: LicenseRef-trstctl-EE

package succession

import (
	"bytes"
	"errors"

	"trstctl.com/trstctl/internal/crypto"
)

// refusal.go carries the signed refusal artifact a signer emits when it REFUSES a
// mint (PCAS-claim-41, dependent of PCAS-claim-17). A refusal is as attributable as an
// issuance: the signer signs, inside the boundary, an artifact identifying the
// refused request and the violated constraint, which is recorded as an audit/ledger
// event. This is part of the INV-13 attribution story — every signer OUTCOME, not
// just every issuance, is evidenced.

const refusalDomain = "trstctl/pcas/refusal/v1"

// Refusal constraint identifiers (the violated invariant a refusal cites).
const (
	RefusalEpoch       = "epoch_monotonicity"
	RefusalStrength    = "strength_ordering"
	RefusalPolicy      = "policy"
	RefusalDualControl = "dual_control"
	RefusalTenant      = "tenant"
)

// ErrRefusalArtifact is returned when a refusal artifact does not verify.
var ErrRefusalArtifact = errors.New("succession: refusal artifact invalid")

// RefusalArtifact is the signer's signed evidence of a refused mint (PCAS-claim-41): the
// refused request (by params digest), the violated constraint, the signer, and when.
type RefusalArtifact struct {
	SignerID      string `json:"signer_id"`
	IdentityID    string `json:"identity_id"`
	TenantID      string `json:"tenant_id"`
	RequestDigest []byte `json:"request_digest"`
	Constraint    string `json:"constraint"`
	IssuedAt      int64  `json:"issued_at"`
	Signature     []byte `json:"sig"`
}

func refusalMessage(a RefusalArtifact) []byte {
	var b bytes.Buffer
	writeField(&b, []byte(refusalDomain))
	writeField(&b, []byte(a.SignerID))
	writeField(&b, []byte(a.IdentityID))
	writeField(&b, []byte(a.TenantID))
	writeField(&b, a.RequestDigest)
	writeField(&b, []byte(a.Constraint))
	writeUint(&b, uint64(a.IssuedAt))
	return b.Bytes()
}

// SignRefusal signs a refusal artifact with the signer's attestation key (called
// inside the signer boundary). The Signature field of art is ignored on input.
func SignRefusal(attestSigner crypto.Signer, art RefusalArtifact) (RefusalArtifact, error) {
	art.Signature = nil
	sig, err := attestSigner.Sign(refusalMessage(art), crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return RefusalArtifact{}, err
	}
	art.Signature = sig
	return art, nil
}

// VerifyRefusal verifies a refusal artifact against the signer's attestation key.
func VerifyRefusal(signerPubDER []byte, art RefusalArtifact) error {
	unsigned := art
	unsigned.Signature = nil
	if len(art.Signature) == 0 || crypto.VerifyMessage(signerPubDER, refusalMessage(unsigned), art.Signature) != nil {
		return ErrRefusalArtifact
	}
	return nil
}
