// SPDX-License-Identifier: LicenseRef-trstctl-EE

package rpverify

import (
	"bytes"
	"errors"
	"fmt"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/succession/attest"
	"trstctl.com/trstctl/internal/crypto"
)

// Attested-succession relying-party errors.
var (
	ErrAttestationBelowMin = errors.New("rpverify: record's custody attestation class is below the minimum for its algorithm class")
	ErrAttestationEvidence = errors.New("rpverify: record's bound attestation evidence digest does not match the published evidence")
)

// AttestedPolicy mirrors the signer's custody class gate (PCAS-claim-35, FIG. 9): for a
// gated algorithm class the relying party requires the record to carry a signer-attested
// custody attestation of at least the minimum class.
type AttestedPolicy struct {
	SignerRoster map[string][]byte             // verifies the attestation that binds the evidence
	MinByClass   map[string]attest.Class       // algorithm-class key -> minimum custody class
	AlgClass     func(crypto.Algorithm) string // successor algorithm -> algorithm-class key
}

// VerifyAttestedRecord mirrors the signer's refusal: after the base dual-attestation,
// for a gated algorithm class it requires a verifying signer attestation binding the
// custody evidence AND an attestation type of at least the minimum class. Un-gated
// classes are unaffected.
func VerifyAttestedRecord(rec succession.SuccessionRecord, p AttestedPolicy) error {
	if err := succession.VerifyRecord(rec); err != nil {
		return err
	}
	min := attest.ClassNone
	if p.AlgClass != nil && p.MinByClass != nil {
		min = p.MinByClass[p.AlgClass(rec.Fields.SuccessorAlg)]
	}
	if min <= attest.ClassNone {
		return nil // un-gated algorithm class: unaffected
	}
	// Gated: the record must carry a signer-attested attestation of sufficient class.
	// The signer attestation binds AttestationType + AttestationEvidenceDigest, so a
	// forged type/class cannot pass.
	if _, err := succession.VerifyAttestation(p.SignerRoster, rec); err != nil {
		return fmt.Errorf("%w: %v", ErrAttestationBelowMin, err)
	}
	if attest.ClassOfType(rec.AttestationType) < min {
		return fmt.Errorf("%w: type %q (class %d) < min %d", ErrAttestationBelowMin, rec.AttestationType, attest.ClassOfType(rec.AttestationType), min)
	}
	return nil
}

// VerifyEvidenceDigest checks that a record's bound evidence digest matches the
// published attestation evidence (PCAS-claim-35: the custody evidence that gated the
// succession is verifiable from the published record + evidence).
func VerifyEvidenceDigest(rec succession.SuccessionRecord, evidence attest.Evidence) error {
	if !bytes.Equal(rec.AttestationEvidenceDigest, attest.Digest(evidence)) {
		return ErrAttestationEvidence
	}
	return nil
}
