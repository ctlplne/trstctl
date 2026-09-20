// SPDX-License-Identifier: BUSL-1.1

package succession

import (
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
)

// exceptional.go carries the exceptional-but-chained succession records (PCAS-claims-36,
// 37; establishes the revocation/ceremony limbs of INV-15). The point is that
// exceptional paths stay ON the chain: they are minted as distinct record TYPES at
// the next algorithm-epoch, they carry a mandatory transparency-log inclusion proof,
// and their type is bound by the signer attestation — so no exceptional path bypasses
// the ledger, the epoch discipline, or auditability.
//
//   - Revocation-as-succession (PCAS-claim-36): a tombstone record at the next epoch. A
//     relying party learns revocation from ordinary offline chain verification — the
//     chain itself is the revocation status; there is no separate revocation query.
//   - Ceremony / emergency records (PCAS-claim-37): a PCAS-claim-17 break-glass downgrade, or a
//     control-plane-unavailable emergency issuance, minted as a distinct chained type
//     with mandatory inclusion and stricter relying-party policy.

// Exceptional-record errors.
var (
	ErrExceptionalInclusion   = errors.New("succession: exceptional record requires a transparency-log inclusion proof")
	ErrExceptionalAttestation = errors.New("succession: exceptional record requires a signer attestation binding its type")
)

// IsExceptional reports whether a record is a non-ordinary (exceptional) type.
func IsExceptional(rec SuccessionRecord) bool { return rec.RecordType != RecOrdinary }

// BuildRevocation mints a revocation tombstone at the next epoch (PCAS-claim-36): the
// current key signs a record marking the identity revoked. The successor is the key
// itself (a self-succession tombstone), so the record is a valid dual-attested chain
// record; RecordType marks it a tombstone and the signer attestation binds that type.
// The mandatory inclusion proof is attached after ledger inclusion.
func BuildRevocation(current crypto.Signer, deploymentScope, identityID, tenantID string, predecessorEpoch uint64, notBefore, notAfter int64, attest crypto.Signer, signerID string) (SuccessionRecord, error) {
	fields := CommitmentFields{
		DeploymentScope:  deploymentScope,
		IdentityID:       identityID,
		TenantID:         tenantID,
		PredecessorEpoch: predecessorEpoch,
		Epoch:            predecessorEpoch + 1,
		PredecessorAlg:   current.Algorithm(),
		PredecessorPub:   current.Public().DER,
		HashAlg:          HashAlgSHA256,
		NotBefore:        notBefore,
		NotAfter:         notAfter,
	}
	return BuildExceptional(fields, current, current, RecRevocation, attest, signerID)
}

// BuildExceptional mints a distinct chained record of type rt (ceremony / emergency /
// revocation) with a real successor, dual-signed and signer-attested. It sets the
// successor fields from the successor signer.
func BuildExceptional(fields CommitmentFields, predecessor, successor crypto.Signer, rt RecordType, attest crypto.Signer, signerID string) (SuccessionRecord, error) {
	if rt == RecOrdinary {
		return SuccessionRecord{}, fmt.Errorf("succession: BuildExceptional requires a non-ordinary record type")
	}
	fields.SuccessorAlg = successor.Algorithm()
	fields.SuccessorPub = successor.Public().DER
	// v2: bind the record TYPE in the commitment (INT-09), so base VerifyChain — not
	// only VerifyExceptional — rejects a flip that would hide a revocation by turning it
	// ordinary. RecordType is additionally bound by the signer attestation (below).
	fields.CommitmentVersion = 2
	fields.RecordType = rt
	commitment, err := Commit(fields)
	if err != nil {
		return SuccessionRecord{}, err
	}
	predSig, err := predecessor.Sign(commitment, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return SuccessionRecord{}, err
	}
	succSig, err := successor.Sign(commitment, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return SuccessionRecord{}, err
	}
	rec := SuccessionRecord{
		Fields:         fields,
		PredecessorAtt: predSig,
		Possession:     PossessionProof{Kind: ProofSuccessorSignature, Signature: succSig},
		RecordType:     rt,
	}
	att, err := Attest(attest, signerID, rec) // binds RecordType (tamper-evident)
	if err != nil {
		return SuccessionRecord{}, err
	}
	rec.SignerAttestation = att
	return rec, nil
}

// RequireInclusionForExceptional refuses to publish/finalize an exceptional record
// that lacks an inclusion proof — no exceptional path takes effect outside the ledger
// (PCAS-claim-37 / INV-15). Ordinary records are unaffected.
func RequireInclusionForExceptional(rec SuccessionRecord) error {
	if IsExceptional(rec) && len(rec.InclusionProof) == 0 {
		return ErrExceptionalInclusion
	}
	return nil
}

// VerifyExceptional verifies an exceptional record for a relying party: the base
// dual-attestation, the signer attestation binding its type (against roster), and the
// MANDATORY inclusion proof. Ordinary records pass with only the base verification.
func VerifyExceptional(rec SuccessionRecord, roster map[string][]byte, verifyInclusion func(proof []byte) error) error {
	if err := VerifyRecord(rec); err != nil {
		return err
	}
	if !IsExceptional(rec) {
		return nil
	}
	if _, err := VerifyAttestation(roster, rec); err != nil {
		return fmt.Errorf("%w: %v", ErrExceptionalAttestation, err)
	}
	if len(rec.InclusionProof) == 0 || verifyInclusion == nil {
		return ErrExceptionalInclusion
	}
	if err := verifyInclusion(rec.InclusionProof); err != nil {
		// Wrap both the domain sentinel and the underlying reason so a caller can match
		// either ErrExceptionalInclusion or the specific verifier error (e.g. the real
		// translog inclusion/STH errors).
		return fmt.Errorf("%w: %w", ErrExceptionalInclusion, err)
	}
	return nil
}

// Revoked reports whether a chain's head is a revocation tombstone (PCAS-claim-36): the
// chain itself is the revocation status. Establish the chain's authenticity with
// VerifyChain first.
func Revoked(chain []SuccessionRecord) bool {
	if len(chain) == 0 {
		return false
	}
	return chain[len(chain)-1].RecordType == RecRevocation
}
