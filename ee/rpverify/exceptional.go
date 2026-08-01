// SPDX-License-Identifier: LicenseRef-trstctl-EE

package rpverify

import (
	"errors"
	"fmt"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/translog"
)

// ErrCeremonyRejected is returned when the relying party's policy rejects a ceremony
// or emergency record (PCAS-claim-37).
var ErrCeremonyRejected = errors.New("rpverify: ceremony/emergency record rejected by relying-party policy")

// ExceptionalPolicy is the relying party's stricter policy for exceptional records
// (revocation / ceremony / emergency, PCAS-claims-36, 37). Revocation tombstones are
// accepted with mandatory inclusion + a type-binding attestation; ceremony/emergency
// records are either rejected outright or accepted with an elevated confirmation.
type ExceptionalPolicy struct {
	SignerRoster map[string][]byte // verifies the type-binding signer attestation
	// STHVerifyKeyDER is the transparency log's public key. The mandatory inclusion
	// proof carried in the record is verified against it with the REAL RFC-6962 Merkle
	// verifier (translog.VerifyEncodedInclusion): the record's commitment must be the
	// proven leaf under a head this key signed. Empty => inclusion fails closed
	// (ErrProofUntrusted): a relying party without a trusted log key cannot soundly
	// verify inclusion, and there is no injected-closure escape hatch (INT-18).
	STHVerifyKeyDER []byte
	RejectCeremony  bool // reject ceremony/emergency records outright
	// ElevatedConfirm, when set and RejectCeremony is false, must succeed to accept a
	// ceremony/emergency record (accept-with-elevated-requirements).
	ElevatedConfirm func(rec succession.SuccessionRecord) error
}

// VerifyExceptionalRecord applies the relying party's stricter exceptional-record
// policy. Every exceptional record needs the base dual-attestation, its type-binding
// signer attestation, and a mandatory inclusion proof (via succession.VerifyExceptional).
// A ceremony/emergency record is then rejected or elevated per policy. Ordinary records
// pass through unchanged.
func VerifyExceptionalRecord(rec succession.SuccessionRecord, p ExceptionalPolicy) error {
	// The inclusion check is the REAL translog verifier, constructed here (not injected
	// by the caller): the proven leaf must be this record's commitment, under a head
	// signed by the trusted log key. A missing proof or key fails closed.
	realInclusion := func(proofBytes []byte) error {
		leaf, err := succession.Commit(rec.Fields)
		if err != nil {
			return err
		}
		return translog.VerifyEncodedInclusion(leaf, proofBytes, p.STHVerifyKeyDER)
	}
	if err := succession.VerifyExceptional(rec, p.SignerRoster, realInclusion); err != nil {
		return err
	}
	switch rec.RecordType {
	case succession.RecCeremony, succession.RecEmergency:
		if p.RejectCeremony {
			return ErrCeremonyRejected
		}
		if p.ElevatedConfirm != nil {
			if err := p.ElevatedConfirm(rec); err != nil {
				return fmt.Errorf("%w: %v", ErrCeremonyRejected, err)
			}
		}
	}
	return nil
}
