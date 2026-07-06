// SPDX-License-Identifier: LicenseRef-trstctl-EE

package rpverify

import (
	"errors"
	"fmt"

	"trstctl.com/trstctl/ee/succession"
)

// ErrCeremonyRejected is returned when the relying party's policy rejects a ceremony
// or emergency record (claim 37).
var ErrCeremonyRejected = errors.New("rpverify: ceremony/emergency record rejected by relying-party policy")

// ExceptionalPolicy is the relying party's stricter policy for exceptional records
// (revocation / ceremony / emergency, claims 36, 37). Revocation tombstones are
// accepted with mandatory inclusion + a type-binding attestation; ceremony/emergency
// records are either rejected outright or accepted with an elevated confirmation.
type ExceptionalPolicy struct {
	SignerRoster    map[string][]byte        // verifies the type-binding signer attestation
	VerifyInclusion func(proof []byte) error // mandatory for exceptional records
	RejectCeremony  bool                     // reject ceremony/emergency records outright
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
	if err := succession.VerifyExceptional(rec, p.SignerRoster, p.VerifyInclusion); err != nil {
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
