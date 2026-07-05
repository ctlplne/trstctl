// SPDX-License-Identifier: LicenseRef-trstctl-EE

package translog

import (
	"bytes"
	"errors"
	"fmt"

	"trstctl.com/trstctl/ee/succession"
)

// MisissuanceProof is a self-contained, verifiable artifact evidencing that two
// dual-signed succession records for one identity conflict on the algorithm-epoch
// — two distinct records minted at the same epoch (an equivocation) — per claim
// 11. Because both records are dual-signed, the conflict is attributable from the
// records alone; where records carry a signer attestation (PCAS-20), that
// attestation names the minting signer.
type MisissuanceProof struct {
	RecordA succession.SuccessionRecord
	RecordB succession.SuccessionRecord
}

// ErrNoConflict is returned when two records do not evidence misissuance.
var ErrNoConflict = errors.New("translog: records do not evidence misissuance")

// EpochCollision reports whether a and b are two records for the same identity
// that share an algorithm-epoch but commit to different content (an equivocation:
// the signer minted two different successions at one epoch).
func EpochCollision(a, b succession.SuccessionRecord) bool {
	if a.Fields.IdentityID != b.Fields.IdentityID || a.Fields.Epoch != b.Fields.Epoch {
		return false
	}
	ca, errA := succession.Commit(a.Fields)
	cb, errB := succession.Commit(b.Fields)
	if errA != nil || errB != nil {
		return false
	}
	return !bytes.Equal(ca, cb)
}

// BuildMisissuanceProof constructs a misissuance proof from two records for the
// same identity that collide on epoch. Both records must be independently valid
// (dual-signed); a proof over an invalid record is refused.
func BuildMisissuanceProof(a, b succession.SuccessionRecord) (MisissuanceProof, error) {
	if err := succession.VerifyRecord(a); err != nil {
		return MisissuanceProof{}, fmt.Errorf("translog: record A invalid: %w", err)
	}
	if err := succession.VerifyRecord(b); err != nil {
		return MisissuanceProof{}, fmt.Errorf("translog: record B invalid: %w", err)
	}
	if !EpochCollision(a, b) {
		return MisissuanceProof{}, ErrNoConflict
	}
	return MisissuanceProof{RecordA: a, RecordB: b}, nil
}

// VerifyMisissuanceProof independently checks a misissuance proof: both records
// verify, and they collide on epoch. A third party can thus confirm misissuance
// from the artifact alone.
func VerifyMisissuanceProof(p MisissuanceProof) error {
	if err := succession.VerifyRecord(p.RecordA); err != nil {
		return fmt.Errorf("translog: record A invalid: %w", err)
	}
	if err := succession.VerifyRecord(p.RecordB); err != nil {
		return fmt.Errorf("translog: record B invalid: %w", err)
	}
	if !EpochCollision(p.RecordA, p.RecordB) {
		return ErrNoConflict
	}
	return nil
}
