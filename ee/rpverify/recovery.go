// SPDX-License-Identifier: LicenseRef-trstctl-EE

package rpverify

import (
	"errors"
	"fmt"

	"trstctl.com/trstctl/ee/succession/recovery"
)

// Recovery-record relying-party errors.
var (
	ErrRecoveryThresholdTooLow   = errors.New("rpverify: recovery approval threshold below the relying party's minimum")
	ErrRecoveryInclusionRequired = errors.New("rpverify: recovery record requires a transparency-log inclusion proof")
	ErrRecoveryOutOfBand         = errors.New("rpverify: recovery record requires out-of-band confirmation")
)

// RecoveryOptions is the relying party's strictly stronger policy for a recovery
// record (the only record type that omits the predecessor signature): an elevated
// approval threshold, an unconditional inclusion proof, and an optional out-of-band
// confirmation hook.
type RecoveryOptions struct {
	TrustRootPubDER  []byte
	MinThreshold     int                      // reject a recovery whose authorization threshold is below this
	VerifyInclusion  func(proof []byte) error // mandatory: nil or a missing proof fails
	ConfirmOutOfBand func() error             // optional: when set, must succeed
}

// VerifyRecovery applies the relying party's stricter recovery policy. It first
// checks the record's integrity (successor possession + the m-of-n authorization
// rooted in the tenant trust root, via recovery.VerifyRecord), then enforces the
// elevated approval threshold, the unconditional transparency-log inclusion proof,
// and any required out-of-band confirmation. A recovery record is accepted only when
// all hold — recovery bypasses none of the ledger, epoch, or audit disciplines.
func VerifyRecovery(rec recovery.RecoveryRecord, opts RecoveryOptions) error {
	if err := recovery.VerifyRecord(rec, opts.TrustRootPubDER); err != nil {
		return err
	}
	if opts.MinThreshold > 0 && rec.Authorization.Threshold < opts.MinThreshold {
		return fmt.Errorf("%w: %d < %d", ErrRecoveryThresholdTooLow, rec.Authorization.Threshold, opts.MinThreshold)
	}
	if len(rec.InclusionProof) == 0 || opts.VerifyInclusion == nil {
		return ErrRecoveryInclusionRequired
	}
	if err := opts.VerifyInclusion(rec.InclusionProof); err != nil {
		return fmt.Errorf("rpverify: recovery inclusion: %w", err)
	}
	if opts.ConfirmOutOfBand != nil {
		if err := opts.ConfirmOutOfBand(); err != nil {
			return fmt.Errorf("%w: %v", ErrRecoveryOutOfBand, err)
		}
	}
	return nil
}
