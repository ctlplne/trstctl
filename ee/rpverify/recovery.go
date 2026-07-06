// SPDX-License-Identifier: LicenseRef-trstctl-EE

package rpverify

import (
	"errors"
	"fmt"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/succession/recovery"
	"trstctl.com/trstctl/ee/translog"
)

// Recovery-record relying-party errors.
var (
	ErrRecoveryThresholdTooLow   = errors.New("rpverify: recovery approval threshold below the relying party's minimum")
	ErrRecoveryInclusionRequired = errors.New("rpverify: recovery record requires a transparency-log inclusion proof")
	ErrRecoveryOutOfBand         = errors.New("rpverify: recovery record requires out-of-band confirmation")
	ErrStaleRecoveryEpoch        = errors.New("rpverify: recovery record epoch is not greater than the last-accepted epoch (replay)")
)

// RecoveryOptions is the relying party's strictly stronger policy for a recovery
// record (the only record type that omits the predecessor signature): an elevated
// approval threshold, an unconditional inclusion proof, and an optional out-of-band
// confirmation hook.
type RecoveryOptions struct {
	TrustRootPubDER []byte
	MinThreshold    int // reject a recovery whose authorization threshold is below this
	// STHVerifyKeyDER is the transparency log's public key. The mandatory inclusion
	// proof is verified with the REAL RFC-6962 Merkle verifier: the recovery record's
	// commitment must be the proven leaf under a head this key signed. Empty => the
	// inclusion requirement fails closed (no injected-closure escape hatch, INT-18).
	STHVerifyKeyDER []byte
	// EpochStore enforces recovery-record epoch monotonicity across restarts, keyed by
	// identity — the same discipline Verify applies to ordinary chains. A recovery
	// record is a distinct type that never flows through VerifyChain, so without this a
	// previously-valid recovery artifact could be replayed to roll an identity's posture
	// back to a superseded epoch. A recovery whose epoch is not strictly greater than the
	// last accepted value is rejected; on success the store is advanced. Nil disables the
	// discipline (single-shot check).
	EpochStore       EpochStore
	ConfirmOutOfBand func() error // optional: when set, must succeed
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
	if len(rec.InclusionProof) == 0 {
		return ErrRecoveryInclusionRequired
	}
	// Real RFC-6962 inclusion: the recovery record's commitment must be the proven leaf
	// under a head signed by the trusted log key. No injected closure can stand in.
	leaf, err := succession.Commit(rec.Fields)
	if err != nil {
		return err
	}
	if err := translog.VerifyEncodedInclusion(leaf, rec.InclusionProof, opts.STHVerifyKeyDER); err != nil {
		return fmt.Errorf("%w: %v", ErrRecoveryInclusionRequired, err)
	}
	// Epoch-replay defense: a recovery record must strictly advance the identity's
	// last-accepted epoch, so a captured, superseded recovery artifact cannot be
	// replayed to downgrade posture.
	if opts.EpochStore != nil {
		identity := rec.Fields.IdentityID
		last, ok, err := opts.EpochStore.LastAccepted(identity)
		if err != nil {
			return err
		}
		if ok && rec.Fields.Epoch <= last {
			return fmt.Errorf("%w: recovery epoch %d <= last-accepted %d", ErrStaleRecoveryEpoch, rec.Fields.Epoch, last)
		}
	}
	if opts.ConfirmOutOfBand != nil {
		if err := opts.ConfirmOutOfBand(); err != nil {
			return fmt.Errorf("%w: %v", ErrRecoveryOutOfBand, err)
		}
	}
	if opts.EpochStore != nil {
		if err := opts.EpochStore.SetLastAccepted(rec.Fields.IdentityID, rec.Fields.Epoch); err != nil {
			return err
		}
	}
	return nil
}
