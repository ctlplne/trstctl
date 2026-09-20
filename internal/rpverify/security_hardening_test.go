// SPDX-License-Identifier: BUSL-1.1

package rpverify_test

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/rpverify"
)

// TestSec_InclusionFailsClosedWithoutLogKey locks in the security-review HIGH fix: the
// primary verifier's inclusion check fails CLOSED when inclusion is required but no
// trusted transparency-log key is configured. Previously the STH signature was skipped
// when the key was empty, so an attacker-supplied (unsigned) tree head with
// RootHash = leafHash(their leaf) passed inclusion.
func TestSec_InclusionFailsClosedWithoutLogKey(t *testing.T) {
	sc := mustChain(t)
	ev, _ := buildInclusion(t, sc) // a real, valid proof — but we withhold the log key
	in := input(sc)
	in.Inclusion = ev
	if _, err := rpverify.Verify(in, newMemEpoch(), rpverify.Options{ExpectedTenant: tenant, RequireInclusion: true}); !errors.Is(err, rpverify.ErrInclusionInvalid) {
		t.Fatalf("inclusion required but no log key: got %v, want ErrInclusionInvalid (fail closed)", err)
	}
}

// TestSec_RecoveryEpochReplayRejected locks in the security-review MEDIUM fix: a
// recovery record cannot be replayed to roll an identity's posture back to a superseded
// epoch — with an EpochStore, a recovery whose epoch is not greater than last-accepted
// is refused.
func TestSec_RecoveryEpochReplayRejected(t *testing.T) {
	rec, root, logPub := craftRecoveryRecord(t, 2, 2, true) // epoch 2
	store := newMemEpoch()
	opts := rpverify.RecoveryOptions{TrustRootPubDER: root, MinThreshold: 2, STHVerifyKeyDER: logPub, EpochStore: store}

	// First acceptance advances the store to epoch 2.
	if err := rpverify.VerifyRecovery(rec, opts); err != nil {
		t.Fatalf("first recovery acceptance: %v", err)
	}
	// Replaying the same (now-superseded) recovery record is refused.
	if err := rpverify.VerifyRecovery(rec, opts); !errors.Is(err, rpverify.ErrStaleRecoveryEpoch) {
		t.Fatalf("recovery replay: got %v, want ErrStaleRecoveryEpoch", err)
	}
}
