// SPDX-License-Identifier: BUSL-1.1
package relay

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/winaccounts"
	"trstctl.com/trstctl/internal/hostaccounts"
)

// localRotationRecoverer answers as the native recoverer does, by sign-in.
type localRotationRecoverer struct {
	calls   int
	outcome string
}

func (r *localRotationRecoverer) Recover(ctx context.Context, b winaccounts.RotationBinding, generation string, old, next []byte, fence winaccounts.RotationFence) (winaccounts.RotationProof, error) {
	r.calls++
	if len(old) == 0 || !crypto.ValidAccountPassword(next, 24) {
		return winaccounts.RotationProof{}, winaccounts.ErrRotationInvalid
	}
	switch r.outcome {
	case "applied":
		p := winaccounts.RotationProof{Binding: b, GenerationID: generation, NewAuthenticated: true, OldRefused: true, ObservedAt: time.Now().UTC()}
		if e := fence.Complete(ctx, p); e != nil {
			return winaccounts.RotationProof{}, e
		}
		return p, nil
	case "not_applied":
		return winaccounts.RotationProof{}, winaccounts.ErrRotationNotApplied
	}
	return winaccounts.RotationProof{}, winaccounts.ErrRotationUncertain
}

// localRecoveryChannel is a current agent's channel: it can settle a begun
// generation by sign-in.
type localRecoveryChannel struct {
	*localRotationChannel
	recoverer *localRotationRecoverer
}

func (c *localRecoveryChannel) RecoverLocalAccountRotation(ctx context.Context, job int64, i hostaccounts.RotationIntent, old, next []byte) (winaccounts.RotationProof, error) {
	return c.store.RecoverLocalAccountRotationOnce(ctx, job, i.Native, i.RotationID, i.PredecessorGenerationID, old, next, c.recoverer)
}

// TestLocalAccountRotationRecoveryDeliverySettlesBySignInA268O1 is A268-O1 on
// the agent: the re-delivery of a generation whose outcome was lost redeems
// its two passwords once more and settles it by sign-in alone. It never
// resets the password again, and it reports with the agent's own outcomes:
// verified with proof when the new password signs in, not applied when the
// predecessor still does, uncertain when it still cannot tell. The redeemed
// material is gone before the report.
func TestLocalAccountRotationRecoveryDeliverySettlesBySignInA268O1(t *testing.T) {
	for _, tc := range []struct{ outcome, status, failure string }{
		{"applied", "succeeded", ""},
		{"not_applied", "not_applied", "predecessor_signs_in"},
		{"unknown", "uncertain", "execution_uncertain"},
	} {
		t.Run(tc.outcome, func(t *testing.T) {
			i := localRotationIntent(t)
			base := newLocalRotationChannel(t, i)
			base.native.unknown = true
			job := rotationJob(t, i)
			if runJob(t.Context(), base, nil, localRotationProfile(i), nil, nil, nil, job) || base.report.Status != "uncertain" || base.native.calls != 1 || base.redemptions != 1 {
				t.Fatal("the first delivery did not leave the generation unknown")
			}
			c := &localRecoveryChannel{localRotationChannel: base, recoverer: &localRotationRecoverer{outcome: tc.outcome}}
			recovery := job
			recovery.JobID = job.JobID + 1
			ok := runJob(t.Context(), c, nil, localRotationProfile(i), nil, nil, nil, recovery)
			if ok != (tc.status == "succeeded") || base.report.Status != tc.status || base.report.Failure != tc.failure {
				t.Fatalf("recovery reported %v %s/%s", ok, base.report.Status, base.report.Failure)
			}
			if c.recoverer.calls != 1 || base.native.calls != 1 || base.executions != 1 || base.redemptions != 2 {
				t.Fatalf("recovery signed in %d times, reset %d times, redeemed %d times", c.recoverer.calls, base.native.calls, base.redemptions)
			}
			if base.wireLiveAtReport {
				t.Fatal("redeemed material outlived the recovery")
			}
			if tc.status == "succeeded" && (base.report.Proof == nil || base.report.Proof.GenerationID != i.RotationID) {
				t.Fatal("the recovered generation was reported without its proof")
			}
		})
	}
}
