// SPDX-License-Identifier: BUSL-1.1

package winaccounts

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// recoverBoundary is a local account whose current password a test chooses;
// a refused sign-in counts toward the lockout threshold, as Windows counts it.
type recoverBoundary struct {
	state   RotationState
	current []byte
	foreign bool
	logons  int
	writes  int
}

func (d *recoverBoundary) Inspect(context.Context, RotationBinding) (RotationState, error) {
	return d.state, nil
}
func (d *recoverBoundary) SetPassword(context.Context, RotationBinding, []byte) error {
	d.writes++
	return errors.New("recovery never writes")
}
func (d *recoverBoundary) Authenticate(_ context.Context, _ RotationBinding, value []byte) (string, error) {
	d.logons++
	if bytes.Equal(value, d.current) {
		if d.foreign {
			return "S-1-5-21-9-8-7-1001", nil
		}
		return d.state.Binding.Account.SID, nil
	}
	d.state.BadPasswordCount++
	return "", ErrCredentialRejected
}

// TestNativeLocalRotationRecoverSettlesAnUnknownOutcomeA268O1 is A268-O1: a
// begun generation whose outcome was lost is settled by signing in, never by
// writing a password. An applied generation yields the same proof Rotate
// would, once the predecessor is refused. A generation the account never took
// is reported not applied when the predecessor still signs in. Every other
// answer stays uncertain, and no sign-in is attempted once one more failure
// could lock the account.
func TestNativeLocalRotationRecoverSettlesAnUnknownOutcomeA268O1(t *testing.T) {
	_, _, _, old, next := rotationFixture()
	defer secret.Wipe(old)
	defer secret.Wipe(next)
	fixture := func(current []byte, threshold, bad uint32) (Rotator, *recoverBoundary, *rotationFence) {
		state := RotationState{Binding: ownedRotationBinding(), MinimumPasswordLength: 12, LockoutThreshold: threshold, BadPasswordCount: bad}
		native := &recoverBoundary{state: state, current: current}
		return Rotator{driver: native}, native, &rotationFence{alreadyStarted: true}
	}

	r, native, fence := fixture(next, 10, 0)
	proof, err := r.Recover(t.Context(), ownedRotationBinding(), ownedGeneration, old, next, fence)
	if err != nil || !proof.NewAuthenticated || !proof.OldRefused || proof.GenerationID != ownedGeneration || fence.completes != 1 || fence.proof != proof ||
		native.logons != 2 || native.writes != 0 {
		t.Fatalf("an applied generation = %+v, %v (logons %d, writes %d, completes %d)", proof, err, native.logons, native.writes, fence.completes)
	}

	r, native, fence = fixture(old, 10, 0)
	if _, err := r.Recover(t.Context(), ownedRotationBinding(), ownedGeneration, old, next, fence); !errors.Is(err, ErrRotationNotApplied) ||
		native.logons != 2 || native.writes != 0 || fence.completes != 0 || native.state.BadPasswordCount != 1 {
		t.Fatalf("a generation never applied = %v (logons %d, bad %d, completes %d)", err, native.logons, native.state.BadPasswordCount, fence.completes)
	}

	r, native, fence = fixture([]byte("someone-else-set-this-password"), 10, 0)
	if _, err := r.Recover(t.Context(), ownedRotationBinding(), ownedGeneration, old, next, fence); !errors.Is(err, ErrRotationUncertain) || native.logons != 2 || fence.completes != 0 {
		t.Fatalf("neither password signs in = %v (logons %d)", err, native.logons)
	}

	r, native, fence = fixture(next, 10, 0)
	native.foreign = true
	if _, err := r.Recover(t.Context(), ownedRotationBinding(), ownedGeneration, old, next, fence); !errors.Is(err, ErrRotationUncertain) || native.logons != 1 || fence.completes != 0 {
		t.Fatalf("a foreign SID = %v (logons %d)", err, native.logons)
	}

	// With the threshold at 3 and one failure already counted, the prepared
	// password may be tried (a failure leaves 2), but the predecessor may not.
	r, native, fence = fixture(old, 3, 1)
	if _, err := r.Recover(t.Context(), ownedRotationBinding(), ownedGeneration, old, next, fence); !errors.Is(err, ErrRotationUncertain) ||
		native.logons != 1 || native.state.BadPasswordCount != 2 {
		t.Fatalf("recovery at the lockout margin = %v (logons %d, bad %d)", err, native.logons, native.state.BadPasswordCount)
	}
	r, native, fence = fixture(next, 2, 1)
	if _, err := r.Recover(t.Context(), ownedRotationBinding(), ownedGeneration, old, next, fence); !errors.Is(err, ErrRotationUncertain) || native.logons != 0 {
		t.Fatalf("recovery with no lockout budget signed in: %v (logons %d)", err, native.logons)
	}
	if _, err := r.Recover(t.Context(), ownedRotationBinding(), ownedGeneration, old, old, fence); !errors.Is(err, ErrRotationInvalid) {
		t.Fatalf("recovery with identical material = %v", err)
	}
}
