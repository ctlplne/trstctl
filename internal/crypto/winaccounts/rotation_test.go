// SPDX-License-Identifier: BUSL-1.1
package winaccounts

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"trstctl.com/trstctl/internal/crypto/secret"
)

const ownedGeneration = "58700000-0000-4000-8000-000000000001"

func ownedRotationBinding() RotationBinding {
	return RotationBinding{Machine: Machine{Name: "OWNED", SID: "S-1-5-21-1-2-3", Role: 3}, Account: Account{Name: "OwnedAdmin", SID: "S-1-5-21-1-2-3-1001", Enabled: true, PasswordRequired: true}}
}

type rotationBoundary struct {
	state                            RotationState
	inspects, writes, logons         int
	badSID, oldAccepted, writeFailed bool
	afterInspect                     func(*rotationBoundary)
	next                             []byte
}

func (d *rotationBoundary) Inspect(context.Context, RotationBinding) (RotationState, error) {
	d.inspects++
	if d.afterInspect != nil {
		d.afterInspect(d)
	}
	return d.state, nil
}
func (d *rotationBoundary) SetPassword(_ context.Context, _ RotationBinding, value []byte) error {
	d.writes++
	if !bytes.Equal(value, d.next) {
		return errors.New("different prepared value")
	}
	if d.writeFailed {
		return errors.New("owned unknown native outcome")
	}
	return nil
}
func (d *rotationBoundary) Authenticate(_ context.Context, _ RotationBinding, value []byte) (string, error) {
	d.logons++
	if bytes.Equal(value, d.next) {
		if d.badSID {
			return "S-1-5-21-9-8-7-1001", nil
		}
		return d.state.Binding.Account.SID, nil
	}
	if d.oldAccepted {
		return d.state.Binding.Account.SID, nil
	}
	d.state.BadPasswordCount++
	return "", ErrCredentialRejected
}

type rotationFence struct {
	begins, completes          int
	alreadyStarted, failCommit bool
	proof                      RotationProof
}

func (f *rotationFence) Begin(context.Context, RotationBinding, string) (bool, error) {
	f.begins++
	if f.alreadyStarted {
		return false, nil
	}
	f.alreadyStarted = true
	return true, nil
}
func (f *rotationFence) Complete(_ context.Context, p RotationProof) error {
	f.completes++
	if f.failCommit {
		return errors.New("owned journal unavailable")
	}
	f.proof = p
	return nil
}
func rotationFixture() (Rotator, *rotationBoundary, *rotationFence, []byte, []byte) {
	old := bytes.Repeat([]byte{'x'}, 32)
	next := bytes.Repeat([]byte{'z'}, 32)
	next[0] = 'A'
	next[1] = '9'
	native := &rotationBoundary{state: RotationState{Binding: ownedRotationBinding(), MinimumPasswordLength: 12, LockoutThreshold: 10}, next: next}
	fence := &rotationFence{}
	return Rotator{driver: native}, native, fence, old, next
}
func TestNativeLocalRotationPublishesOnlyExactNewSIDAndOldRefusalA268(t *testing.T) {
	r, native, fence, old, next := rotationFixture()
	defer secret.Wipe(old)
	defer secret.Wipe(next)
	proof, err := r.Rotate(t.Context(), ownedRotationBinding(), ownedGeneration, old, next, fence)
	if err != nil || native.writes != 1 || native.logons != 2 || fence.begins != 1 || fence.completes != 1 || !proof.NewAuthenticated || !proof.OldRefused || proof.Binding != ownedRotationBinding() || proof.GenerationID != ownedGeneration {
		t.Fatal("complete native proof or one-generation execution missing", err)
	}
	if _, err := r.Rotate(t.Context(), ownedRotationBinding(), ownedGeneration, old, next, fence); !errors.Is(err, ErrRotationUncertain) || native.writes != 1 || native.logons != 2 {
		t.Fatal("started operation performed a blind second reset/probe", err)
	}
}
func TestNativeLocalRotationRefusesUnsafeOrForeignPreflightBeforeResetA268(t *testing.T) {
	for _, change := range []func(*rotationBoundary){
		func(n *rotationBoundary) { n.state.Binding.Machine.SID = "S-1-5-21-4-5-6" },
		func(n *rotationBoundary) { n.state.Binding.Machine.Role = 5 },
		func(n *rotationBoundary) { n.state.Binding.Account.SID = "S-1-5-21-4-5-6-1001" },
		func(n *rotationBoundary) { n.state.Binding.Account.Enabled = false },
		func(n *rotationBoundary) { n.state.Binding.Account.Locked = true },
		func(n *rotationBoundary) { n.state.BadPasswordCount = ^uint32(0) },
		func(n *rotationBoundary) { n.state.LockoutThreshold = 1 },
		func(n *rotationBoundary) { n.state.LockoutThreshold = 3; n.state.BadPasswordCount = 2 },
	} {
		r, native, fence, old, next := rotationFixture()
		change(native)
		_, err := r.Rotate(t.Context(), ownedRotationBinding(), ownedGeneration, old, next, fence)
		secret.Wipe(old)
		secret.Wipe(next)
		if err == nil || native.writes != 0 || native.logons != 0 || fence.begins != 0 {
			t.Fatal("unsafe identity or lockout budget reached native mutation/authentication", err)
		}
	}
}
func TestNativeLocalRotationUnknownEffectsNeverBecomeSuccessOrRetryA268(t *testing.T) {
	for _, change := range []func(*rotationBoundary, *rotationFence){
		func(n *rotationBoundary, _ *rotationFence) { n.badSID = true },
		func(n *rotationBoundary, _ *rotationFence) { n.oldAccepted = true },
		func(n *rotationBoundary, _ *rotationFence) { n.writeFailed = true },
		func(_ *rotationBoundary, f *rotationFence) { f.failCommit = true },
		func(n *rotationBoundary, _ *rotationFence) {
			n.afterInspect = func(n *rotationBoundary) {
				if n.inspects == 2 {
					n.state.Binding.Account.Name = "ChangedAdmin"
				}
			}
		},
		func(n *rotationBoundary, _ *rotationFence) {
			n.afterInspect = func(n *rotationBoundary) {
				if n.inspects == 3 {
					n.state.LockoutThreshold = 1
				}
			}
		},
	} {
		r, native, fence, old, next := rotationFixture()
		change(native, fence)
		proof, err := r.Rotate(t.Context(), ownedRotationBinding(), ownedGeneration, old, next, fence)
		if !errors.Is(err, ErrRotationUncertain) || proof.NewAuthenticated || proof.OldRefused {
			t.Fatal("unknown/changed native execution became a published credential", err)
		}
		writes, logons := native.writes, native.logons
		if _, err := r.Rotate(t.Context(), ownedRotationBinding(), ownedGeneration, old, next, fence); err == nil || native.writes != writes || native.logons != logons {
			t.Fatal("unknown native execution repeated a reset or password guess", err)
		}
		secret.Wipe(old)
		secret.Wipe(next)
	}
}
func TestNativeLocalRotationNeedsDurableFenceAndDistinctMaterialA268(t *testing.T) {
	r, native, fence, old, next := rotationFixture()
	defer secret.Wipe(old)
	defer secret.Wipe(next)
	if _, err := r.Rotate(t.Context(), ownedRotationBinding(), ownedGeneration, old, next, nil); err == nil || native.writes != 0 {
		t.Fatal("unfenced reset reached Windows")
	}
	if _, err := r.Rotate(t.Context(), ownedRotationBinding(), ownedGeneration, next, next, fence); err == nil || fence.begins != 0 {
		t.Fatal("same generation was treated as a changed password")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := r.Rotate(canceled, ownedRotationBinding(), ownedGeneration, old, next, fence); err == nil || fence.begins != 0 {
		t.Fatal("canceled operation started a native reset")
	}
}

func TestNativeLocalRotationRejectsOversizedPredecessorBeforeFenceA268(t *testing.T) {
	r, native, fence, unusedOld, next := rotationFixture()
	secret.Wipe(unusedOld)
	defer secret.Wipe(next)
	old := bytes.Repeat([]byte{'x'}, 257)
	defer secret.Wipe(old)
	if _, err := r.Rotate(t.Context(), ownedRotationBinding(), ownedGeneration, old, next, fence); err == nil || fence.begins != 0 || native.writes != 0 {
		t.Fatal("unusable predecessor was checked only after a password reset")
	}
}
