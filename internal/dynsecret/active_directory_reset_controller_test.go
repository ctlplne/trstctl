// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
)

var errOwnedADResetInterrupted = errors.New("owned native reset response interrupted")

type ownedADResetRuntime struct {
	current        adNativeResetIdentity
	password       []byte
	writes         int
	interruptAfter int
	proved         [][]byte
}

func (r *ownedADResetRuntime) Observe(context.Context) (adNativeResetIdentity, error) {
	return r.current, nil
}
func (r *ownedADResetRuntime) Prove(_ context.Context, expected adNativeResetIdentity, password []byte) error {
	r.proved = append(r.proved, append([]byte(nil), password...))
	if expected != r.current || !bytes.Equal(password, r.password) {
		return errors.New("owned single native generation proof failed")
	}
	return nil
}
func (r *ownedADResetRuntime) Reset(_ context.Context, expected adNativeResetIdentity, password []byte, _ bool) error {
	if expected != r.current {
		return errors.New("owned native state changed before reset")
	}
	r.password = append([]byte(nil), password...)
	r.current.KeyVersion++
	r.current.PasswordSetAt = strconv.FormatUint(r.current.KeyVersion, 10)
	r.writes++
	if r.writes == r.interruptAfter {
		return errOwnedADResetInterrupted
	}
	return nil
}
func ownedDurableADReset() (adStaticPreparation, []byte, *ownedADResetRuntime) {
	p := adPreparationFixture()
	p.Version = 2
	p.KeyVersion = 48
	p.DCInvocationID = strings.Repeat("c", 32)
	p.NativeAddress = "127.0.0.1:636"
	p.ForwardIntermediate = []byte("Owned1!forward-intermediate")
	p.InverseIntermediate = []byte("Owned1!inverse-intermediate")
	old := []byte("Owned1!initial-password")
	return p, old, &ownedADResetRuntime{current: adNativeResetIdentity{adNativeIdentity: adNativeIdentity{Name: p.Name, GUID: p.GUID, SID: p.SID, PasswordSetAt: p.PasswordSetAt}, KeyVersion: p.KeyVersion, DCInvocationID: p.DCInvocationID, NativeAddress: p.NativeAddress}, password: append([]byte(nil), old...)}
}
func TestADPreparedResetResumesEveryInterruptedBoundaryA267(t *testing.T) {
	for boundary := 1; boundary <= 4; boundary++ {
		t.Run(strconv.Itoa(boundary), func(t *testing.T) {
			p, old, native := ownedDurableADReset()
			if boundary > 2 {
				if e := driveADPreparedReset(t.Context(), p, old, false, native); e != nil {
					t.Fatal(e)
				}
			}
			native.interruptAfter = boundary
			inverse := boundary > 2
			if e := driveADPreparedReset(t.Context(), p, old, inverse, native); !errors.Is(e, errOwnedADResetInterrupted) {
				t.Fatal("native interruption was not observed", e)
			}
			if native.writes != boundary {
				t.Fatal("native effect repeated before response recovery")
			}
			native.interruptAfter = 0
			if e := driveADPreparedReset(t.Context(), p, old, inverse, native); e != nil {
				t.Fatal("frozen generation failed to resume", e)
			}
			want := 2
			credential := p.Password
			if inverse {
				want = 4
				credential = old
			}
			if native.writes != want || !bytes.Equal(native.password, credential) {
				t.Fatal("recovery repeated a reset or selected another generation")
			}
			if e := driveADPreparedReset(t.Context(), p, old, inverse, native); e != nil || native.writes != want {
				t.Fatal("completed native recovery was not a no-write replay", e)
			}
		})
	}
}
func TestADPreparedInverseAfterFirstForwardResetA267(t *testing.T) {
	p, old, native := ownedDurableADReset()
	native.interruptAfter = 1
	if e := driveADPreparedReset(t.Context(), p, old, false, native); !errors.Is(e, errOwnedADResetInterrupted) {
		t.Fatal(e)
	}
	native.interruptAfter = 0
	if e := driveADPreparedReset(t.Context(), p, old, true, native); e != nil || native.writes != 4 || !bytes.Equal(native.password, old) {
		t.Fatal("mid-forward inverse lost its unambiguous fixed generation sequence", e)
	}
}
func TestADPreparedResetRefusesAnotherNativePasswordA267(t *testing.T) {
	p, old, native := ownedDurableADReset()
	native.interruptAfter = 1
	if e := driveADPreparedReset(t.Context(), p, old, false, native); !errors.Is(e, errOwnedADResetInterrupted) {
		t.Fatal(e)
	}
	native.password = []byte("Owned1!unrelated-native-change")
	native.interruptAfter = 0
	if e := driveADPreparedReset(t.Context(), p, old, false, native); e == nil || native.writes != 1 || len(native.proved) != 1 || !bytes.Equal(native.proved[0], p.ForwardIntermediate) {
		t.Fatal("drift was overwritten or password candidates were guessed")
	}
}
func TestADPreparedInverseBeforeAnyEffectA267(t *testing.T) {
	p, old, native := ownedDurableADReset()
	if e := driveADPreparedReset(t.Context(), p, old, true, native); e != nil || native.writes != 0 || len(native.proved) != 1 || !bytes.Equal(native.proved[0], old) {
		t.Fatal("read-only inverse changed an untouched account", e)
	}
}
