// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"testing"
	"unsafe"
)

func TestAutomationVariantAuthorityA267(t *testing.T) {
	encoded := automationVariant{Value: 1, Extra: 2}.scalarBits64()
	wantBits := uint64(1)
	if unsafe.Sizeof(uintptr(0)) == 4 {
		wantBits = 0x200000001
	}
	if encoded != wantBits {
		t.Fatal("native 64-bit union layout differs")
	}
	if automationDISPID(-3) != 0xfffffffd || automationDISPID(-2147483648) != 0x80000000 || automationDISPID(42) != 42 {
		t.Fatal("native signed dispatch ID encoding differs")
	}
	if value, err := automationInteger(42).integer(); err != nil || value != 42 {
		t.Fatal("typed native integer construction failed")
	}
	for _, test := range []struct {
		value automationVariant
		want  int64
	}{
		{automationVariant{VT: 3, Value: 42}, 42}, {automationVariant{VT: 3, Value: 0xffffffff}, -1}, {automationVariant{VT: 19, Value: 0xffffffff}, 4294967295},
	} {
		got, err := test.value.integer()
		if err != nil || got != test.want {
			t.Fatal("native Automation scalar decoded incorrectly")
		}
	}
	for _, vt := range []uint16{0, 1, 8, 9, 12, 13, 0x2003, 0x4003, 0x8003} {
		if _, err := (automationVariant{VT: vt, Value: 42}).integer(); err == nil {
			t.Fatal("non-scalar Automation authority was accepted as an integer")
		}
	}
	if value, err := (automationVariant{VT: 11, Value: 0xffff}).boolean(); err != nil || !value {
		t.Fatal("native Automation true decoded incorrectly")
	}
	if _, err := (automationVariant{VT: 3, Value: 0xffff}).boolean(); err == nil {
		t.Fatal("wrong native type accepted as a Boolean")
	}
	want := uintptr(16)
	if unsafe.Sizeof(uintptr(0)) == 8 {
		want = 24
	}
	if unsafe.Sizeof(automationVariant{}) != want {
		t.Fatal("VARIANT ABI size differs from native OLE layout")
	}
}
func FuzzAutomationVariantA267(f *testing.F) {
	f.Add(uint16(3), uint64(42))
	f.Add(uint16(0x4003), uint64(0xffff))
	f.Add(uint16(19), uint64(0xffffffff))
	f.Fuzz(func(t *testing.T, vt uint16, value uint64) {
		native := automationVariant{VT: vt, Value: uintptr(value)}
		integer, err := native.integer()
		if err == nil {
			if vt != 2 && vt != 3 && vt != 19 {
				t.Fatal("unsupported native variant type admitted")
			}
			if integer < -2147483648 || integer > 4294967295 {
				t.Fatal("unbounded native scalar")
			}
		}
	})
}
