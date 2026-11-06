// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"errors"
	"strconv"
)

// VARIANT's native union includes a two-pointer BRECORD arm. This gives the
// required 24-byte layout on 64-bit Windows and 16-byte layout on 32-bit Windows.
// Pointer/array/by-reference variants are never interpreted as scalar authority.
type automationVariant struct {
	VT           uint16
	Reserved     [3]uint16
	Value, Extra uintptr
}

func (v automationVariant) integer() (int64, error) {
	switch v.VT {
	case 2:
		value := int64(uint64(v.Value) & 0xffff)
		if value&0x8000 != 0 {
			value -= 1 << 16
		}
		return value, nil
	case 3:
		value := int64(uint64(v.Value) & 0xffffffff)
		if value&0x80000000 != 0 {
			value -= 1 << 32
		}
		return value, nil
	case 19:
		return int64(uint64(v.Value) & 0xffffffff), nil
	default:
		return 0, errors.New("windows Automation: unexpected native scalar type")
	}
}
func (v automationVariant) boolean() (bool, error) {
	if v.VT != 11 {
		return false, errors.New("windows Automation: unexpected native Boolean type")
	}
	switch uint64(v.Value) & 0xffff {
	case 0:
		return false, nil
	case 0xffff:
		return true, nil
	default:
		return false, errors.New("windows Automation: noncanonical native Boolean")
	}
}
func automationInteger(value uint32) automationVariant {
	return automationVariant{VT: 3, Value: uintptr(value)}
}

// IDispatch takes a signed 32-bit DISPID in one native argument slot. Avoid
// converting a negative integer to unsigned before its width is established.
func automationDISPID(value int32) uintptr {
	if value >= 0 {
		return uintptr(value)
	}
	return uintptr(((int64(1) << 32) + int64(value)) & 0xffffffff)
}

// Native 64-bit scalar union members span both pointer slots on 32-bit Windows.
func (v automationVariant) scalarBits64() uint64 {
	if strconv.IntSize == 32 {
		return uint64(v.Value&0xffffffff) | (uint64(v.Extra&0xffffffff) << 32)
	}
	return uint64(v.Value)
}
