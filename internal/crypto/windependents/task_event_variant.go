// SPDX-License-Identifier: BUSL-1.1
package windependents

import "errors"

// EVT_VARIANT is a distinct native ABI from Automation VARIANT. Scalar numeric
// authority never follows a native pointer, array or unrecognized type.
type taskEventVariant struct {
	Value       uint64
	Count, Type uint32
}

func (v taskEventVariant) unsigned() (uint64, error) {
	if v.Count != 0 {
		return 0, errors.New("windows task: unexpected native event array")
	}
	switch v.Type {
	case 4:
		return v.Value & 0xff, nil
	case 6:
		return v.Value & 0xffff, nil
	case 8, 20:
		return v.Value & 0xffffffff, nil
	case 10, 21:
		return v.Value, nil
	default:
		return 0, errors.New("windows task: unexpected native event scalar type")
	}
}
func (v taskEventVariant) boolean() (bool, error) {
	if v.Count != 0 || v.Type != 13 {
		return false, errors.New("windows task: unexpected native channel flag type")
	}
	switch v.Value & 0xffffffff {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, errors.New("windows task: invalid native channel flag")
	}
}
