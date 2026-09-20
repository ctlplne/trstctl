// SPDX-License-Identifier: BUSL-1.1

package adcs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Bounds are part of the parser contract. A directory response is untrusted
// input, and one damaged template must not turn a relay into an unbounded
// allocator or an out-of-range reader.
const (
	MaxTemplates          = 2_048
	MaxEnrollmentServices = 512
	maxDescriptorBytes    = 1 << 20
	maxACEs               = 4_096

	securityDescriptorSelfRelative = 0x8000
	securityDescriptorDACLPresent  = 0x0004
	accessMaskControlAccess        = 0x00000100
	accessMaskGenericAll           = 0x10000000
	aceFlagInheritOnly             = 0x08
	aceObjectTypePresent           = 0x00000001
	aceInheritedObjectTypePresent  = 0x00000002
)

// enrollmentExtendedRightGUID is the Windows in-memory byte order of the
// Certificate-Enrollment extended-right GUID
// 0e10c968-78fb-11d2-90d4-00c04f79dc55. GUID's first three integer fields are
// little-endian in a binary ACE; the final eight bytes retain display order.
var enrollmentExtendedRightGUID = [16]byte{
	0x68, 0xc9, 0x10, 0x0e, 0xfb, 0x78, 0xd2, 0x11,
	0x90, 0xd4, 0x00, 0xc0, 0x4f, 0x79, 0xdc, 0x55,
}

// EnrollmentPrincipalsFromSecurityDescriptor decodes the trustees that the
// template DACL grants certificate enrollment. The result is canonical SID
// text, sorted and deduplicated; directory name resolution is intentionally a
// separate concern because names can change while SIDs are the ACL authority.
//
// Exact-trustee enrollment denies remove the same SID from the grant set.
// Group-membership expansion and conditional ACE evaluation are deliberately
// not guessed: the output describes normalized ACL trustees, not an invented
// effective-token authorization result.
func EnrollmentPrincipalsFromSecurityDescriptor(raw []byte) ([]string, error) {
	if len(raw) < 20 {
		return nil, errors.New("security descriptor is shorter than its fixed header")
	}
	if len(raw) > maxDescriptorBytes {
		return nil, errors.New("security descriptor exceeds the parser bound")
	}
	if raw[0] != 1 {
		return nil, fmt.Errorf("security descriptor revision %d is unsupported", raw[0])
	}
	control := binary.LittleEndian.Uint16(raw[2:4])
	if control&securityDescriptorSelfRelative == 0 {
		return nil, errors.New("security descriptor is not self-relative")
	}
	if control&securityDescriptorDACLPresent == 0 {
		// A null DACL grants full access. Reporting nobody here would invert the
		// most dangerous possible descriptor into the safest-looking answer.
		return []string{"S-1-1-0"}, nil
	}
	daclOffset := uint64(binary.LittleEndian.Uint32(raw[16:20]))
	if daclOffset == 0 {
		return []string{"S-1-1-0"}, nil
	}
	if daclOffset+8 > uint64(len(raw)) {
		return nil, errors.New("security descriptor DACL offset is outside the value")
	}
	acl := raw[int(daclOffset):] // #nosec G115 -- the offset is uint32-derived and bounded against len(raw) above (CWE-190).
	if acl[0] != 2 && acl[0] != 4 {
		return nil, fmt.Errorf("DACL revision %d is unsupported", acl[0])
	}
	aclSize := int(binary.LittleEndian.Uint16(acl[2:4]))
	aceCount := int(binary.LittleEndian.Uint16(acl[4:6]))
	if aclSize < 8 || aclSize > len(acl) {
		return nil, errors.New("DACL size is outside the security descriptor")
	}
	if aceCount > maxACEs {
		return nil, errors.New("DACL ACE count exceeds the parser bound")
	}
	acl = acl[:aclSize]
	allowed := make(map[string]struct{}, aceCount)
	denied := make(map[string]struct{}, aceCount)
	offset := 8
	for i := 0; i < aceCount; i++ {
		if offset+4 > len(acl) {
			return nil, fmt.Errorf("ACE %d header exceeds the DACL", i)
		}
		aceSize := int(binary.LittleEndian.Uint16(acl[offset+2 : offset+4]))
		if aceSize < 4 || offset+aceSize > len(acl) {
			return nil, fmt.Errorf("ACE %d size exceeds the DACL", i)
		}
		ace := acl[offset : offset+aceSize]
		offset += aceSize
		if ace[1]&aceFlagInheritOnly != 0 {
			continue
		}
		grant, deny, sidOffset, applies, err := enrollmentACE(ace)
		if err != nil {
			return nil, fmt.Errorf("ACE %d: %w", i, err)
		}
		if !applies {
			continue
		}
		sid, err := canonicalSID(ace[sidOffset:])
		if err != nil {
			return nil, fmt.Errorf("ACE %d trustee: %w", i, err)
		}
		if deny {
			denied[sid] = struct{}{}
		}
		if grant {
			allowed[sid] = struct{}{}
		}
	}
	if offset != len(acl) {
		return nil, errors.New("DACL ACE count does not cover its encoded size")
	}
	out := make([]string, 0, len(allowed))
	for sid := range allowed {
		if _, blocked := denied[sid]; !blocked {
			out = append(out, sid)
		}
	}
	sort.Strings(out)
	return out, nil
}

func enrollmentACE(ace []byte) (grant, deny bool, sidOffset int, applies bool, err error) {
	if len(ace) < 8 {
		return false, false, 0, false, errors.New("ACE is shorter than mask header")
	}
	mask := binary.LittleEndian.Uint32(ace[4:8])
	rightApplies := mask&accessMaskGenericAll != 0 || mask&accessMaskControlAccess != 0
	switch ace[0] {
	case 0x00, 0x01: // ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE
		return ace[0] == 0x00, ace[0] == 0x01, 8, rightApplies, nil
	case 0x05, 0x06: // ACCESS_ALLOWED_OBJECT_ACE, ACCESS_DENIED_OBJECT_ACE
		if len(ace) < 12 {
			return false, false, 0, false, errors.New("object ACE is shorter than its flags")
		}
		flags := binary.LittleEndian.Uint32(ace[8:12])
		if flags & ^uint32(aceObjectTypePresent|aceInheritedObjectTypePresent) != 0 {
			return false, false, 0, false, errors.New("object ACE carries unknown flags")
		}
		sidAt := 12
		objectMatches := flags&aceObjectTypePresent == 0
		if flags&aceObjectTypePresent != 0 {
			if sidAt+16 > len(ace) {
				return false, false, 0, false, errors.New("object ACE omits ObjectType GUID")
			}
			objectMatches = string(ace[sidAt:sidAt+16]) == string(enrollmentExtendedRightGUID[:])
			sidAt += 16
		}
		if flags&aceInheritedObjectTypePresent != 0 {
			if sidAt+16 > len(ace) {
				return false, false, 0, false, errors.New("object ACE omits InheritedObjectType GUID")
			}
			sidAt += 16
		}
		applies := mask&accessMaskGenericAll != 0 || (mask&accessMaskControlAccess != 0 && objectMatches)
		return ace[0] == 0x05, ace[0] == 0x06, sidAt, applies, nil
	default:
		// Audit, callback, mandatory-label, and resource ACEs are not simple
		// unconditional enrollment grants. Ignoring them is safer than claiming
		// a conditional principal can enroll without evaluating its condition.
		return false, false, 0, false, nil
	}
}

func canonicalSID(raw []byte) (string, error) {
	if len(raw) < 8 {
		return "", errors.New("SID is shorter than its fixed header")
	}
	if raw[0] != 1 {
		return "", fmt.Errorf("SID revision %d is unsupported", raw[0])
	}
	count := int(raw[1])
	if count > 15 {
		return "", errors.New("SID has more than 15 subauthorities")
	}
	length := 8 + 4*count
	if length > len(raw) {
		return "", errors.New("SID subauthorities exceed the ACE")
	}
	if length != len(raw) {
		return "", errors.New("SID does not consume the complete ACE trustee value")
	}
	authority := uint64(0)
	for _, value := range raw[2:8] {
		authority = authority<<8 | uint64(value)
	}
	var b strings.Builder
	b.WriteString("S-1-")
	b.WriteString(strconv.FormatUint(authority, 10))
	for i := 0; i < count; i++ {
		b.WriteByte('-')
		b.WriteString(strconv.FormatUint(uint64(binary.LittleEndian.Uint32(raw[8+i*4:])), 10))
	}
	return b.String(), nil
}
