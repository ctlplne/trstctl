// SPDX-License-Identifier: MPL-2.0

package clusterfuzz

import (
	"encoding/binary"
	"strconv"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/discovery/adcs"
)

func FuzzEnrollmentPrincipalsFromSecurityDescriptor(f *testing.F) {
	f.Add(securityDescriptor(objectACE(0x05, 0x00000100, enrollmentGUIDBytes(), sidBytes("S-1-5-11"))))
	f.Add([]byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = adcs.EnrollmentPrincipalsFromSecurityDescriptor(raw)
	})
}

func enrollmentGUIDBytes() []byte {
	return []byte{0x68, 0xc9, 0x10, 0x0e, 0xfb, 0x78, 0xd2, 0x11, 0x90, 0xd4, 0x00, 0xc0, 0x4f, 0x79, 0xdc, 0x55}
}

// #nosec G115 -- test SID inputs have at most 255 sub-authorities (CWE-190).

// #nosec G115 -- ParseUint limits authority to 48 bits and this loop emits one byte at a time (CWE-190).

func objectACE(aceType byte, mask uint32, objectGUID, sid []byte) []byte {
	out := make([]byte, 12+len(objectGUID)+len(sid))
	out[0] = aceType
	binary.LittleEndian.PutUint16(out[2:4], uint16(len(out))) // #nosec G115 -- deterministic test SIDs keep the object ACE below MaxUint16 (CWE-190).
	binary.LittleEndian.PutUint32(out[4:8], mask)
	binary.LittleEndian.PutUint32(out[8:12], 0x1)
	copy(out[12:], objectGUID)
	copy(out[12+len(objectGUID):], sid)
	return out
}

func securityDescriptor(aces ...[]byte) []byte {
	aclSize := 8
	for _, ace := range aces {
		aclSize += len(ace)
	}
	out := make([]byte, 20+aclSize)
	out[0] = 1
	binary.LittleEndian.PutUint16(out[2:4], 0x8004)
	binary.LittleEndian.PutUint32(out[16:20], 20)
	acl := out[20:]
	acl[0] = 4
	binary.LittleEndian.PutUint16(acl[2:4], uint16(aclSize))
	binary.LittleEndian.PutUint16(acl[4:6], uint16(len(aces))) // #nosec G115 -- test call sites pass a bounded literal ACE set (CWE-190).
	offset := 8
	for _, ace := range aces {
		copy(acl[offset:], ace)
		offset += len(ace)
	}
	return out
}
func sidBytes(text string) []byte {
	parts := strings.Split(strings.TrimPrefix(text, "S-"), "-")
	if len(parts) < 2 {
		panic("bad test SID")
	}
	revision, _ := strconv.ParseUint(parts[0], 10, 8)
	authority, _ := strconv.ParseUint(parts[1], 10, 48)
	out := make([]byte, 8+4*(len(parts)-2))
	out[0], out[1] = byte(revision), byte(len(parts)-2) // #nosec G115 -- ParseUint bounds revision to 8 bits and the test SID grammar caps sub-authorities at 255 (CWE-190).
	for i := 0; i < 6; i++ {
		out[7-i] = byte(authority) // #nosec G115 -- ParseUint bounds authority to 48 bits and this loop emits one byte at a time (CWE-190).
		authority >>= 8
	}
	for i, part := range parts[2:] {
		value, _ := strconv.ParseUint(part, 10, 32)
		binary.LittleEndian.PutUint32(out[8+i*4:], uint32(value))
	}
	return out
}
