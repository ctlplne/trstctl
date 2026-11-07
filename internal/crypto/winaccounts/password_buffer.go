// SPDX-License-Identifier: BUSL-1.1
package winaccounts

import (
	"encoding/binary"
	"trstctl.com/trstctl/internal/crypto/secret"
	"unicode/utf16"
	"unicode/utf8"
)

// lockedPasswordUTF16 creates no private string or GC-managed UTF-16 array.
// The only encoded password lives in locked, explicitly destroyed byte memory.
func lockedPasswordUTF16(value []byte) (*secret.Buffer, error) {
	if !validPrivatePassword(value) {
		return nil, ErrRotationInvalid
	}
	units := 0
	for rest := value; len(rest) > 0; {
		r, n := utf8.DecodeRune(rest)
		units += utf16.RuneLen(r)
		rest = rest[n:]
	}
	if units == 0 || units > 256 {
		return nil, ErrRotationInvalid
	}
	result, err := secret.New((units + 1) * 2)
	if err != nil {
		return nil, err
	}
	offset := 0
	for rest := value; len(rest) > 0; {
		r, n := utf8.DecodeRune(rest)
		rest = rest[n:]
		if r <= 0xffff {
			binary.LittleEndian.PutUint16(result.Bytes()[offset:], uint16(r&0xffff))
			offset += 2
		} else {
			hi, lo := utf16.EncodeRune(r)
			binary.LittleEndian.PutUint16(result.Bytes()[offset:], uint16(hi&0xffff))
			binary.LittleEndian.PutUint16(result.Bytes()[offset+2:], uint16(lo&0xffff))
			offset += 4
		}
	}
	return result, nil
}
