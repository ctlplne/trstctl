// SPDX-License-Identifier: BUSL-1.1
package winaccounts

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unicode/utf16"
	"unicode/utf8"
)

func TestPrivatePasswordEncodingStaysExactAndBoundedA268(t *testing.T) {
	for _, value := range [][]byte{nil, {'a', 0, 'b'}, {0xff}, bytes.Repeat([]byte{'x'}, 257)} {
		if buffer, err := lockedPasswordUTF16(value); err == nil {
			buffer.Destroy()
			t.Fatal("invalid private encoding reached a native password")
		}
	}
	value := []byte{'A', 0xf0, 0x9f, 0x98, 0x80, '3'}
	buffer, err := lockedPasswordUTF16(value)
	if err != nil {
		t.Fatal(err)
	}
	defer buffer.Destroy()
	encoded := buffer.Bytes()
	if len(encoded) != 10 || binary.LittleEndian.Uint16(encoded) != uint16('A') || binary.LittleEndian.Uint16(encoded[2:]) != 0xd83d || binary.LittleEndian.Uint16(encoded[4:]) != 0xde00 || binary.LittleEndian.Uint16(encoded[6:]) != uint16('3') || binary.LittleEndian.Uint16(encoded[8:]) != 0 {
		t.Fatal("native password code units changed")
	}
}
func FuzzPrivateWindowsPasswordEncodingA268(f *testing.F) {
	f.Add([]byte{'A', 'b', '3'})
	f.Add([]byte{0xf0, 0x9f, 0x98, 0x80})
	f.Add([]byte{0xff})
	f.Add([]byte{'a', 0})
	f.Fuzz(func(t *testing.T, value []byte) {
		buffer, err := lockedPasswordUTF16(value)
		if err != nil {
			if validPrivatePassword(value) {
				t.Fatal("valid bounded password failed encoding", err)
			}
			return
		}
		defer buffer.Destroy()
		units := 0
		for rest := value; len(rest) > 0; {
			r, n := utf8.DecodeRune(rest)
			rest = rest[n:]
			if r <= 0xffff {
				if rune(binary.LittleEndian.Uint16(buffer.Bytes()[units*2:])) != r {
					t.Fatal("private character changed")
				}
				units++
			} else {
				hi, lo := utf16.EncodeRune(r)
				if rune(binary.LittleEndian.Uint16(buffer.Bytes()[units*2:])) != hi || rune(binary.LittleEndian.Uint16(buffer.Bytes()[(units+1)*2:])) != lo {
					t.Fatal("private surrogate changed")
				}
				units += 2
			}
		}
		if units > 256 || len(buffer.Bytes()) != (units+1)*2 || binary.LittleEndian.Uint16(buffer.Bytes()[units*2:]) != 0 {
			t.Fatal("private encoding exceeded its framing/bound")
		}
	})
}
