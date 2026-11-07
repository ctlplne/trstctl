// SPDX-License-Identifier: BUSL-1.1
package winaccounts

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func ownedNativeSID() []byte {
	return []byte{1, 4, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 10, 0, 0, 0, 20, 0, 0, 0, 30, 0, 0, 0}
}
func TestNativePublicBufferDecodersKeepExactIdentityA268(t *testing.T) {
	sid, err := nativeSIDBytes(ownedNativeSID())
	if err != nil || sid != ownedMachineSID {
		t.Fatal("native SID byte order changed", sid, err)
	}
	for _, raw := range [][]byte{nil, {2, 0, 0, 0, 0, 0, 0, 5}, {1, 16, 0, 0, 0, 0, 0, 5}, ownedNativeSID()[:12]} {
		if _, err := nativeSIDBytes(raw); err == nil {
			t.Fatal("malformed native SID accepted")
		}
	}
	good := []byte{'A', 0, 'd', 0, 'm', 0, 'i', 0, 'n', 0, 0, 0}
	if name, err := nativeWideBytes(good, 20); err != nil || name != "Admin" {
		t.Fatal(name, err)
	}
	for _, raw := range [][]byte{nil, {'a', 0}, {0, 0xd8, 0, 0}, {0, 0xdc, 0, 0}} {
		if _, err := nativeWideBytes(raw, 20); err == nil {
			t.Fatal("malformed native UTF16 accepted")
		}
	}
	if _, err := nativeWideBytes(good, 4); err == nil {
		t.Fatal("native name exceeded its supplied field bound")
	}
}
func FuzzNativeLocalAccountPublicBuffersA268(f *testing.F) {
	f.Add(ownedNativeSID(), []byte{'A', 0, 0, 0})
	f.Add([]byte{1, 255}, []byte{0, 0xd8, 0, 0})
	f.Fuzz(func(t *testing.T, sid, wide []byte) {
		_, _ = nativeSIDBytes(sid)
		if value, err := nativeWideBytes(wide, 255); err == nil {
			var encoded []byte
			for _, unit := range utf16.Encode([]rune(value)) {
				encoded = binary.LittleEndian.AppendUint16(encoded, unit)
			}
			encoded = append(encoded, 0, 0)
			if !bytes.HasPrefix(wide, encoded) {
				t.Fatal("native public UTF16 silently changed identity bytes")
			}
		}
	})
}
