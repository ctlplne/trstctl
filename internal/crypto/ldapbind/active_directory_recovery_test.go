// SPDX-License-Identifier: BUSL-1.1
package ldapbind

import (
	"bytes"
	"encoding/binary"
	"github.com/go-asn1-ber/asn1-ber"
	"testing"
	"testing/quick"
	"unicode/utf16"
	"unicode/utf8"
)

func checkADRecoveryPacket(password []byte) bool {
	packet, err := newADRecoveryPasswordPacket("CN=owned,DC=example,DC=test", password)
	valid := len(password) >= 16 && len(password) <= 1024 && utf8.Valid(password) && !bytes.Contains(password, []byte{0})
	if err != nil {
		return !valid
	}
	defer packet.Destroy()
	if !valid || len(packet.Bytes()) > 16<<10 {
		return false
	}
	decoded, err := ber.DecodePacketErr(packet.Bytes())
	if err != nil || len(decoded.Children) != 2 {
		return false
	}
	change := decoded.Children[1].Children[1].Children[0]
	if change.Children[0].Value != int64(2) || change.Children[1].Children[0].Value != "unicodePwd" {
		return false
	}
	got := change.Children[1].Children[1].Children[0].Data.Bytes()
	// Reference conversion uses synthetic test material only. The production
	// encoder never creates a string or temporary UTF-16 password slice.
	units := utf16.Encode([]rune(string(password)))
	want := make([]byte, (len(units)+2)*2)
	want[0] = '"'
	want[len(want)-2] = '"'
	for i, v := range units {
		binary.LittleEndian.PutUint16(want[(i+1)*2:], v)
	}
	return bytes.Equal(got, want)
}
func TestADRecoveryPacketUTF16A267(t *testing.T) {
	for _, password := range [][]byte{[]byte("Tr5!owned-café-密碼-🙂"), []byte("Tr5!owned-\"-\\-password"), []byte("Tr5!owned-�-password"), nil, []byte("short"), bytes.Repeat([]byte{'A'}, 1025), append(bytes.Repeat([]byte{'A'}, 16), 0), append(bytes.Repeat([]byte{'A'}, 16), 255)} {
		if !checkADRecoveryPacket(password) {
			t.Fatal("UTF-16 recovery encoding or rejection differs from reference")
		}
	}
	if err := quick.Check(func(value string) bool {
		return checkADRecoveryPacket(append([]byte("Tr5!owned-property-"), []byte(value)...))
	}, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatal(err)
	}
}
func FuzzADRecoveryPacketA267(f *testing.F) {
	f.Add([]byte("Tr5!owned-café-密碼-🙂"))
	f.Add([]byte("Tr5!owned-password"))
	f.Add([]byte{0, 255})
	f.Fuzz(func(t *testing.T, password []byte) {
		if !checkADRecoveryPacket(password) {
			t.Fatal("bounded UTF-16 recovery encoding differs from reference")
		}
	})
}
