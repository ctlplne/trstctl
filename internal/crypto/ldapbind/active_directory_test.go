// SPDX-License-Identifier: BUSL-1.1
package ldapbind

import (
	"bytes"
	"github.com/go-asn1-ber/asn1-ber"
	"testing"
)

func TestADPasswordPacketIsBoundedUTF16AndWiped(t *testing.T) {
	password := []byte("Tr5!owned-password-0123456789")
	packet, err := newADPasswordPacket("CN=owned,OU=proof,DC=example,DC=test", password)
	if err != nil {
		t.Fatal(err)
	}
	wire := packet.Bytes()
	decoded, err := ber.DecodePacketErr(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Children) != 2 || decoded.Children[0].Value != int64(2) || decoded.Children[1].Tag != 6 {
		t.Fatal("not an LDAP ModifyRequest")
	}
	operation := decoded.Children[1]
	if len(operation.Children) != 2 || len(operation.Children[1].Children) != 1 {
		t.Fatal("not one modification")
	}
	change := operation.Children[1].Children[0]
	if change.Children[0].Value != int64(2) {
		t.Fatal("not a replace")
	}
	attribute := change.Children[1]
	if attribute.Children[0].Value != "unicodePwd" {
		t.Fatal("not unicodePwd")
	}
	got := attribute.Children[1].Children[0].Data.Bytes()
	want := make([]byte, (len(password)+2)*2)
	want[0] = '"'
	for i, v := range password {
		want[2+i*2] = v
	}
	want[len(want)-2] = '"'
	if !bytes.Equal(got, want) {
		t.Fatal("password is not quoted UTF-16LE")
	}
	packet.Destroy()
	for _, v := range wire {
		if v != 0 {
			t.Fatal("locked wire retained material")
		}
	}
	for _, raw := range [][]byte{nil, []byte("short"), bytes.Repeat([]byte{'A'}, 1025), append(bytes.Repeat([]byte{'A'}, 16), 0), append(bytes.Repeat([]byte{'A'}, 16), 255)} {
		if p, e := newADPasswordPacket("CN=owned", raw); e == nil {
			p.Destroy()
			t.Fatal("unsafe password accepted")
		}
	}
}

func FuzzADPasswordPacket(f *testing.F) {
	f.Add("CN=owned,DC=example,DC=test", []byte("Tr5!owned-fuzz-password"))
	f.Fuzz(func(t *testing.T, dn string, password []byte) {
		p, err := newADPasswordPacket(dn, password)
		if err != nil {
			return
		}
		defer p.Destroy()
		if len(p.Bytes()) > 16<<10 {
			t.Fatal("unbounded AD wire")
		}
		if _, err := ber.DecodePacketErr(p.Bytes()); err != nil {
			t.Fatal("encoder produced invalid BER")
		}
	})
}
