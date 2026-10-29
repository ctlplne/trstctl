// SPDX-License-Identifier: BUSL-1.1
package ldapbind

import (
	"bytes"
	"strings"
	"testing"
)

func TestBindPacketKeepsPasswordInDestroyableBytes(t *testing.T) {
	password := []byte("owned-disposable-bind-fixture")
	packet, err := newBindPacket(1, "CN=Reader,DC=example", password)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(packet.Bytes(), password) {
		t.Fatal("bind omitted its byte-backed authentication value")
	}
	if packet.Bytes()[0] != 0x30 {
		t.Fatal("bind has no LDAP message envelope")
	}
	packet.Destroy()
	if packet.Bytes() != nil {
		t.Fatal("bind retained its locked authentication envelope")
	}
}
func TestLDAPResultBindsMessageAndWithholdsDiagnostics(t *testing.T) {
	good := []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}
	if err := parseLDAPResult(good, 1, 0x61); err != nil {
		t.Fatal(err)
	}
	if err := parseLDAPResult(good, 2, 0x61); err == nil {
		t.Fatal("reply to a different operation accepted")
	}
	diagnostic := []byte("private-server-diagnostic")
	body := append([]byte{0x0a, 0x01, 49, 0x04, 0}, tlv(0x04, diagnostic)...)
	refused := tlv(0x30, append([]byte{0x02, 0x01, 0x01}, tlv(0x61, body)...))
	if err := parseLDAPResult(refused, 1, 0x61); err == nil || strings.Contains(err.Error(), string(diagnostic)) {
		t.Fatalf("bind refusal missing or diagnostic escaped: %v", err)
	}
}
func TestLDAPFrameRejectsOversizeAndIndefiniteLength(t *testing.T) {
	for _, raw := range [][]byte{{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff}, {0x30, 0x80}, {0x31, 0x01, 0}} {
		if _, err := readLDAPFrame(bytes.NewReader(raw), 64<<10); err == nil {
			t.Fatal("unbounded or invalid LDAP frame accepted")
		}
	}
}
func FuzzLDAPBindResponse(f *testing.F) {
	f.Add([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = readLDAPFrame(bytes.NewReader(raw), 64<<10)
		_ = parseLDAPResult(raw, 1, 0x61)
	})
}
