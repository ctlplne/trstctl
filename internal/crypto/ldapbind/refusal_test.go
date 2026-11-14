// SPDX-License-Identifier: BUSL-1.1
package ldapbind

import (
	"errors"
	"testing"
)

// bindReply is an LDAP BindResponse frame for message 1 with result code and
// diagnostic message.
func bindReply(code byte, diagnostic string) []byte {
	result := append([]byte{0x0a, 0x01, code}, tlv(0x04, nil)...)
	result = append(result, tlv(0x04, []byte(diagnostic))...)
	return tlv(0x30, append([]byte{0x02, 0x01, 0x01}, tlv(0x61, result)...))
}

// A258-L1: a refused bind carries Active Directory's sub-status from the
// diagnostic message, and only that; the error text is unchanged.
func TestBindRefusalCarriesTheADSubStatusA258L1(t *testing.T) {
	for _, tc := range []struct {
		name       string
		code       byte
		diagnostic string
		want       uint32
	}{
		{"wrong password", 49, "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e, v4563", 0x52e},
		{"locked", 49, "80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 775, v1db1", 0x775},
		{"password expired", 49, "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 532, v4563", 0x532},
		{"must change", 49, "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 773, v4563", 0x773},
		{"at the end", 49, "AcceptSecurityContext error, data 701", 0x701},
		{"upper case", 49, "AcceptSecurityContext error, data 52E, v4563", 0x52e},
		{"no sub-status", 49, "Invalid credentials", 0},
		{"not a word", 49, "metadata 52e, v1", 0},
		{"not hexadecimal", 49, "AcceptSecurityContext error, data 5z2, v1", 0},
		{"too long", 49, "AcceptSecurityContext error, data 123456789, v1", 0},
		{"empty", 49, "AcceptSecurityContext error, data , v1", 0},
		{"other result", 53, "00002035: LdapErr: DSID-0C090D8A, comment: Operation not allowed through GC port, data 0, v4563", 0},
	} {
		err := parseLDAPResult(bindReply(tc.code, tc.diagnostic), 1, 0x61)
		var refusal *RefusalError
		if !errors.As(err, &refusal) || refusal.Result != tc.code || refusal.ADData != tc.want {
			t.Fatalf("%s: %#v, want result %d sub-status %#x", tc.name, err, tc.code, tc.want)
		}
		if got := err.Error(); got != "LDAP operation was refused (result "+map[byte]string{49: "49", 53: "53"}[tc.code]+")" {
			t.Fatalf("%s: the error reads %q", tc.name, got)
		}
	}
	if err := parseLDAPResult(bindReply(0, "data 52e"), 1, 0x61); err != nil {
		t.Fatalf("a successful bind refused: %v", err)
	}
}
