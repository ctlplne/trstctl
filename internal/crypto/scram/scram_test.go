// SPDX-License-Identifier: BUSL-1.1

package scram

import "testing"

// RFC 7677 section 3's example exchange (user "user", password "pencil").
func TestSCRAMSHA256MatchesRFC7677(t *testing.T) {
	c := New("user", []byte("pencil"), "rOprNGfwEbeRWgbNEkqO")
	if got := string(c.First()); got != "n,,n=user,r=rOprNGfwEbeRWgbNEkqO" {
		t.Fatalf("client-first = %q", got)
	}
	final, err := c.Final([]byte("r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="; string(final) != want {
		t.Fatalf("client-final = %q, want %q", final, want)
	}
	if err := c.Verify([]byte("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")); err != nil {
		t.Fatalf("server signature: %v", err)
	}
	if err := c.Verify([]byte("v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")); err == nil {
		t.Fatal("a wrong server signature was accepted")
	}
	if _, err := New("", []byte("pencil"), "abc").Final([]byte("r=xyz,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")); err == nil {
		t.Fatal("a server nonce that does not extend the client's was accepted")
	}
}

// A SASL user name escapes '=' and ',' (RFC 5802 section 5.1).
func TestUserNameIsEscaped(t *testing.T) {
	if got := string(New("a=b,c", nil, "n").First()); got != "n,,n=a=3Db=2Cc,r=n" {
		t.Fatalf("client-first = %q", got)
	}
}
