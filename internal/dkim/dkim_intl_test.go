// SPDX-License-Identifier: BUSL-1.1

package dkim

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// P15-L4: an internationalized signing domain compares and looks up its key
// in A-labels, whichever form the From domain and the signature's d= are
// written in (RFC 8616 §4).
func TestDKIMComparesInternationalDomainsInALabelsP15L4(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	verifier := Verifier{Pinned: map[string]string{
		"lab._domainkey.xn--bcher-kva.example": "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(key.Public().DER)}}
	msg := []byte("From: alice@bücher.example\r\nTo: acme@ca.example\r\nSubject: Re: ACME: t\r\n\r\nbody\r\n")
	for _, signedAs := range []string{"xn--bcher-kva.example", "bücher.example"} {
		signed, err := Sign(msg, signedAs, "lab", []string{"From", "To", "Subject"}, key, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		for _, from := range []string{"bücher.example", "XN--BCHER-KVA.example", "Bücher.Example"} {
			if err := verifier.VerifyDomain(context.Background(), signed, from); err != nil {
				t.Fatalf("d=%s for From domain %s: %v", signedAs, from, err)
			}
		}
		if err := verifier.VerifyDomain(context.Background(), signed, "bucher.example"); err == nil {
			t.Fatalf("d=%s verified for a look-alike domain", signedAs)
		}
	}
}
