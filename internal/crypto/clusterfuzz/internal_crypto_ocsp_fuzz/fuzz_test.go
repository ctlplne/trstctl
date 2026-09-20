// SPDX-License-Identifier: BUSL-1.1

package clusterfuzz

import (
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// FuzzParseOCSPRequestSerial hardens the public OCSP responder's ASN.1 request
// parser. /ocsp/{tenant} accepts attacker-supplied DER and routes it through
// crypto.ParseOCSPRequestSerial; no malformed input may panic, and parse failures
// must stay classified as ErrMalformedOCSPRequest so the served HTTP path can
// return a client-fault status instead of an internal responder error.
func FuzzParseOCSPRequestSerial(f *testing.F) {
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		f.Fatal(err)
	}
	defer signer.Destroy()
	issuerDER, err := crypto.SelfSignedCACert(signer, "ocsp fuzz issuer", time.Hour)
	if err != nil {
		f.Fatal(err)
	}
	validReqDER, err := crypto.BuildOCSPRequestForSerial(issuerDER, "a1b2c3d4e5f6")
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte(nil))
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00})
	f.Add([]byte{0x30, 0x84, 0x00, 0x00})
	f.Add([]byte("not an ocsp request"))
	f.Add(validReqDER)

	f.Fuzz(func(t *testing.T, reqDER []byte) {
		validatedSerial, validateErr := crypto.ValidateOCSPRequestForIssuer(reqDER, issuerDER)
		if validateErr != nil && !errors.Is(validateErr, crypto.ErrMalformedOCSPRequest) {
			t.Fatalf("ValidateOCSPRequestForIssuer error = %v, want ErrMalformedOCSPRequest-wrapped error", validateErr)
		}
		if validateErr == nil && validatedSerial == "" {
			t.Fatal("ValidateOCSPRequestForIssuer returned empty serial with nil error")
		}
		serial, err := crypto.ParseOCSPRequestSerial(reqDER)
		if err != nil {
			if !errors.Is(err, crypto.ErrMalformedOCSPRequest) {
				t.Fatalf("ParseOCSPRequestSerial error = %v, want ErrMalformedOCSPRequest-wrapped error", err)
			}
			return
		}
		if serial == "" {
			t.Fatal("ParseOCSPRequestSerial returned empty serial with nil error")
		}
	})
}
