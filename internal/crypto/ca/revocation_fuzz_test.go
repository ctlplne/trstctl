// SPDX-License-Identifier: MPL-2.0

package ca

import (
	"testing"
)

// FuzzParseOCSPRequestSerial drives arbitrary DER through the OCSP-request
// serial extractor, which runs on attacker-controlled bytes at the served
// /ocsp endpoint. It must fail closed (an error) rather than panic, and a
// nil-error parse must yield a non-empty serial (no silent empty success).
func FuzzParseOCSPRequestSerial(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("not der"))
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})

	f.Fuzz(func(t *testing.T, der []byte) {
		serial, err := ParseOCSPRequestSerial(der)
		if err == nil && serial == "" {
			t.Fatal("ParseOCSPRequestSerial returned a nil error but an empty serial")
		}
	})
}

// FuzzParseOCSPResponse drives arbitrary bytes through the OCSP-response parser
// (untrusted upstream responder bytes). It must never panic; both arguments are
// attacker-influenced.
func FuzzParseOCSPResponse(f *testing.F) {
	f.Add([]byte(""), []byte(""))
	f.Add([]byte{0x30, 0x03}, []byte{0x30, 0x03})

	f.Fuzz(func(t *testing.T, respDER, issuerDER []byte) {
		_, _ = ParseOCSPResponse(respDER, issuerDER)
	})
}

// FuzzParseCRL drives arbitrary DER through the CRL parser (untrusted CRL
// distribution-point bytes). It must never panic; a nil-error parse must not
// invert the update window (NextUpdate before ThisUpdate is a malformed CRL a
// parser must reject, not surface as a valid window).
func FuzzParseCRL(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("not a crl"))
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})

	f.Fuzz(func(t *testing.T, der []byte) {
		info, err := ParseCRL(der)
		if err != nil {
			return
		}
		if !info.NextUpdate.IsZero() && info.NextUpdate.Before(info.ThisUpdate) {
			t.Fatalf("ParseCRL accepted a CRL whose NextUpdate (%s) precedes ThisUpdate (%s)", info.NextUpdate, info.ThisUpdate)
		}
	})
}
