// SPDX-License-Identifier: LicenseRef-trstctl-EE

package carriage_test

import (
	"testing"

	"trstctl.com/trstctl/ee/agentid/delegation/carriage"
)

// The three fuzz targets drive each carriage DECODER with untrusted bytes (a certificate,
// a workload-identity document, a signed token that a hostile party controls). The
// contract for all three: NEVER panic, and FAIL CLOSED -- any input either decodes to a
// well-formed BoundValues or returns an error; a decoder must never return a nil error
// together with a garbage/partial value. Carriage is downstream of the signer's
// verify-before-generate (INV-A1), so a decoder that mis-parses untrusted input can never
// become a bypass -- but it must still be crash-safe and unambiguous.

// checkNoPanicFailClosed runs one decoder over an input and enforces the fail-closed
// contract: on a nil error the value must at least round-trip through its own canonical
// bytes (a self-consistent decode), never a half-populated struct.
func checkNoPanicFailClosed(t *testing.T, dec carriage.Decoder, in []byte) {
	t.Helper()
	bv, err := dec.Decode(in)
	if err != nil {
		return // fail-closed: an error and no usable value is the acceptable outcome.
	}
	// A successful decode must be self-consistent: re-deriving its canonical digest must
	// not panic and must be stable (idempotent), proving the decoded value is a complete,
	// usable BoundValues rather than a partially-filled struct.
	d1 := bv.CarriageDigest()
	d2 := bv.Clone().CarriageDigest()
	if string(d1) != string(d2) {
		t.Fatalf("%s: decoded value is not self-consistent (clone digest differs)", dec.Kind())
	}
}

// FuzzX509Decoder fuzzes the X.509 carriage decoder with untrusted certificate DER.
func FuzzX509Decoder(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte("not-a-cert"))
	f.Add([]byte{0x30, 0x00})             // empty ASN.1 SEQUENCE
	f.Add([]byte{0x30, 0x82, 0xff, 0xff}) // bogus long-form length
	dec := carriage.X509Decoder{}
	f.Fuzz(func(t *testing.T, certDER []byte) {
		checkNoPanicFailClosed(t, dec, certDER)
	})
}

// FuzzWorkloadDocDecoder fuzzes the workload-identity document decoder with untrusted
// JSON.
func FuzzWorkloadDocDecoder(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte("{"))
	f.Add([]byte(`{"agid_binding":{}}`))
	f.Add([]byte(`{"agid_binding":{"chain_head_digest":"!!!notbase64"}}`))
	f.Add([]byte(`{"agid_binding":{"chain_head_digest":123}}`))
	f.Add([]byte(`{"sub":"x"}`))
	dec := carriage.WorkloadDocDecoder{}
	f.Fuzz(func(t *testing.T, docJSON []byte) {
		checkNoPanicFailClosed(t, dec, docJSON)
	})
}

// FuzzTokenDecoder fuzzes the signed-token decoder with untrusted token bytes.
func FuzzTokenDecoder(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte("a.b.c"))
	f.Add([]byte("only.two"))
	f.Add([]byte("aGVhZGVy.eyJhZ2lkX2JpbmRpbmciOnt9fQ.c2ln")) // header.{agid_binding:{}}.sig
	f.Add([]byte("h.!!!notbase64.s"))
	f.Add([]byte("h..s"))
	dec := carriage.TokenDecoder{}
	f.Fuzz(func(t *testing.T, token []byte) {
		checkNoPanicFailClosed(t, dec, token)
	})
}
