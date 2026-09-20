// SPDX-License-Identifier: LicenseRef-trstctl-EE

package clusterfuzz

import (
	"testing"

	"trstctl.com/trstctl/internal/agentid/delegation/carriage"
)

// fail-closed: an error and no usable value is the acceptable outcome.

// A successful decode must be self-consistent: re-deriving its canonical digest must
// not panic and must be stable (idempotent), proving the decoded value is a complete,
// usable BoundValues rather than a partially-filled struct.

// empty ASN.1 SEQUENCE
// bogus long-form length

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

func FuzzX509Decoder(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte("not-a-cert"))
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x82, 0xff, 0xff})
	dec := carriage.X509Decoder{}
	f.Fuzz(func(t *testing.T, certDER []byte) {
		checkNoPanicFailClosed(t, dec, certDER)
	})
}

func checkNoPanicFailClosed(t *testing.T, dec carriage.Decoder, in []byte) {
	t.Helper()
	bv, err := dec.Decode(in)
	if err != nil {
		return
	}

	d1 := bv.CarriageDigest()
	d2 := bv.Clone().CarriageDigest()
	if string(d1) != string(d2) {
		t.Fatalf("%s: decoded value is not self-consistent (clone digest differs)", dec.Kind())
	}
}
