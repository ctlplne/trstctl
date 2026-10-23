// SPDX-License-Identifier: BUSL-1.1

package trust

import (
	"bytes"
	"testing"
)

// The three parsers here take attacker-influenced bytes: an operator's distrust
// file, a trust bundle from an image build input, and an Alpine package. Each
// must fail closed on malformed input and never panic (TEST-FUZZASSERT-001).

func FuzzParse(f *testing.F) {
	f.Add(shippedJSON)
	f.Add([]byte(`{"schema":1,"updated":"2026-10-23","entries":[]}`))
	f.Add([]byte(`{"schema":1,"entries":[{"name":"x","kind":"root","spki_sha256":"` + string(bytes.Repeat([]byte("a"), 64)) + `","reason":"r","sources":["s"],"since":"2026-10-23"}]}`))
	f.Add([]byte(""))
	f.Add([]byte("{"))
	f.Add([]byte(`{"schema":2}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		l, err := Parse(data)
		if err != nil {
			if l != nil {
				t.Fatal("error with a non-nil list")
			}
			return
		}
		// Every accepted entry round-trips through the matcher.
		for _, e := range l.Entries() {
			if _, ok := l.MatchHashes(e.SPKISHA256, ""); !ok {
				t.Fatalf("accepted entry %q is not matchable by its own key", e.Name)
			}
		}
		if _, err := Shipped().Merge(l); err != nil {
			t.Fatalf("a parsed list did not merge: %v", err)
		}
	})
}

func FuzzFilterBundle(f *testing.F) {
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n"))
	f.Add([]byte("# comment\n-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"))
	f.Add([]byte(""))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := FilterBundle(data, Shipped())
		if err != nil {
			return
		}
		if res.Kept < 0 || res.Kept != len(res.KeptSubjects) {
			t.Fatalf("kept %d, subjects %d", res.Kept, len(res.KeptSubjects))
		}
		// The output is itself a bundle the filter accepts unchanged.
		again, err := FilterBundle(res.Bundle, Shipped())
		if err != nil || !bytes.Equal(again.Bundle, res.Bundle) {
			t.Fatalf("filter output is not a fixed point: %v", err)
		}
	})
}

func FuzzBundleFromAPK(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte{0x1f, 0x8b})
	f.Add([]byte("not gzip at all"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = BundleFromAPK(data)
	})
}
