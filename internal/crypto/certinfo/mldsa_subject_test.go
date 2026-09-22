// SPDX-License-Identifier: BUSL-1.1
package certinfo

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

func inventorySPKI(t testing.TB, oid asn1.ObjectIdentifier, size int, params asn1.RawValue, padding int) []byte {
	t.Helper()
	raw, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{pkix.AlgorithmIdentifier{Algorithm: oid, Parameters: params}, asn1.BitString{Bytes: make([]byte, size), BitLength: size*8 - padding}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestMLDSAInventoryRejectsMalformedRecognizedKeys(t *testing.T) {
	for _, test := range []struct {
		last, size int
		want       string
	}{{17, 1312, "ML-DSA-44"}, {18, 1952, "ML-DSA-65"}, {19, 2592, "ML-DSA-87"}} {
		t.Run(test.want, func(t *testing.T) {
			oid := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, test.last}
			valid := inventorySPKI(t, oid, test.size, asn1.RawValue{}, 0)
			if got, err := inspectMLDSASubject(valid); err != nil || got != test.want {
				t.Fatalf("valid key=%q err=%v", got, err)
			}
			for name, raw := range map[string][]byte{
				"short":           inventorySPKI(t, oid, test.size-1, asn1.RawValue{}, 0),
				"long":            inventorySPKI(t, oid, test.size+1, asn1.RawValue{}, 0),
				"padding":         inventorySPKI(t, oid, test.size, asn1.RawValue{}, 1),
				"null-parameters": inventorySPKI(t, oid, test.size, asn1.NullRawValue, 0),
				"trailing":        append(append([]byte(nil), valid...), 0),
			} {
				t.Run(name, func(t *testing.T) {
					if got, err := inspectMLDSASubject(raw); err == nil || got != "" {
						t.Fatalf("malformed key became %q: %v", got, err)
					}
				})
			}
		})
	}
	unknown := inventorySPKI(t, asn1.ObjectIdentifier{1, 2, 3, 4, 5}, 1312, asn1.RawValue{}, 0)
	if got, err := inspectMLDSASubject(unknown); err != nil || got != "" {
		t.Fatalf("unknown OID inferred from size: %q %v", got, err)
	}
}
func FuzzMLDSASubjectInventory(f *testing.F) {
	for _, test := range []struct{ last, size int }{{17, 1312}, {18, 1952}, {19, 2592}} {
		oid := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, test.last}
		f.Add(inventorySPKI(f, oid, test.size, asn1.RawValue{}, 0))
		f.Add(inventorySPKI(f, oid, test.size, asn1.NullRawValue, 0))
	}
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, err := inspectMLDSASubject(raw)
		if err != nil && got != "" {
			t.Fatal("rejected input retained an algorithm label")
		}
		if got != "" && got != "ML-DSA-44" && got != "ML-DSA-65" && got != "ML-DSA-87" {
			t.Fatalf("unregistered label %q", got)
		}
	})
}
