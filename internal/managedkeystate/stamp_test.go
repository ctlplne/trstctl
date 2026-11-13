// SPDX-License-Identifier: BUSL-1.1

package managedkeystate

import "testing"

// A168-L4: the stamp a provider adapter puts on the key an operation creates
// is SHA-256 over kind, operation id, the replaced key and algorithm, and the
// fingerprint every provider carries is its first 48 hex characters. The
// vector was checked independently (shasum -a 256 over the same bytes).
func TestOperationStampIsTheProvidersDigestA168L4(t *testing.T) {
	const want = "7ec1f3e0702a9762171cfa3c76ced57e81d6e7899f8dcae23d6a8f3a450b2146"
	if got := OperationStamp("generate", "managedkey:a168l4", "", "ECDSA-P256"); got != want {
		t.Fatalf("stamp = %s, want %s", got, want)
	}
	if got := OperationFingerprint("generate", "managedkey:a168l4", "", "ECDSA-P256"); got != want[:OperationFingerprintLen] || len(got) != 48 {
		t.Fatalf("fingerprint = %s", got)
	}
	if OperationStamp("rotate", "managedkey:a168l4", "key-1", "ECDSA-P256") == want {
		t.Fatal("a rotation stamped like a generate")
	}
}
