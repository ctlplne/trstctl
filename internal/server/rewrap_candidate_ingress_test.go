// SPDX-License-Identifier: BUSL-1.1
package server

import "testing"

func TestSealedIngressClassifierDistinguishesCiphertextFromMetadata(t *testing.T) {
	for _, payload := range []string{
		`{"sealed_at":"2026-11-20T00:00:00Z"}`,
		`{"sealed_sha256":"plain-digest"}`,
		`{"sealed_only_floor":true}`,
	} {
		if hasUnclassifiedSealedIngressField([]byte(payload)) {
			t.Errorf("public sealed metadata was treated as ciphertext: %s", payload)
		}
	}
	for _, payload := range []string{
		`{"sealed":"opaque-value"}`,
		`{"nested":{"sealed_preparation":"opaque-value"}}`,
		`{"nested":{"sealed_future":"opaque-value"}}`,
	} {
		if !hasUnclassifiedSealedIngressField([]byte(payload)) {
			t.Errorf("ciphertext field escaped classification: %s", payload)
		}
	}
}
