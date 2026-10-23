// SPDX-License-Identifier: BUSL-1.1

package cbom

import (
	"strings"
	"testing"
)

// Part 4: a source's weak-key reasons or distrusted issuer make a key weak and
// out of policy whatever its family and size, with the reasons and the
// replacement path; a key without them classifies as before.
func TestClassifyRatesKeysTheSourceFoundWeak(t *testing.T) {
	p := DefaultPolicy()
	plain := Classify(Finding{Kind: AssetCertKey, Algorithm: "ECDSA", KeyBits: 384}, p)
	if plain.Strength != StrengthAcceptable || plain.OutOfPolicy || !plain.QuantumVulnerable {
		t.Fatalf("plain P-384: %+v", plain)
	}
	weak := Classify(Finding{Kind: AssetCertKey, Algorithm: "ECDSA", KeyBits: 384, KeyWeakReasons: []string{"the P-384 public key is 4·G: its private key is 4, which anyone can recover"}}, p)
	if weak.Strength != StrengthWeak || !weak.OutOfPolicy || !strings.Contains(strings.Join(weak.Reasons, "|"), "weak key: the P-384 public key is 4·G") || !strings.Contains(strings.Join(weak.Reasons, "|"), "/api/v1/pqc/migrations/plan") {
		t.Fatalf("weak P-384: %+v", weak)
	}
	distrusted := Classify(Finding{Kind: AssetCertKey, Algorithm: "RSA", KeyBits: 4096, KeyDistrust: "the certificate depends on EM OV TLS CA - G3C, which is on the distrust list (chain)"}, p)
	if distrusted.Strength != StrengthWeak || !strings.Contains(strings.Join(distrusted.Reasons, "|"), "EM OV TLS CA - G3C") {
		t.Fatalf("distrusted RSA-4096: %+v", distrusted)
	}
}
