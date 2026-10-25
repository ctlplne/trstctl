// SPDX-License-Identifier: BUSL-1.1

package profile

import (
	"strings"
	"testing"
)

// Owner decision (batch 14): an unset min_rsa_bits means 2048. A profile may
// still set a lower floor explicitly.
func TestProfileUnsetRSAFloorIsTheDefault(t *testing.T) {
	unset := CertificateProfile{Name: "no-floor", Version: 1, AllowedKeyAlgorithms: []string{"RSA"}}
	err := unset.Validate(Request{KeyAlgorithm: "RSA", KeyBits: 1024})
	if err == nil || !strings.Contains(err.Error(), "2048") || !strings.Contains(err.Error(), "min_rsa_bits is unset") {
		t.Fatalf("an unset floor accepted RSA-1024 or did not name the default: %v", err)
	}
	if err := unset.Validate(Request{KeyAlgorithm: "RSA", KeyBits: 2048}); err != nil {
		t.Fatalf("an unset floor refused RSA-2048: %v", err)
	}
	explicit := CertificateProfile{Name: "legacy-floor", Version: 2, AllowedKeyAlgorithms: []string{"RSA"}, MinRSABits: 1024}
	if err := explicit.Validate(Request{KeyAlgorithm: "RSA", KeyBits: 1024}); err != nil {
		t.Fatalf("an explicit 1024-bit floor refused RSA-1024: %v", err)
	}
	if err := explicit.Validate(Request{KeyAlgorithm: "RSA", KeyBits: 768}); err == nil {
		t.Fatal("an explicit 1024-bit floor accepted RSA-768")
	}
	if unset.EffectiveMinRSABits() != DefaultMinRSABits || unset.BelowDefaultRSAFloor() || !explicit.BelowDefaultRSAFloor() ||
		(CertificateProfile{MinRSABits: 3072}).BelowDefaultRSAFloor() {
		t.Fatal("the posture check misreads the RSA floor")
	}
	negative := CertificateProfile{Name: "negative", Version: 1, MinRSABits: -1}
	if err := negative.ValidateDefinition(); err == nil {
		t.Fatal("a negative min_rsa_bits was accepted")
	}
}
