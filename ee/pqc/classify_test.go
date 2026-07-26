// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqc

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/profile"
)

func TestClassifyAlgorithmCoversEveryLicensedFamily(t *testing.T) {
	cases := []struct {
		alg    crypto.Algorithm
		family string
		kind   string
	}{
		{MLDSA44, "ML-DSA", "signature"},
		{MLDSA65, "ML-DSA", "signature"},
		{MLDSA87, "ML-DSA", "signature"},
		{MLKEM512, "ML-KEM", "kem"},
		{MLKEM768, "ML-KEM", "kem"},
		{MLKEM1024, "ML-KEM", "kem"},
		{SLHDSA128s, "SLH-DSA", "signature"},
		{SLHDSA128f, "SLH-DSA", "signature"},
		{SLHDSA192s, "SLH-DSA", "signature"},
		{SLHDSA256s, "SLH-DSA", "signature"},
		{HybridEd25519Dilithium3, "Hybrid", "signature"},
		{crypto.Algorithm(HybridMLDSA44ECDSAP256Algorithm), "Hybrid", "signature"},
	}
	for _, tc := range cases {
		c, ok := ClassifyAlgorithm(tc.alg)
		if !ok {
			t.Fatalf("ClassifyAlgorithm(%s) not recognized", tc.alg)
		}
		if c.Family != tc.family || c.Kind != tc.kind || !c.PostQuantum || c.QuantumVulnerable {
			t.Fatalf("ClassifyAlgorithm(%s) = %+v, want family=%s kind=%s post-quantum, not quantum-vulnerable", tc.alg, c, tc.family, tc.kind)
		}
	}
	for _, classical := range []crypto.Algorithm{crypto.RSA2048, crypto.ECDSAP256, crypto.Ed25519, "FROBNICATE"} {
		if _, ok := ClassifyAlgorithm(classical); ok {
			t.Fatalf("ClassifyAlgorithm(%s) claimed a non-licensed algorithm", classical)
		}
	}
}

// TestProfileLabelsValidateWithLicensedClassifier proves the A0.3b seam end to
// end: with the licensed classifier installed (as attachPQC does), a
// certificate profile naming pure and hybrid post-quantum signature labels
// passes authoring validation, a pure ML-DSA issuance request matches its
// exact label at enforcement time, and a KEM label still fails authoring
// because it cannot sign certificates.
func TestProfileLabelsValidateWithLicensedClassifier(t *testing.T) {
	crypto.InstallLicensedAlgorithmClassifier(ClassifyAlgorithm)

	spec := map[string]any{
		"name":    "pq-web",
		"version": 1,
		"allowed_key_algorithms": []string{
			string(MLDSA65),
			HybridMLDSA44ECDSAP256Algorithm,
			"ECDSA",
		},
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := profile.ValidateSpec(raw); err != nil {
		t.Fatalf("ValidateSpec with licensed labels: %v", err)
	}

	var p profile.CertificateProfile
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(profile.Request{KeyAlgorithm: string(MLDSA65), Protocol: "est"}); err != nil {
		t.Fatalf("pure ML-DSA request against its exact label: %v", err)
	}
	if err := p.Validate(profile.Request{KeyAlgorithm: "ECDSA", KeyBits: 256, Protocol: "cmp"}); err != nil {
		t.Fatalf("classical (and hybrid-carrying) request against ECDSA label: %v", err)
	}
	if err := p.Validate(profile.Request{KeyAlgorithm: "RSA", KeyBits: 2048}); err == nil {
		t.Fatal("RSA request must still be refused by a profile that does not list it")
	}

	kemSpec, err := json.Marshal(map[string]any{
		"name": "bad", "version": 1,
		"allowed_key_algorithms": []string{string(MLKEM768)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := profile.ValidateSpec(kemSpec); err == nil {
		t.Fatal("a KEM label must fail profile authoring: it is not a certificate signing algorithm")
	}
}
