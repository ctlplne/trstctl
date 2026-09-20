// SPDX-License-Identifier: BUSL-1.1

package cbomposture

import (
	"testing"

	"trstctl.com/trstctl/internal/cbom"
	pqc "trstctl.com/trstctl/internal/pqc"
)

func TestCBOMTargetForNamesFIPSReplacements(t *testing.T) {
	cases := []struct {
		name    string
		finding cbom.Finding
		wantAlg string
		wantStd string
		wantGen string
		wantOK  bool
	}{
		{"rsa key", cbom.Finding{Algorithm: "RSA", KeyBits: 2048}, "ML-DSA-65", "FIPS 204", cbom.GenerationMigrationRequired, true},
		{"ecdsa curve label", cbom.Finding{Algorithm: "ECDSA P-256"}, "ML-DSA-65", "FIPS 204", cbom.GenerationMigrationRequired, true},
		{"ed25519", cbom.Finding{Algorithm: "Ed25519"}, "ML-DSA-65", "FIPS 204", cbom.GenerationMigrationRequired, true},
		{"deprecated dsa", cbom.Finding{Algorithm: "DSA"}, "SLH-DSA-SHA2-128s", "FIPS 205", cbom.GenerationMigrationRequired, true},
		{"tls protocol", cbom.Finding{Protocol: "TLSv1.2"}, "ML-KEM-768", "FIPS 203", cbom.GenerationMigrationRequired, true},
		{"cipher", cbom.Finding{Cipher: "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}, "ML-KEM-768", "FIPS 203", cbom.GenerationMigrationRequired, true},
		{"pure ml-dsa is future-ready", cbom.Finding{Algorithm: "ML-DSA-65"}, "ML-DSA-65", "FIPS 204", cbom.GenerationFutureReady, true},
		{"dilithium alias", cbom.Finding{Algorithm: "Dilithium3"}, "Dilithium3", "FIPS 204", cbom.GenerationFutureReady, true},
		{"ml-kem is future-ready", cbom.Finding{Algorithm: "ML-KEM-768"}, "ML-KEM-768", "FIPS 203", cbom.GenerationFutureReady, true},
		{"slh-dsa is future-ready", cbom.Finding{Algorithm: "SLH-DSA-SHA2-128s"}, "SLH-DSA-SHA2-128s", "FIPS 205", cbom.GenerationFutureReady, true},
		{"sphincs alias", cbom.Finding{Algorithm: "SPHINCS+-SHA2-128s"}, "SPHINCS+-SHA2-128s", "FIPS 205", cbom.GenerationFutureReady, true},
		{"hybrid stays transitional", cbom.Finding{Algorithm: string(pqc.HybridMLDSA44ECDSAP256Algorithm)}, "ML-DSA-65", "FIPS 204", cbom.GenerationMigrationRequired, true},
		{"unknown label falls back to core", cbom.Finding{Algorithm: "FROBNICATE-9000"}, "", "", "", false},
		{"empty finding falls back to core", cbom.Finding{}, "", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := CBOMTargetFor(tc.finding)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if got.Algorithm != tc.wantAlg || got.Standard != tc.wantStd || got.Generation != tc.wantGen {
				t.Fatalf("target = %+v, want {%s %s %s}", got, tc.wantAlg, tc.wantStd, tc.wantGen)
			}
		})
	}
}

func TestCBOMClassifyKeyRecognizesPostQuantumFamilies(t *testing.T) {
	for _, alg := range []string{
		string(pqc.MLDSA44), string(pqc.MLDSA65), string(pqc.MLDSA87),
		string(pqc.MLKEM512), string(pqc.MLKEM768), string(pqc.MLKEM1024),
		string(pqc.SLHDSA128s), string(pqc.SLHDSA256s),
		"Dilithium3", "Kyber768", "SPHINCS+-SHA2-128s",
	} {
		c, ok := CBOMClassifyKey(alg, 0)
		if !ok {
			t.Fatalf("CBOMClassifyKey(%q) not recognized", alg)
		}
		if c.QuantumVulnerable {
			t.Fatalf("CBOMClassifyKey(%q) marked quantum-vulnerable", alg)
		}
		if c.Strength != cbom.StrengthStrong {
			t.Fatalf("CBOMClassifyKey(%q) strength = %s, want strong", alg, c.Strength)
		}
		if c.OutOfPolicy {
			t.Fatalf("CBOMClassifyKey(%q) marked out of policy", alg)
		}
	}

	hybrid, ok := CBOMClassifyKey(string(pqc.HybridEd25519Dilithium3), 0)
	if !ok || hybrid.QuantumVulnerable {
		t.Fatalf("hybrid label: ok=%v class=%+v, want recognized and not quantum-vulnerable", ok, hybrid)
	}

	for _, classical := range []string{"RSA", "ECDSA P-256", "Ed25519", "DSA", "FROBNICATE-9000", ""} {
		if _, ok := CBOMClassifyKey(classical, 2048); ok {
			t.Fatalf("CBOMClassifyKey(%q) claimed a non-PQC label", classical)
		}
	}
}

// TestProgressCountsLicensedFutureReady proves the served rollup moves off zero
// once the licensed posture is installed: a mixed classical + post-quantum
// estate reports the post-quantum share as migrated.
func TestProgressCountsLicensedFutureReady(t *testing.T) {
	cbom.InstallLicensedPosture(CBOMTargetFor, CBOMClassifyKey)

	policy := cbom.DefaultPolicy()
	findings := []cbom.Finding{
		cbom.Finding{Kind: cbom.AssetCertKey, Location: "a", Algorithm: "RSA", KeyBits: 2048}.Classified(policy),
		cbom.Finding{Kind: cbom.AssetCertKey, Location: "b", Algorithm: string(pqc.MLDSA65)}.Classified(policy),
		cbom.Finding{Kind: cbom.AssetTLSEndpoint, Location: "c", Protocol: "TLSv1.2"}.Classified(policy),
		cbom.Finding{Kind: cbom.AssetCertKey, Location: "d", Algorithm: string(pqc.HybridMLDSA44ECDSAP256Algorithm)}.Classified(policy),
	}

	p := cbom.ProgressFor(findings)
	if p.TotalAssets != 4 {
		t.Fatalf("TotalAssets = %d, want 4", p.TotalAssets)
	}
	if p.PostQuantumReadyAssets != 1 {
		t.Fatalf("PostQuantumReadyAssets = %d, want 1 (pure ML-DSA only; hybrid stays transitional)", p.PostQuantumReadyAssets)
	}
	if p.PercentMigrated != 25 {
		t.Fatalf("PercentMigrated = %v, want 25", p.PercentMigrated)
	}
	// The licensed classifier ran at Classified time: only the classical RSA
	// key is quantum-vulnerable; the ML-DSA and hybrid keys are not.
	if p.QuantumVulnerableAssets != 1 {
		t.Fatalf("QuantumVulnerableAssets = %d, want 1", p.QuantumVulnerableAssets)
	}

	// Migration targets carry the FIPS names end to end.
	rsaTarget := cbom.MigrationTargetFor(findings[0])
	if rsaTarget.Algorithm != string(pqc.MLDSA65) || rsaTarget.Standard != "FIPS 204" {
		t.Fatalf("RSA target = %+v, want ML-DSA-65 / FIPS 204", rsaTarget)
	}
	pqTarget := cbom.MigrationTargetFor(findings[1])
	if pqTarget.Generation != cbom.GenerationFutureReady {
		t.Fatalf("ML-DSA target generation = %s, want future-ready", pqTarget.Generation)
	}
}
