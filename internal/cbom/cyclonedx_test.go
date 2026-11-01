// SPDX-License-Identifier: BUSL-1.1

package cbom

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

var updateCycloneDXGolden = flag.Bool("update-cyclonedx-golden", false, "rewrite testdata/cyclonedx-export.golden.json")

// cycloneDXFixture covers every shape the export writes: certificate keys of
// each family it names (and one it does not), a weak key, TLS endpoints, and
// declared host protocol and cipher configuration.
func cycloneDXFixture() []CycloneDXAsset {
	return []CycloneDXAsset{
		{ID: "00000000-0000-4000-8000-000000000001", Kind: "certificate-key", Location: "api.example.test:443", Algorithm: "RSA", KeyBits: 2048,
			CertificateFingerprint: "ab12", Strength: "acceptable", QuantumVulnerable: true,
			Reasons: []string{"RSA is breakable by a cryptographically-relevant quantum computer"}, MigrationTarget: "ML-DSA-65"},
		{ID: "00000000-0000-4000-8000-000000000002", Kind: "certificate-key", Location: "web.example.test:443", Algorithm: "ECDSA", KeyBits: 256,
			Strength: "acceptable", QuantumVulnerable: true, MigrationTarget: "ML-DSA-44"},
		{ID: "00000000-0000-4000-8000-000000000003", Kind: "certificate-key", Location: "edge.example.test:8443", Algorithm: "Ed25519", KeyBits: 256,
			Strength: "acceptable", QuantumVulnerable: true},
		{ID: "00000000-0000-4000-8000-000000000004", Kind: "certificate-key", Location: "legacy.example.test:443", Algorithm: "RSA", KeyBits: 1024,
			Strength: "weak", QuantumVulnerable: true, OutOfPolicy: true, Reasons: []string{"RSA 1024-bit is below the 2048-bit minimum"}},
		{ID: "00000000-0000-4000-8000-000000000005", Kind: "certificate-key", Location: "pq.example.test:443", Algorithm: "ML-DSA-65", Strength: "strong"},
		{ID: "00000000-0000-4000-8000-000000000006", Kind: "certificate-key", Location: "old.example.test:443", Algorithm: "GOST", KeyBits: 256, Strength: "acceptable",
			Reasons: []string{"unrecognized algorithm GOST"}},
		{ID: "00000000-0000-4000-8000-000000000007", Kind: "tls-endpoint", Location: "api.example.test:443", Protocol: "TLSv1.3", Strength: "strong"},
		{ID: "00000000-0000-4000-8000-000000000008", Kind: "tls-endpoint", Location: "legacy.example.test:443", Protocol: "TLSv1.2", Strength: "acceptable"},
		{ID: "00000000-0000-4000-8000-000000000009", Kind: "host-config", Location: "/etc/ssl/openssl.cnf", Protocol: "TLSv1.0", Library: "openssl",
			Strength: "weak", OutOfPolicy: true, Reasons: []string{"TLSv1.0 is below the TLSv1.2 minimum"}},
		{ID: "00000000-0000-4000-8000-00000000000a", Kind: "host-config", Location: "/etc/nginx/nginx.conf", Cipher: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
			Library: "nginx", Strength: "weak", OutOfPolicy: true, Reasons: []string{"cipher contains banned primitive 3DES"}},
	}
}

func TestCycloneDXExportMapsEveryAssetAndStatesCoverage(t *testing.T) {
	assets := cycloneDXFixture()
	bom := CycloneDX(assets, CycloneDXMeta{SerialUUID: "3f2f1c1e-7c1a-5b7e-9a1d-3e2c1b0a9f8e",
		GeneratedAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), ToolVersion: "test"})
	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.6" || len(bom.Components) != len(assets) ||
		len(bom.Compositions) != 1 || bom.Compositions[0].Aggregate != "incomplete" || len(bom.Compositions[0].Assemblies) != len(assets) {
		t.Fatalf("bom = %+v", bom)
	}
	byRef := map[string]CycloneDXAssetJS{}
	for _, c := range bom.Components {
		byRef[c.BOMRef] = c
	}
	for _, a := range assets {
		c, ok := byRef[a.ID]
		if !ok || c.Type != "cryptographic-asset" || len(c.Evidence.Occurrences) != 1 || c.Evidence.Occurrences[0].Location != a.Location {
			t.Fatalf("asset %s → %+v", a.ID, c)
		}
		switch {
		case a.Kind == "certificate-key":
			p := c.CryptoProperties.AlgorithmProperties
			if c.CryptoProperties.AssetType != "algorithm" || p == nil {
				t.Fatalf("%s: %+v", a.ID, c.CryptoProperties)
			}
			if a.KeyBits > 0 && a.Algorithm == "RSA" && p.ParameterSetIdentifier != strconv.Itoa(a.KeyBits) {
				t.Fatalf("%s: RSA key size %s, inventory %d", a.ID, p.ParameterSetIdentifier, a.KeyBits)
			}
			if a.QuantumVulnerable && (p.NISTQuantumSecurityLevel == nil || *p.NISTQuantumSecurityLevel != 0) {
				t.Fatalf("%s: a quantum-vulnerable key must carry NIST level 0: %+v", a.ID, p)
			}
		case a.Cipher != "":
			if c.CryptoProperties.ProtocolProperties.CipherSuites[0].Name != a.Cipher {
				t.Fatalf("%s: %+v", a.ID, c.CryptoProperties)
			}
		default:
			if "TLSv"+c.CryptoProperties.ProtocolProperties.Version != a.Protocol {
				t.Fatalf("%s: protocol %+v, inventory %s", a.ID, c.CryptoProperties.ProtocolProperties, a.Protocol)
			}
		}
	}
	if byRef["00000000-0000-4000-8000-000000000005"].CryptoProperties.AlgorithmProperties.NISTQuantumSecurityLevel == nil ||
		*byRef["00000000-0000-4000-8000-000000000005"].CryptoProperties.AlgorithmProperties.NISTQuantumSecurityLevel != 3 {
		t.Fatal("ML-DSA-65 must carry NIST quantum security level 3")
	}
	if byRef["00000000-0000-4000-8000-000000000006"].CryptoProperties.AlgorithmProperties.Primitive != "unknown" {
		t.Fatal("an unrecognized algorithm must not be given a primitive")
	}
	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bytes.ToLower(data), []byte("fips")) {
		t.Fatal("the export must not claim FIPS")
	}
	data = append(data, '\n')
	golden := filepath.Join("testdata", "cyclonedx-export.golden.json")
	if *updateCycloneDXGolden {
		if err := os.WriteFile(golden, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden) // #nosec G304 -- the package's own golden test fixture (CWE-22)
	if err != nil {
		t.Fatalf("read golden (run with -update-cyclonedx-golden): %v", err)
	}
	if !bytes.Equal(want, data) {
		t.Fatal("the CycloneDX export changed; review it and rerun with -update-cyclonedx-golden (the console test validates the golden against the CycloneDX 1.6 schema)")
	}
}
