// SPDX-License-Identifier: BUSL-1.1

package cbom

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// cycloneDXSupplementFixture covers every component the export writes beside
// the inventory (Q3-L2): a certificate for the fixture's first certificate key,
// a keystore key, a weak key file, a secret-key store, a library, and TLS and
// SSH handshakes an observer saw, with the host keys cut at their bound.
func cycloneDXSupplementFixture() CycloneDXSupplement {
	return CycloneDXSupplement{
		Certificates: []CycloneDXCertificate{{Fingerprint: "ab12", Subject: "CN=api.example.test", Issuer: "CN=Example Issuing CA", Serial: "0a1b2c",
			NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
			KeyRefs: []string{"00000000-0000-4000-8000-000000000001"}, Locations: []string{"api.example.test:443"}}},
		Keys: []CycloneDXKeyMaterial{
			{ID: "10000000-0000-4000-8000-000000000001", Location: "/opt/app/conf/keystore.p12#tomcat", Format: "PKCS12", Algorithm: "RSA-2048", KeyBits: 2048,
				Fingerprint: "cd34", Encrypted: true},
			{ID: "10000000-0000-4000-8000-000000000002", Location: "/etc/ssl/private/legacy.key", Format: "PEM", Algorithm: "RSA-1024", KeyBits: 1024,
				Weak: true, Reasons: []string{"RSA modulus below 2048 bits"}},
			{ID: "10000000-0000-4000-8000-000000000003", Location: "/etc/hadoop/conf/creds.jceks", Format: "JCEKS", Algorithm: "unknown", Encrypted: true, Secret: true},
		},
		Libraries: []CycloneDXLibrary{{ID: "20000000-0000-4000-8000-000000000001", Name: "openssl", Version: "3.0.13", Location: "/usr/lib/libssl.so.3", PQHybrid: "no"}},
		Observations: []CycloneDXObservation{
			{ID: "30000000-0000-4000-8000-000000000001", Observer: "network-observer", Location: "10.0.0.5:443", Protocol: "tls", Version: "TLSv1.3",
				CipherSuite: "TLS_AES_128_GCM_SHA256", Group: "X25519MLKEM768", PQHybrid: true},
			{ID: "30000000-0000-4000-8000-000000000002", Observer: "network-observer", Location: "10.0.0.9:22", Protocol: "ssh",
				CipherSuite: "chacha20-poly1305@openssh.com", Group: "mlkem768x25519-sha256", PQHybrid: true},
		},
		CutAt: map[string]int{"host_keys": 10000},
	}
}

// Q3-L2: certificates, host keys, libraries and observed handshakes become
// components of their CycloneDX kinds, every one in the composition, and the
// coverage counts them and names a class cut at its bound. The golden is
// validated against the official CycloneDX 1.6 schema by the console's test.
func TestCycloneDXExportCarriesCertificatesHostKeysLibrariesAndObservationsQ3L2(t *testing.T) {
	assets, extra := cycloneDXFixture(), cycloneDXSupplementFixture()
	bom := CycloneDXWith(assets, extra, CycloneDXMeta{SerialUUID: "4a3b2c1d-8e7f-5a6b-9c0d-1e2f3a4b5c6d",
		GeneratedAt: time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC), ToolVersion: "test"})
	want := len(assets) + 1 + 3 + 1 + 2
	if len(bom.Components) != want || len(bom.Compositions[0].Assemblies) != want {
		t.Fatalf("components %d, assemblies %d; want %d", len(bom.Components), len(bom.Compositions[0].Assemblies), want)
	}
	byRef := map[string]CycloneDXAssetJS{}
	for _, c := range bom.Components {
		byRef[c.BOMRef] = c
	}
	cert := byRef["certificate:ab12"]
	if cert.CryptoProperties == nil || cert.CryptoProperties.AssetType != "certificate" || cert.CryptoProperties.CertificateProperties == nil ||
		cert.CryptoProperties.CertificateProperties.SubjectPublicKeyRef != "00000000-0000-4000-8000-000000000001" ||
		cert.CryptoProperties.CertificateProperties.NotValidAfter != "2027-01-01T00:00:00Z" || cert.Evidence.Occurrences[0].Location != "api.example.test:443" {
		t.Fatalf("certificate = %+v", cert)
	}
	for ref, wantType := range map[string]string{
		"crypto-material:10000000-0000-4000-8000-000000000001": "private-key",
		"crypto-material:10000000-0000-4000-8000-000000000002": "private-key",
		"crypto-material:10000000-0000-4000-8000-000000000003": "secret-key",
	} {
		c := byRef[ref]
		if c.CryptoProperties == nil || c.CryptoProperties.AssetType != "related-crypto-material" || c.CryptoProperties.RelatedCryptoMaterialProperties.Type != wantType {
			t.Fatalf("%s = %+v; want %s", ref, c, wantType)
		}
	}
	if k := byRef["crypto-material:10000000-0000-4000-8000-000000000001"].CryptoProperties.RelatedCryptoMaterialProperties; k.Size != 2048 || k.Format != "PKCS12" {
		t.Fatalf("keystore key = %+v", k)
	}
	if lib := byRef["library:20000000-0000-4000-8000-000000000001"]; lib.Type != "library" || lib.Name != "openssl" || lib.Version != "3.0.13" || lib.CryptoProperties != nil {
		t.Fatalf("library = %+v", lib)
	}
	if tls := byRef["observed:30000000-0000-4000-8000-000000000001"]; tls.Name != "TLS 1.3" || tls.CryptoProperties.ProtocolProperties.Version != "1.3" ||
		tls.CryptoProperties.ProtocolProperties.CipherSuites[0].Name != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("observed TLS = %+v", tls)
	}
	if ssh := byRef["observed:30000000-0000-4000-8000-000000000002"]; ssh.CryptoProperties.ProtocolProperties.Type != "ssh" || ssh.CryptoProperties.ProtocolProperties.Version != "" {
		t.Fatalf("observed SSH = %+v", ssh)
	}
	coverage := map[string]string{}
	for _, p := range bom.Metadata.Properties {
		coverage[p.Name] = p.Value
	}
	if coverage["trstctl:coverage:certificates"] != "1" || coverage["trstctl:coverage:host_keys"] != "3" || coverage["trstctl:coverage:libraries"] != "1" ||
		coverage["trstctl:coverage:observed_handshakes"] != "2" || coverage["trstctl:coverage:cut_at"] != "host_keys=10000" {
		t.Fatalf("coverage = %v", coverage)
	}
	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bytes.ToLower(data), []byte("fips")) {
		t.Fatal("the export must not claim FIPS")
	}
	data = append(data, '\n')
	golden := filepath.Join("testdata", "cyclonedx-export-supplement.golden.json")
	if *updateCycloneDXGolden {
		if err := os.WriteFile(golden, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(golden) // #nosec G304 -- the package's own golden test fixture (CWE-22)
	if err != nil {
		t.Fatalf("read golden (run with -update-cyclonedx-golden): %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("the CycloneDX export changed; review it and rerun with -update-cyclonedx-golden (the console test validates the golden against the CycloneDX 1.6 schema)")
	}
}
