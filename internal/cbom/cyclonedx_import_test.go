// SPDX-License-Identifier: BUSL-1.1

package cbom_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/cbom"
)

const vendorCBOM = `{
  "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 3,
  "serialNumber": "urn:uuid:7f1c1d5e-6a3b-4f1e-9a4e-0d6b1c2e3f40",
  "components": [
    {"type": "library", "bom-ref": "lib:openssl", "name": "OpenSSL", "version": "3.0.13"},
    {"type": "cryptographic-asset", "bom-ref": "alg:rsa", "name": "RSA-2048",
     "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "pke", "parameterSetIdentifier": "2048"}},
     "evidence": {"occurrences": [{"location": "/usr/lib/app/signer.so", "line": 0}]}},
    {"type": "cryptographic-asset", "bom-ref": "alg:ecdh", "name": "ECDH",
     "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "key-agree", "curve": "secp256r1"}}},
    {"type": "cryptographic-asset", "bom-ref": "key:device", "name": "device key",
     "cryptoProperties": {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": {"type": "public-key", "algorithmRef": "alg:rsa", "size": 1024}}},
    {"type": "cryptographic-asset", "bom-ref": "cert:device", "name": "device certificate",
     "cryptoProperties": {"assetType": "certificate", "certificateProperties": {"subjectName": "CN=device", "subjectPublicKeyRef": "key:device"}},
     "evidence": {"occurrences": [{"location": "/etc/device/cert.pem"}]}},
    {"type": "cryptographic-asset", "bom-ref": "proto:tls", "name": "TLS",
     "cryptoProperties": {"assetType": "protocol", "protocolProperties": {"type": "tls", "version": "1.0",
       "cipherSuites": [{"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}]}}},
    {"type": "application", "bom-ref": "app", "name": "firmware"}
  ]
}`

// X6: a vendor CBOM's algorithms, keys, certificates, protocols and crypto
// libraries become classified findings located under the import's source.
func TestParseCycloneDXImportMapsEveryAssetType(t *testing.T) {
	bom, err := cbom.ParseCycloneDXImport([]byte(vendorCBOM), "vendor:acme-router", cbom.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if bom.SerialNumber != "urn:uuid:7f1c1d5e-6a3b-4f1e-9a4e-0d6b1c2e3f40" || bom.Version != 3 || bom.Components != 7 {
		t.Fatalf("bom = %+v", bom)
	}
	got := map[string]cbom.Finding{}
	for _, f := range bom.Findings {
		if !strings.HasPrefix(f.Location, "vendor:acme-router:") {
			t.Fatalf("finding located outside its source: %+v", f)
		}
		got[string(f.Kind)+"|"+f.Location+"|"+f.Algorithm+"|"+f.Protocol+"|"+f.Cipher] = f
	}
	want := []string{
		"imported-library|vendor:acme-router:lib:openssl|||",
		"imported-algorithm|vendor:acme-router:/usr/lib/app/signer.so|RSA||",
		"imported-algorithm|vendor:acme-router:alg:ecdh|ECDH-P256||",
		"imported-key|vendor:acme-router:key:device|RSA||",
		"imported-certificate|vendor:acme-router:/etc/device/cert.pem|RSA||",
		"imported-protocol|vendor:acme-router:proto:tls||TLSv1.0|",
		"imported-protocol|vendor:acme-router:proto:tls|||TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	}
	if len(got) != len(want) {
		t.Fatalf("findings = %v", keys(got))
	}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Fatalf("missing %s in %v", k, keys(got))
		}
	}
	if f := got["imported-library|vendor:acme-router:lib:openssl|||"]; f.Library != "openssl 3.0.13" {
		t.Fatalf("library = %+v", f)
	}
	if f := got["imported-key|vendor:acme-router:key:device|RSA||"]; f.KeyBits != 1024 || f.Class.Strength != cbom.StrengthWeak {
		t.Fatalf("a 1024-bit key is not weak: %+v", f)
	}
	if f := got["imported-algorithm|vendor:acme-router:alg:ecdh|ECDH-P256||"]; f.KeyBits != 256 || !f.Class.QuantumVulnerable {
		t.Fatalf("ECDH P-256 = %+v", f)
	}
	if f := got["imported-protocol|vendor:acme-router:proto:tls||TLSv1.0|"]; f.Class.Strength != cbom.StrengthWeak {
		t.Fatalf("TLS 1.0 not weak: %+v", f)
	}

	for name, doc := range map[string]string{
		"not json":      "<bom/>",
		"not cyclonedx": `{"bomFormat":"SPDX","specVersion":"1.6"}`,
		"no crypto":     `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"application","name":"x"}]}`,
	} {
		if _, err := cbom.ParseCycloneDXImport([]byte(doc), "vendor:x", cbom.DefaultPolicy()); err == nil {
			t.Fatalf("%s was imported", name)
		}
	}
	if _, err := cbom.ParseCycloneDXImport([]byte(vendorCBOM), "bad source with spaces", cbom.DefaultPolicy()); err == nil {
		t.Fatal("an unsafe source name was accepted")
	}
}

// Q3's export reads back through the import: the BOM trstctl signs is a BOM
// trstctl can merge.
func TestCycloneDXExportImportsBack(t *testing.T) {
	exported := cbom.CycloneDX([]cbom.CycloneDXAsset{
		{ID: "a1", Kind: "certificate-key", Location: "10.0.0.5:443", Algorithm: "RSA", KeyBits: 2048},
		{ID: "a2", Kind: "tls-endpoint", Location: "10.0.0.5:443", Protocol: "TLSv1.2"},
	}, cbom.CycloneDXMeta{SerialUUID: "11111111-2222-4333-8444-555555555555", GeneratedAt: time.Unix(1_700_000_000, 0), ToolVersion: "test"})
	raw, err := json.Marshal(exported)
	if err != nil {
		t.Fatal(err)
	}
	bom, err := cbom.ParseCycloneDXImport(raw, "trstctl:peer", cbom.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	var sawKey, sawTLS bool
	for _, f := range bom.Findings {
		sawKey = sawKey || (f.Algorithm == "RSA" && f.KeyBits == 2048)
		sawTLS = sawTLS || f.Protocol == "TLSv1.2"
	}
	if !sawKey || !sawTLS {
		t.Fatalf("round trip lost facts: %+v", bom.Findings)
	}
}

func keys(m map[string]cbom.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
