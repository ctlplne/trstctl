// SPDX-License-Identifier: BUSL-1.1

package cbom

import (
	"strings"
	"testing"
	"time"
)

// X6-L6: an imported certificate component carries its own facts — subject,
// issuer, serial, validity and, when the BOM names it, its SHA-256 fingerprint
// (a 1.6 component's hashes or a 1.7 certificate's fingerprint) — so the
// import can take it into the certificate inventory. A fingerprint counts
// only as a SHA-256 of 64 hex digits.
func TestImportedCertificateCarriesFingerprintAndValidityX6L6(t *testing.T) {
	t.Parallel()
	fp16 := strings.Repeat("ab", 32)
	fp17 := strings.Repeat("CD", 32)
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.7","version":1,"components":[
	  {"type":"cryptographic-asset","bom-ref":"alg:rsa","name":"RSA-2048","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"parameterSetIdentifier":"2048"}}},
	  {"type":"cryptographic-asset","bom-ref":"key:dev","name":"device key","cryptoProperties":{"assetType":"related-crypto-material","relatedCryptoMaterialProperties":{"type":"public-key","algorithmRef":"alg:rsa","size":2048}}},
	  {"type":"cryptographic-asset","bom-ref":"cert:16","name":"device","hashes":[{"alg":"MD5","content":"00112233445566778899aabbccddeeff"},{"alg":"SHA-256","content":"` + fp16 + `"}],
	   "cryptoProperties":{"assetType":"certificate","certificateProperties":{"subjectName":"CN=hsm-01.acme.example","issuerName":"CN=Acme Device CA",
	   "notValidBefore":"2026-01-01T00:00:00Z","notValidAfter":"2026-12-01T00:00:00Z","subjectPublicKeyRef":"key:dev"}}},
	  {"type":"cryptographic-asset","bom-ref":"cert:17","name":"management",
	   "cryptoProperties":{"assetType":"certificate","certificateProperties":{"subjectName":"CN=mgmt.acme.example","serialNumber":"0A1B",
	   "fingerprint":{"alg":"SHA-256","content":"` + strings.Join(splitPairs(fp17), ":") + `"},"notValidAfter":"2027-06-30T12:00:00+02:00"}}},
	  {"type":"cryptographic-asset","bom-ref":"cert:none","name":"CN=legacy.acme.example",
	   "cryptoProperties":{"assetType":"certificate","certificateProperties":{"notValidAfter":"not a date"}}},
	  {"type":"cryptographic-asset","bom-ref":"cert:md5","name":"md5 only","hashes":[{"alg":"MD5","content":"00112233445566778899aabbccddeeff"},{"alg":"SHA-256","content":"short"}],
	   "cryptoProperties":{"assetType":"certificate","certificateProperties":{"subjectName":"CN=md5.acme.example"}}}]}`
	bom, err := ParseCycloneDXImport([]byte(doc), "vendor:acme-hsm", DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	bySubject := map[string]*ImportedCertificate{}
	for _, f := range bom.Findings {
		if f.Kind != AssetImportedCertificate {
			continue
		}
		if f.Certificate == nil {
			t.Fatalf("certificate finding %s carries no certificate facts", f.Location)
		}
		if f.CertificateFingerprint != "" {
			t.Fatalf("the CBOM row of %s was given a fingerprint (only certificate-key rows hold one)", f.Location)
		}
		bySubject[f.Certificate.Subject] = f.Certificate
	}
	dev := bySubject["CN=hsm-01.acme.example"]
	if dev == nil || dev.Fingerprint != fp16 || dev.Issuer != "CN=Acme Device CA" || dev.NotBefore == nil || dev.NotAfter == nil ||
		!dev.NotAfter.Equal(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)) || !dev.NotBefore.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("1.6 certificate with hashes = %+v", dev)
	}
	mgmt := bySubject["CN=mgmt.acme.example"]
	if mgmt == nil || mgmt.Fingerprint != strings.ToLower(fp17) || mgmt.Serial != "0A1B" || mgmt.NotAfter == nil ||
		!mgmt.NotAfter.Equal(time.Date(2027, 6, 30, 10, 0, 0, 0, time.UTC)) || mgmt.NotAfter.Location() != time.UTC {
		t.Fatalf("1.7 certificate with a fingerprint = %+v", mgmt)
	}
	legacy := bySubject["CN=legacy.acme.example"]
	if legacy == nil || legacy.Fingerprint != "" || legacy.NotAfter != nil {
		t.Fatalf("certificate without a fingerprint or a valid date = %+v", legacy)
	}
	if md5 := bySubject["CN=md5.acme.example"]; md5 == nil || md5.Fingerprint != "" {
		t.Fatalf("an MD5 hash or a short SHA-256 became a fingerprint: %+v", md5)
	}
}

func splitPairs(hex string) []string {
	var out []string
	for i := 0; i+2 <= len(hex); i += 2 {
		out = append(out, hex[i:i+2])
	}
	return out
}
