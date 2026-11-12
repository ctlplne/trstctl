// SPDX-License-Identifier: BUSL-1.1

package cbom

import (
	"strings"
	"testing"
)

// x6l5BOM is a vendor CBOM whose dependency graph says which library
// provides each algorithm and protocol, which algorithm a key uses, and which
// key and issuer a certificate depends on — facts its components' own
// properties leave out.
const x6l5BOM = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
 "components":[
  {"type":"application","bom-ref":"app:gateway","name":"acme-gateway","version":"4.2"},
  {"type":"library","bom-ref":"lib:openssl","name":"OpenSSL","version":"1.1.1w"},
  {"type":"library","bom-ref":"lib:boring","name":"BoringSSL"},
  {"type":"cryptographic-asset","bom-ref":"alg:rsa1024","name":"RSA-1024","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"parameterSetIdentifier":"1024"}}},
  {"type":"cryptographic-asset","bom-ref":"alg:ecdh","name":"ECDH","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"curve":"secp256r1"}}},
  {"type":"cryptographic-asset","bom-ref":"proto:tls","name":"TLS","cryptoProperties":{"assetType":"protocol","protocolProperties":{"type":"tls","version":"1.2","cipherSuites":[{"name":"TLS_RSA_WITH_AES_128_CBC_SHA"}]}}},
  {"type":"cryptographic-asset","bom-ref":"key:dev","name":"device key","cryptoProperties":{"assetType":"related-crypto-material","relatedCryptoMaterialProperties":{"type":"private-key"}}},
  {"type":"cryptographic-asset","bom-ref":"cert:ca","name":"Acme Root","cryptoProperties":{"assetType":"certificate","certificateProperties":{"subjectName":"CN=Acme Root"}}},
  {"type":"cryptographic-asset","bom-ref":"cert:dev","name":"device certificate","cryptoProperties":{"assetType":"certificate","certificateProperties":{"subjectName":"CN=gw-01.acme.example"}}}],
 "dependencies":[
  {"ref":"app:gateway","dependsOn":["lib:openssl","lib:boring"]},
  {"ref":"lib:openssl","provides":["alg:rsa1024","proto:tls"]},
  {"ref":"lib:boring","provides":["alg:ecdh"]},
  {"ref":"key:dev","dependsOn":["alg:rsa1024"]},
  {"ref":"cert:dev","dependsOn":["key:dev","cert:ca"]},
  {"ref":"urn:cdx:3b6f1d2e-0000-4000-8000-000000000001/1#lib:other","provides":["alg:ecdh"]}]}`

// X6-L5: the import reads the BOM's dependency graph. provides attributes an
// algorithm or protocol to the library that implements it, and dependsOn
// gives a key or certificate the algorithm (and a certificate the issuer) its
// own properties leave out. A reference to another BOM is not followed.
func TestImportReadsTheDependencyGraphX6L5(t *testing.T) {
	t.Parallel()
	bom, err := ParseCycloneDXImport([]byte(x6l5BOM), "vendor:acme-gateway", DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	byLocation := map[string]Finding{}
	for _, f := range bom.Findings {
		key := f.Location
		if f.Cipher != "" {
			key += "|" + f.Cipher
		}
		byLocation[key] = f
	}
	for loc, want := range map[string]string{
		"vendor:acme-gateway:alg:rsa1024":                            "openssl 1.1.1w",
		"vendor:acme-gateway:proto:tls":                              "openssl 1.1.1w",
		"vendor:acme-gateway:proto:tls|TLS_RSA_WITH_AES_128_CBC_SHA": "openssl 1.1.1w",
		"vendor:acme-gateway:alg:ecdh":                               "boringssl",
		"vendor:acme-gateway:key:dev":                                "vendor:acme-gateway",
	} {
		if got := byLocation[loc].Library; got != want {
			t.Fatalf("%s library = %q; want %q (findings %+v)", loc, got, want, bom.Findings)
		}
	}
	key := byLocation["vendor:acme-gateway:key:dev"]
	if key.Algorithm != "RSA" || key.KeyBits != 1024 || key.Class.Strength != StrengthWeak {
		t.Fatalf("key through dependsOn = %+v", key)
	}
	cert := byLocation["vendor:acme-gateway:cert:dev"]
	if cert.Algorithm != "RSA" || cert.KeyBits != 1024 || cert.Certificate == nil || cert.Certificate.Issuer != "CN=Acme Root" {
		t.Fatalf("certificate through dependsOn = %+v (%+v)", cert, cert.Certificate)
	}

	// Without the graph the same components keep only what their properties say.
	plain := x6l5BOM[:strings.Index(x6l5BOM, `,
 "dependencies"`)] + "}"
	flat, err := ParseCycloneDXImport([]byte(plain), "vendor:acme-gateway", DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range flat.Findings {
		if f.Location == "vendor:acme-gateway:alg:rsa1024" && f.Library != "vendor:acme-gateway" {
			t.Fatalf("without provides the algorithm was attributed to %q", f.Library)
		}
		if f.Location == "vendor:acme-gateway:key:dev" && f.KeyBits != 0 {
			t.Fatalf("without dependsOn the key has a size: %+v", f)
		}
	}
}
