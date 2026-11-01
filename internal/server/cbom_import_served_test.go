// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cbom/sourcescan"
	"trstctl.com/trstctl/internal/config"
)

type x6Import struct {
	RunID    string   `json:"run_id"`
	Findings int      `json:"findings"`
	AssetIDs []string `json:"asset_ids"`
	Replayed bool     `json:"replayed"`
}

// x6VendorCBOM is a router vendor's published CBOM.
const x6VendorCBOM = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":2,
 "serialNumber":"urn:uuid:6c1d2e3f-4a5b-4c6d-8e7f-90a1b2c3d4e5",
 "components":[
  {"type":"library","bom-ref":"lib:openssl","name":"OpenSSL","version":"1.1.1w"},
  {"type":"cryptographic-asset","bom-ref":"alg:rsa","name":"RSA-1024",
   "cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"primitive":"signature","parameterSetIdentifier":"1024"}},
   "evidence":{"occurrences":[{"location":"firmware/bin/sign"}]}},
  {"type":"cryptographic-asset","bom-ref":"proto:tls","name":"TLS",
   "cryptoProperties":{"assetType":"protocol","protocolProperties":{"type":"tls","version":"1.2","cipherSuites":[{"name":"TLS_RSA_WITH_AES_128_CBC_SHA"}]}}}]}`

// x6ImageCBOM is what the wrapped image scanner wrote for a sample image: its
// certificate, its private key and its OpenSSL configuration.
const x6ImageCBOM = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
 "serialNumber":"urn:uuid:0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d",
 "components":[
  {"type":"cryptographic-asset","bom-ref":"alg:rsa2048","name":"RSA-2048","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"parameterSetIdentifier":"2048"}}},
  {"type":"cryptographic-asset","bom-ref":"key:app","name":"app key","cryptoProperties":{"assetType":"related-crypto-material","relatedCryptoMaterialProperties":{"type":"private-key","algorithmRef":"alg:rsa2048","size":2048}},
   "evidence":{"occurrences":[{"location":"/etc/ssl/private/app.key"}]}},
  {"type":"cryptographic-asset","bom-ref":"cert:app","name":"CN=app.example.test","cryptoProperties":{"assetType":"certificate","certificateProperties":{"subjectName":"CN=app.example.test","subjectPublicKeyRef":"key:app"}},
   "evidence":{"occurrences":[{"location":"/etc/ssl/certs/app.pem"}]}},
  {"type":"cryptographic-asset","bom-ref":"proto:openssl.cnf","name":"TLS","cryptoProperties":{"assetType":"protocol","protocolProperties":{"type":"tls","version":"1.0"}},
   "evidence":{"occurrences":[{"location":"/etc/ssl/openssl.cnf"}]}}]}`

// X6: a vendor CBOM imports and merges, and importing it again changes
// nothing; a sample image's certificate, key and OpenSSL configuration arrive
// through the image scanner's CBOM; a sample repository's RSA and ECDH uses
// arrive with the code as their source; and coverage shows each import class
// observed.
func TestServedCBOMImportX6(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	writer := seedScopedToken(t, h.store, h.tenant, "discovery:write", "discovery:read", "risk:read")
	reader := seedScopedToken(t, h.store, h.tenant, "discovery:read", "risk:read")
	importBOM := func(key, source string, doc []byte, want int) x6Import {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/cbom/imports?source="+source, writer, key, json.RawMessage(doc))
		var out x6Import
		if status != want || json.Unmarshal(body, &out) != nil {
			t.Fatalf("import %s: HTTP %d %s", source, status, body)
		}
		return out
	}
	inventory := func() string {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/cbom/assets", reader, nil)
		if status != http.StatusOK {
			t.Fatalf("inventory: HTTP %d %s", status, body)
		}
		return string(body)
	}

	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/cbom/imports?source=vendor:acme-router", reader, "x6-forbidden", json.RawMessage(x6VendorCBOM)); status != http.StatusForbidden {
		t.Fatalf("a read-only principal imported a CBOM: HTTP %d", status)
	}
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/cbom/imports?source=elsewhere:x", writer, "x6-bad-source", json.RawMessage(x6VendorCBOM)); status != http.StatusBadRequest {
		t.Fatalf("an import without a known source prefix: HTTP %d", status)
	}
	first := importBOM("x6-vendor", "vendor:acme-router", []byte(x6VendorCBOM), http.StatusCreated)
	if first.Replayed || first.Findings != 4 || len(first.AssetIDs) != 4 {
		t.Fatalf("vendor import = %+v", first)
	}
	merged := inventory()
	for _, want := range []string{"vendor:acme-router:lib:openssl", "vendor:acme-router:firmware/bin/sign", "vendor:acme-router:proto:tls"} {
		if !strings.Contains(merged, want) {
			t.Fatalf("inventory lacks %s: %s", want, merged)
		}
	}
	again := importBOM("x6-vendor-again", "vendor:acme-router", []byte(x6VendorCBOM), http.StatusOK)
	if !again.Replayed || again.RunID != first.RunID || strings.Join(again.AssetIDs, ",") != strings.Join(first.AssetIDs, ",") {
		t.Fatalf("a second import of the same BOM = %+v, want the first replayed", again)
	}
	if after := inventory(); after != merged {
		t.Fatal("importing the same BOM again changed the inventory")
	}

	image := importBOM("x6-image", "image:registry.example/app:1.4", []byte(x6ImageCBOM), http.StatusCreated)
	if image.Findings != 4 {
		t.Fatalf("image import = %+v", image)
	}
	withImage := inventory()
	for _, want := range []string{"image:registry.example/app:1.4:/etc/ssl/certs/app.pem", "image:registry.example/app:1.4:/etc/ssl/private/app.key", "image:registry.example/app:1.4:/etc/ssl/openssl.cnf"} {
		if !strings.Contains(withImage, want) {
			t.Fatalf("inventory lacks the image's %s", want)
		}
	}

	repo := t.TempDir()
	for name, body := range map[string]string{
		"cmd/server/keys.go": "package main\n\nimport (\n\t\"crypto/ecdh\"\n\t\"crypto/rand\"\n\t\"crypto/rsa\"\n)\n\nfunc keys() {\n\t_, _ = rsa.GenerateKey(rand.Reader, 2048)\n\t_, _ = ecdh.P256().GenerateKey(rand.Reader)\n}\n",
	} {
		path := filepath.Join(repo, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	uses, err := sourcescan.Scan(t.Context(), repo)
	if err != nil || len(uses) != 2 {
		t.Fatalf("source scan = %+v, %v", uses, err)
	}
	doc, err := sourcescan.CBOM(uses, "5f4e3d2c-1b0a-4f9e-8d7c-6b5a4f3e2d1c")
	if err != nil {
		t.Fatal(err)
	}
	importBOM("x6-source", "source:demo-repo", doc, http.StatusCreated)
	withSource := inventory()
	var assets struct {
		Items []struct {
			Location  string `json:"location"`
			Algorithm string `json:"algorithm"`
			KeyBits   int    `json:"key_bits"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(withSource), &assets); err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, a := range assets.Items {
		found[a.Location+"|"+a.Algorithm] = true
	}
	if !found["source:demo-repo:cmd/server/keys.go:10|RSA"] || !found["source:demo-repo:cmd/server/keys.go:11|ECDH-P256"] {
		t.Fatalf("the repository's RSA and ECDH uses are not in the inventory with their source: %v", found)
	}

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/coverage", reader, nil)
	var cov struct {
		Classes []struct {
			Class  string `json:"class"`
			Status string `json:"status"`
		} `json:"classes"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &cov) != nil {
		t.Fatalf("coverage: HTTP %d %s", status, body)
	}
	observed := map[string]string{}
	for _, c := range cov.Classes {
		observed[c.Class] = c.Status
	}
	for _, class := range []string{"vendor-embedded-crypto", "container-image-crypto", "source-code-crypto"} {
		if observed[class] != "OBSERVED" {
			t.Fatalf("coverage %s = %q, want OBSERVED (%v)", class, observed[class], observed)
		}
	}
}
