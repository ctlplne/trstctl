// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// X6-L5: a vendor CBOM's dependency graph reaches the served inventory. The
// algorithm and protocol its OpenSSL component provides are listed under
// that library, and the device key whose algorithm only its dependsOn names
// is listed as a weak 1024-bit RSA key.
func TestServedCBOMImportReadsTheDependencyGraphX6L5(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	writer := seedScopedToken(t, h.store, h.tenant, "discovery:write", "discovery:read", "risk:read")
	bom := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"serialNumber":"urn:uuid:5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b",
	 "components":[
	  {"type":"library","bom-ref":"lib:openssl","name":"OpenSSL","version":"1.1.1w"},
	  {"type":"cryptographic-asset","bom-ref":"alg:rsa1024","name":"RSA-1024","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"parameterSetIdentifier":"1024"}}},
	  {"type":"cryptographic-asset","bom-ref":"proto:tls","name":"TLS","cryptoProperties":{"assetType":"protocol","protocolProperties":{"type":"tls","version":"1.0"}}},
	  {"type":"cryptographic-asset","bom-ref":"key:dev","name":"device key","cryptoProperties":{"assetType":"related-crypto-material","relatedCryptoMaterialProperties":{"type":"private-key"}}}],
	 "dependencies":[
	  {"ref":"lib:openssl","provides":["alg:rsa1024","proto:tls"]},
	  {"ref":"key:dev","dependsOn":["alg:rsa1024"]}]}`
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/cbom/imports?source=vendor:acme-x6l5", writer, "x6l5-import", json.RawMessage(bom)); status != http.StatusCreated {
		t.Fatalf("import: HTTP %d %s", status, body)
	}
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/cbom/assets", writer, nil)
	var inventory struct {
		Items []struct {
			Location string `json:"location"`
			Library  string `json:"library"`
			KeyBits  int    `json:"key_bits"`
			Protocol string `json:"protocol"`
			Strength string `json:"strength"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &inventory) != nil {
		t.Fatalf("inventory: HTTP %d %s", status, body)
	}
	found := map[string]bool{}
	for _, a := range inventory.Items {
		switch a.Location {
		case "vendor:acme-x6l5:alg:rsa1024", "vendor:acme-x6l5:proto:tls":
			if a.Library != "openssl 1.1.1w" {
				t.Fatalf("%s is listed under %q; want the OpenSSL component that provides it", a.Location, a.Library)
			}
			found[a.Location] = true
		case "vendor:acme-x6l5:key:dev":
			if a.KeyBits != 1024 || a.Strength != "weak" {
				t.Fatalf("the device key = %+v; want a weak 1024-bit key from its dependsOn", a)
			}
			found[a.Location] = true
		}
	}
	if len(found) != 3 {
		t.Fatalf("the inventory holds %v of the three graph-attributed assets", found)
	}
}
