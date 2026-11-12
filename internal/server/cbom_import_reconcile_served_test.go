// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// X6-L3: an import retires what a newer BOM of its source no longer lists.
// Version 3 of a vendor's BOM drops TLS 1.0: the import retires that row
// and names it, while the vendor's other rows and a neighbouring source
// whose name extends the vendor's (vendor:acme-x6l3:fw) stay. Version 1,
// never imported, is refused as older; version 2 again replays and
// resurrects nothing; the vendor's next firmware BOM (another serial
// number) retires what it no longer lists.
func TestServedCBOMImportRetiresWhatANewerBOMDropsX6L3(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	writer := seedScopedToken(t, h.store, h.tenant, "discovery:write", "discovery:read", "risk:read")
	const (
		vendor    = "vendor:acme-x6l3"
		firmware  = "vendor:acme-x6l3:fw"
		serial    = "urn:uuid:6f7a8b9c-0d1e-4f2a-8b3c-4d5e6f7a8b9c"
		nextBOM   = "urn:uuid:7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d"
		fwSerial  = "urn:uuid:8b9c0d1e-2f3a-4b4c-8d5e-6f7a8b9c0d1e"
		openssl   = `{"type":"library","bom-ref":"lib:openssl","name":"OpenSSL","version":"1.1.1w"}`
		rsa1024   = `{"type":"cryptographic-asset","bom-ref":"alg:rsa1024","name":"RSA-1024","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"parameterSetIdentifier":"1024"}}}`
		tls10     = `{"type":"cryptographic-asset","bom-ref":"proto:tls10","name":"TLS","cryptoProperties":{"assetType":"protocol","protocolProperties":{"type":"tls","version":"1.0"}}}`
		tls13     = `{"type":"cryptographic-asset","bom-ref":"proto:tls13","name":"TLS","cryptoProperties":{"assetType":"protocol","protocolProperties":{"type":"tls","version":"1.3"}}}`
		fwRSA     = `{"type":"cryptographic-asset","bom-ref":"alg:rsa1024","name":"RSA-1024","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"parameterSetIdentifier":"1024"}}}`
		locLib    = vendor + ":lib:openssl"
		locRSA    = vendor + ":alg:rsa1024"
		locTLS10  = vendor + ":proto:tls10"
		locTLS13  = vendor + ":proto:tls13"
		locFwRSA  = firmware + ":alg:rsa1024"
		importURL = "/api/v1/cbom/imports?source="
	)
	bom := func(serial string, version int, components ...string) json.RawMessage {
		return json.RawMessage(fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":%q,"version":%d,"components":[%s]}`,
			serial, version, strings.Join(components, ",")))
	}
	type importResult struct {
		AssetIDs        []string `json:"asset_ids"`
		RetiredAssetIDs []string `json:"retired_asset_ids"`
		Replayed        bool     `json:"replayed"`
	}
	importBOM := func(source, key string, doc json.RawMessage, want int) (importResult, string) {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, importURL+source, writer, key, doc)
		var out importResult
		if status != want || (want < 300 && json.Unmarshal(body, &out) != nil) {
			t.Fatalf("import %s (%s): HTTP %d %s; want %d", source, key, status, body, want)
		}
		return out, string(body)
	}
	// active maps this test's active inventory locations to their row IDs.
	active := func() map[string]string {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/cbom/assets", writer, nil)
		var inventory struct {
			Items []struct {
				ID       string `json:"id"`
				Location string `json:"location"`
			} `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &inventory) != nil {
			t.Fatalf("inventory: HTTP %d %s", status, body)
		}
		out := map[string]string{}
		for _, a := range inventory.Items {
			if strings.HasPrefix(a.Location, vendor+":") {
				out[a.Location] = a.ID
			}
		}
		return out
	}
	expect := func(step string, got map[string]string, want ...string) {
		t.Helper()
		var have []string
		for loc := range got {
			have = append(have, loc)
		}
		sort.Strings(have)
		sort.Strings(want)
		if strings.Join(have, " ") != strings.Join(want, " ") {
			t.Fatalf("%s: the active inventory holds %v; want %v", step, have, want)
		}
	}

	importBOM(firmware, "x6l3-fw", bom(fwSerial, 1, fwRSA), http.StatusCreated)
	first, _ := importBOM(vendor, "x6l3-v2", bom(serial, 2, openssl, rsa1024, tls10), http.StatusCreated)
	if len(first.RetiredAssetIDs) != 0 {
		t.Fatalf("the source's first import retired %v", first.RetiredAssetIDs)
	}
	before := active()
	expect("after version 2", before, locLib, locRSA, locTLS10, locFwRSA)

	newer, _ := importBOM(vendor, "x6l3-v3", bom(serial, 3, openssl, rsa1024, tls13), http.StatusCreated)
	expect("after version 3", active(), locLib, locRSA, locTLS13, locFwRSA)
	if strings.Join(newer.RetiredAssetIDs, " ") != before[locTLS10] {
		t.Fatalf("version 3 retired %v; want only the TLS 1.0 row %s", newer.RetiredAssetIDs, before[locTLS10])
	}

	_, refusal := importBOM(vendor, "x6l3-v1", bom(serial, 1, openssl, rsa1024, tls10), http.StatusConflict)
	if !strings.Contains(refusal, "version 3") || !strings.Contains(refusal, "version 1") {
		t.Fatalf("the older revision's refusal does not name both versions: %s", refusal)
	}
	expect("after the refused version 1", active(), locLib, locRSA, locTLS13, locFwRSA)

	replay, _ := importBOM(vendor, "x6l3-v2-again", bom(serial, 2, openssl, rsa1024, tls10), http.StatusOK)
	if !replay.Replayed || len(replay.RetiredAssetIDs) != 0 {
		t.Fatalf("version 2 again = %+v; want a replay that retires nothing", replay)
	}
	expect("after replaying version 2", active(), locLib, locRSA, locTLS13, locFwRSA)

	held := active()
	firmwareBOM, _ := importBOM(vendor, "x6l3-next", bom(nextBOM, 1, openssl), http.StatusCreated)
	want := []string{held[locRSA], held[locTLS13]}
	sort.Strings(want)
	if strings.Join(firmwareBOM.RetiredAssetIDs, " ") != strings.Join(want, " ") {
		t.Fatalf("the next BOM retired %v; want the RSA and TLS 1.3 rows %v", firmwareBOM.RetiredAssetIDs, want)
	}
	expect("after the next BOM", active(), locLib, locFwRSA)
}
