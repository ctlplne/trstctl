// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// Exercise the actual TLS scanner, event sink, projection and public inventory.
// This proves observed leaf identity, not endpoint trust or managed deployment.
func TestServedCBOMRetainsObservedCertificateFingerprint(t *testing.T) {
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(endpoint.Close)
	address, err := url.Parse(endpoint.URL)
	if err != nil {
		t.Fatal(err)
	}
	expected := crypto.SHA256Hex(endpoint.Certificate().Raw)
	h := newOperatingServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "discovery:write", "risk:read")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/cbom/scans", token, "cbom-observed-leaf", map[string]any{"tls_endpoints": []string{address.Host}})
	if status != http.StatusCreated {
		t.Fatalf("scan: status=%d body=%s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/cbom/assets", token, nil)
	if status != http.StatusOK {
		t.Fatalf("inventory: status=%d body=%s", status, body)
	}
	var inventory struct {
		Items []struct {
			Kind        string `json:"kind"`
			Location    string `json:"location"`
			Fingerprint string `json:"certificate_fingerprint"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &inventory); err != nil {
		t.Fatal(err)
	}
	certificates := 0
	for _, asset := range inventory.Items {
		if asset.Location != address.Host {
			t.Fatalf("unexpected scan target: %+v", asset)
		}
		if asset.Kind == "certificate-key" {
			certificates++
			if asset.Fingerprint != expected {
				t.Fatalf("observed leaf=%q, want exact served SHA-256 %q", asset.Fingerprint, expected)
			}
		} else if asset.Fingerprint != "" {
			t.Fatalf("non-certificate asset inherited leaf identity: %+v", asset)
		}
	}
	if certificates != 1 {
		t.Fatalf("certificate observations=%d, want one", certificates)
	}
	if !h.hasEvent(t, "cbom.asset.observed") {
		t.Fatal("scan did not append observation evidence")
	}
}
