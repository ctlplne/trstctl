// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
)

type x6l6Certificate struct {
	ID                 string     `json:"id"`
	Subject            string     `json:"subject"`
	Issuer             string     `json:"issuer"`
	Serial             string     `json:"serial"`
	Fingerprint        string     `json:"fingerprint"`
	KeyAlgorithm       string     `json:"key_algorithm"`
	NotBefore          *time.Time `json:"not_before"`
	NotAfter           *time.Time `json:"not_after"`
	DeploymentLocation string     `json:"deployment_location"`
	Source             string     `json:"source"`
}

// X6-L6: a vendor CBOM's certificates that name their SHA-256 fingerprint (a
// 1.6 component's hashes, a 1.7 certificate's fingerprint) enter the
// certificate inventory with their subject, issuer, serial, key algorithm and
// validity, so the inventory's expiry query lists the vendor certificate
// expiring soon. A certificate the BOM gives no fingerprint for stays a CBOM
// row. A fingerprint the inventory already holds keeps its row as it was, and
// a replayed import records nothing.
func TestServedCBOMImportTakesFingerprintedCertificatesIntoTheInventoryX6L6(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	writer := seedScopedToken(t, h.store, h.tenant, "discovery:write", "discovery:read", "risk:read", "certs:read", "certs:write")

	// A certificate already in the inventory, ingested with its location.
	serving, err := tlsprobe.NewServingTestServer("lb-1.acme.example")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(serving.Close)
	known, err := certinfo.Inspect(caCertDER(t, serving.LeafPEM))
	if err != nil {
		t.Fatal(err)
	}
	knownFP := strings.ToLower(known.SHA256Fingerprint)
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates", writer, "x6l6-known", map[string]any{
		"pem": string(serving.LeafPEM), "deployment_location": "lb-1.acme.example:443", "source": "import",
	}); status != http.StatusCreated {
		t.Fatalf("ingest the known certificate: HTTP %d %s", status, body)
	}

	soon := time.Now().UTC().Add(10 * 24 * time.Hour).Truncate(time.Second)
	later := time.Now().UTC().Add(400 * 24 * time.Hour).Truncate(time.Second)
	deviceFP := strings.Repeat("1a", 32)
	mgmtFP := strings.Repeat("2b", 32)
	vendorBOM := fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.7","version":3,
	 "serialNumber":"urn:uuid:7d2e3f40-5b6c-4d7e-8f90-a1b2c3d4e5f6",
	 "components":[
	  {"type":"cryptographic-asset","bom-ref":"alg:rsa","name":"RSA-2048","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"parameterSetIdentifier":"2048"}}},
	  {"type":"cryptographic-asset","bom-ref":"key:dev","name":"device key","cryptoProperties":{"assetType":"related-crypto-material","relatedCryptoMaterialProperties":{"type":"public-key","algorithmRef":"alg:rsa","size":2048}}},
	  {"type":"cryptographic-asset","bom-ref":"cert:device","name":"device certificate","hashes":[{"alg":"SHA-256","content":"%s"}],
	   "cryptoProperties":{"assetType":"certificate","certificateProperties":{"subjectName":"CN=hsm-01.acme.example","issuerName":"CN=Acme Device CA",
	   "notValidBefore":"2026-01-01T00:00:00Z","notValidAfter":"%s","subjectPublicKeyRef":"key:dev"}},
	   "evidence":{"occurrences":[{"location":"firmware/etc/device.pem"}]}},
	  {"type":"cryptographic-asset","bom-ref":"cert:mgmt","name":"management certificate",
	   "cryptoProperties":{"assetType":"certificate","certificateProperties":{"subjectName":"CN=mgmt.acme.example","issuerName":"CN=Acme Device CA",
	   "serialNumber":"0A1B2C","fingerprint":{"alg":"SHA-256","content":"%s"},"notValidAfter":"%s"}}},
	  {"type":"cryptographic-asset","bom-ref":"cert:lb","name":"load balancer certificate","hashes":[{"alg":"SHA-256","content":"%s"}],
	   "cryptoProperties":{"assetType":"certificate","certificateProperties":{"subjectName":"CN=what the vendor calls it","notValidAfter":"%s"}}},
	  {"type":"cryptographic-asset","bom-ref":"cert:legacy","name":"CN=legacy.acme.example",
	   "cryptoProperties":{"assetType":"certificate","certificateProperties":{"subjectName":"CN=legacy.acme.example","notValidAfter":"%s"}}}]}`,
		deviceFP, soon.Format(time.RFC3339), mgmtFP, later.Format(time.RFC3339), strings.ToUpper(knownFP), later.Format(time.RFC3339), soon.Format(time.RFC3339))

	importBOM := func(key string, want int) (ids []string, replayed bool) {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/cbom/imports?source=vendor:acme-hsm", writer, key, json.RawMessage(vendorBOM))
		var out struct {
			CertificateIDs []string `json:"certificate_ids"`
			Replayed       bool     `json:"replayed"`
		}
		if status != want || json.Unmarshal(body, &out) != nil {
			t.Fatalf("import: HTTP %d %s", status, body)
		}
		return out.CertificateIDs, out.Replayed
	}
	getCertificate := func(id string) x6l6Certificate {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/certificates/"+id, writer, nil)
		var out x6l6Certificate
		if status != http.StatusOK || json.Unmarshal(body, &out) != nil {
			t.Fatalf("certificate %s: HTTP %d %s", id, status, body)
		}
		return out
	}

	ids, replayed := importBOM("x6l6-import", http.StatusCreated)
	if replayed || len(ids) != 3 {
		t.Fatalf("import certificate_ids = %v (replayed %v); want the device, management and known certificates", ids, replayed)
	}
	byFingerprint := map[string]x6l6Certificate{}
	for _, id := range ids {
		c := getCertificate(id)
		byFingerprint[c.Fingerprint] = c
	}
	device := byFingerprint[deviceFP]
	if device.Subject != "CN=hsm-01.acme.example" || device.Issuer != "CN=Acme Device CA" || device.Source != "cbom:vendor:acme-hsm" ||
		device.KeyAlgorithm != "RSA-2048" || device.NotAfter == nil || !device.NotAfter.Equal(soon) || device.NotBefore == nil {
		t.Fatalf("device certificate in the inventory = %+v", device)
	}
	mgmt := byFingerprint[mgmtFP]
	if mgmt.Subject != "CN=mgmt.acme.example" || mgmt.Serial != "0A1B2C" || mgmt.NotAfter == nil || !mgmt.NotAfter.Equal(later) || mgmt.Source != "cbom:vendor:acme-hsm" {
		t.Fatalf("1.7 management certificate in the inventory = %+v", mgmt)
	}
	kept := byFingerprint[knownFP]
	if kept.Subject == "CN=what the vendor calls it" || kept.Source != "import" || kept.DeploymentLocation != "lb-1.acme.example:443" {
		t.Fatalf("the certificate the inventory already held was overwritten by the BOM: %+v", kept)
	}

	// The inventory's expiry query sees the vendor certificate expiring soon.
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/certificates?limit=100&expiring_before="+url.QueryEscape(time.Now().UTC().Add(30*24*time.Hour).Format(time.RFC3339)), writer, nil)
	var expiring struct {
		Items []x6l6Certificate `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &expiring) != nil {
		t.Fatalf("expiring certificates: HTTP %d %s", status, body)
	}
	var expiringFPs []string
	for _, c := range expiring.Items {
		expiringFPs = append(expiringFPs, c.Fingerprint)
		if c.Subject == "CN=legacy.acme.example" {
			t.Fatalf("a certificate the BOM named no fingerprint for entered the inventory: %+v", c)
		}
	}
	sort.Strings(expiringFPs)
	if i := sort.SearchStrings(expiringFPs, deviceFP); i == len(expiringFPs) || expiringFPs[i] != deviceFP {
		t.Fatalf("the vendor device certificate expiring in 10 days is not in the expiring list: %v", expiringFPs)
	}
	if i := sort.SearchStrings(expiringFPs, mgmtFP); i < len(expiringFPs) && expiringFPs[i] == mgmtFP {
		t.Fatal("the management certificate valid for 400 days is in the 30-day expiring list")
	}

	// Replaying the same BOM records nothing and names the same rows.
	again, replayed := importBOM("x6l6-import-again", http.StatusOK)
	if !replayed || strings.Join(again, ",") != strings.Join(ids, ",") {
		t.Fatalf("replayed import = %v (replayed %v); want %v", again, replayed, ids)
	}
	if after := getCertificate(device.ID); after.Source != device.Source || !after.NotAfter.Equal(*device.NotAfter) {
		t.Fatalf("a replay changed the device certificate: %+v", after)
	}
}
