// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// X6 follow-up: an ordinary image scan's CBOM is bigger than the shared
// 1 MiB mutation body limit and the old 5,000-component cap — cbomkit-theia's
// for a small Alpine image is about 6 MiB and 8,000 components, most of them
// the operating system's CA bundle. Such a document imports, the same document
// again changes nothing, and one past the import limit is refused with 413.
func TestServedCBOMImportOfARealSizedImageScanX6(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	writer := seedScopedToken(t, h.store, h.tenant, "discovery:write", "discovery:read", "risk:read")
	var comps []string
	for i := 0; i < 2700; i++ {
		path := fmt.Sprintf("/etc/ssl/certs/%08x.0", i)
		comps = append(comps,
			fmt.Sprintf(`{"type":"cryptographic-asset","bom-ref":"alg:%d","name":"RSA-2048","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"parameterSetIdentifier":"2048"}},"evidence":{"occurrences":[{"location":%q}]}}`, i, path),
			fmt.Sprintf(`{"type":"cryptographic-asset","bom-ref":"key:%d","name":"key %d","cryptoProperties":{"assetType":"related-crypto-material","relatedCryptoMaterialProperties":{"type":"public-key","algorithmRef":"alg:%d","size":2048}},"evidence":{"occurrences":[{"location":%q}]}}`, i, i, i, path),
			fmt.Sprintf(`{"type":"cryptographic-asset","bom-ref":"cert:%d","name":"CN=Root CA %d","cryptoProperties":{"assetType":"certificate","certificateProperties":{"subjectName":"CN=Root CA %d","issuerName":"CN=Root CA %d","subjectPublicKeyRef":"key:%d"}},"evidence":{"occurrences":[{"location":%q}]}}`, i, i, i, i, i, path),
		)
	}
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"serialNumber":"urn:uuid:3f2e1d0c-9b8a-4766-8554-433221100fed","components":[` + strings.Join(comps, ",") + `]}`
	if len(doc) <= 1<<20 {
		t.Fatalf("the document is %d bytes; it must exceed the 1 MiB mutation limit", len(doc))
	}
	start := time.Now()
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/cbom/imports?source=image:registry.example/base:3.20", writer, "x6-large", json.RawMessage(doc))
	var first struct {
		Components int  `json:"components"`
		Findings   int  `json:"findings"`
		Replayed   bool `json:"replayed"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &first) != nil || first.Components != 8100 || first.Findings != 8100 || first.Replayed {
		t.Fatalf("a real-sized image scan: HTTP %d %.300s", status, body)
	}
	t.Logf("imported %d components (%d bytes) in %s", first.Components, len(doc), time.Since(start).Round(time.Millisecond))
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/cbom/imports?source=image:registry.example/base:3.20", writer, "x6-large-again", json.RawMessage(doc))
	var again struct {
		Replayed bool `json:"replayed"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &again) != nil || !again.Replayed {
		t.Fatalf("the same document again: HTTP %d %.300s", status, body)
	}
	oversized, err := json.Marshal(map[string]string{"pad": strings.Repeat("x", 33<<20)})
	if err != nil {
		t.Fatal(err)
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/cbom/imports?source=image:registry.example/huge:1", writer, "x6-oversized", json.RawMessage(oversized)); status != http.StatusRequestEntityTooLarge {
		t.Fatalf("a document past the import limit: HTTP %d %.200s", status, body)
	}
}
