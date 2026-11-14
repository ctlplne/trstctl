// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// X6-O1 Done-when: a CBOM import records its findings as batches, not one
// event per finding. An image scan of 1,200 components appends three
// cbom.assets.observed events (500, 500 and 200 observations) and no
// cbom.asset.observed; every component is in the inventory under the image
// source; the same document again appends nothing.
func TestServedCBOMImportRecordsItsFindingsInBatchesX6O1(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	writer := seedScopedToken(t, h.store, h.tenant, "discovery:write", "discovery:read", "risk:read")
	var comps []string
	for i := 0; i < 400; i++ {
		path := fmt.Sprintf("/etc/ssl/batch/%08x.0", i)
		comps = append(comps,
			fmt.Sprintf(`{"type":"cryptographic-asset","bom-ref":"alg:%d","name":"RSA-2048","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"parameterSetIdentifier":"2048"}},"evidence":{"occurrences":[{"location":%q}]}}`, i, path),
			fmt.Sprintf(`{"type":"cryptographic-asset","bom-ref":"key:%d","name":"key %d","cryptoProperties":{"assetType":"related-crypto-material","relatedCryptoMaterialProperties":{"type":"public-key","algorithmRef":"alg:%d","size":2048}},"evidence":{"occurrences":[{"location":%q}]}}`, i, i, i, path),
			fmt.Sprintf(`{"type":"cryptographic-asset","bom-ref":"cert:%d","name":"CN=Batch CA %d","cryptoProperties":{"assetType":"certificate","certificateProperties":{"subjectName":"CN=Batch CA %d","issuerName":"CN=Batch CA %d","subjectPublicKeyRef":"key:%d"}},"evidence":{"occurrences":[{"location":%q}]}}`, i, i, i, i, i, path),
		)
	}
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"serialNumber":"urn:uuid:6c3b1d0c-9b8a-4766-8554-4332211000aa","components":[` + strings.Join(comps, ",") + `]}`
	const source = "image:registry.example/batched:1.0"
	before, err := h.log.LastSequence(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/cbom/imports?source="+source, writer, "x6o1-batched", json.RawMessage(doc))
	var first struct {
		Findings int    `json:"findings"`
		RunID    string `json:"run_id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &first) != nil || first.Findings != 1200 {
		t.Fatalf("import: HTTP %d %.300s", status, body)
	}
	elapsed := time.Since(start)
	count := func(from uint64) (batches, single, observations int, last uint64) {
		t.Helper()
		if err := h.log.Replay(context.Background(), from+1, func(e events.Event) error {
			last = e.Sequence
			if e.TenantID != h.tenant {
				return nil
			}
			switch e.Type {
			case projections.EventCBOMAssetsObserved:
				var pl projections.CBOMAssetsObserved
				if err := json.Unmarshal(e.Data, &pl); err != nil {
					return err
				}
				batches++
				observations += len(pl.Assets)
			case projections.EventCBOMAssetObserved:
				single++
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return batches, single, observations, last
	}
	batches, single, observations, last := count(before)
	if batches != 3 || single != 0 || observations != 1200 {
		t.Fatalf("the import appended %d batch events with %d observations and %d single events; want 3, 1200 and 0", batches, observations, single)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/cbom/assets", writer, nil)
	var inventory struct {
		Items []struct {
			Location string `json:"location"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &inventory) != nil {
		t.Fatalf("inventory: HTTP %d %.300s", status, body)
	}
	under := 0
	for _, item := range inventory.Items {
		if strings.HasPrefix(item.Location, source+":") {
			under++
		}
	}
	if under != 1200 {
		t.Fatalf("the inventory holds %d assets under %s, want 1200", under, source)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/cbom/imports?source="+source, writer, "x6o1-batched-again", json.RawMessage(doc))
	if status != http.StatusOK || !strings.Contains(string(body), `"replayed":true`) {
		t.Fatalf("the same document again: HTTP %d %.300s", status, body)
	}
	if batches, single, _, _ := count(last); batches != 0 || single != 0 {
		t.Fatalf("the replayed import appended %d batch and %d single observation events", batches, single)
	}
	t.Logf("X6O1_OK findings=1200 batch_events=3 import_elapsed=%s", elapsed.Round(time.Millisecond))
}
