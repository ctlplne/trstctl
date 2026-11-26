// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestServedCBOMImportRejectsExpansionBeforeRecording(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "discovery:write", "discovery:read")
	occurrences := make([]map[string]any, 257)
	for i := range occurrences {
		occurrences[i] = map[string]any{"location": fmt.Sprintf("src/%d", i)}
	}
	raw, err := json.Marshal(map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []any{map[string]any{
			"type": "cryptographic-asset", "bom-ref": "proto:tls", "name": "TLS",
			"evidence": map[string]any{"occurrences": occurrences},
			"cryptoProperties": map[string]any{"assetType": "protocol", "protocolProperties": map[string]any{
				"type": "tls", "version": "1.2", "cipherSuites": []any{map[string]any{"name": "TLS_AES_128_GCM_SHA256"}},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/cbom/imports?source=vendor:bounded", token, "n0021-bounded", json.RawMessage(raw))
	if status != http.StatusBadRequest || !strings.Contains(string(body), "occurrences") {
		t.Fatalf("oversized component import: HTTP %d %s, want bounded 400", status, body)
	}
}
