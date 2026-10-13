// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

func TestServedCTMonitoringCannotReplaceAnotherDiscoverySourceKind(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "discovery:write")
	createManual := func(name, key string) {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost,
			"/api/v1/discovery/sources", token, key, map[string]any{
				"name": name, "kind": "manual", "config": map[string]any{
					"findings": []any{map[string]any{"kind": "x509_certificate", "ref": "qa-public-cert"}},
				},
			})
		if status != http.StatusCreated {
			t.Fatalf("create manual source: %d %s", status, body)
		}
	}
	putCT := func(name, sourceID, key string) (int, []byte) {
		t.Helper()
		request := map[string]any{
			"name": name, "logs": []string{"https://ct.example.com/log"},
			"watched_domains": []string{"example.com"}, "run_now": false,
		}
		if sourceID != "" {
			request["source_id"] = sourceID
		}
		return secretsReqKey(t, h, http.MethodPut, "/api/v1/discovery/ct-monitoring", token, key, request)
	}

	createManual("qa-ct-other-kind-by-name", "manual-before-ct-name")
	before, err := h.store.GetDiscoverySourceByName(t.Context(), h.tenant, "qa-ct-other-kind-by-name")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("same name without source ID", func(t *testing.T) {
		status, body := putCT(before.Name, "", "ct-cannot-overwrite-manual-name")
		if status != http.StatusConflict {
			t.Fatalf("CT replaced manual source by name: %d %s", status, body)
		}
		assertDiscoverySourcePreserved(t, h, before)
	})

	status, body := putCT("qa-ct-owned-source", "", "ct-own-source")
	if status != http.StatusOK {
		t.Fatalf("create CT source: %d %s", status, body)
	}
	var created struct {
		Source struct {
			ID string `json:"id"`
		} `json:"source"`
	}
	if err := json.Unmarshal(body, &created); err != nil || created.Source.ID == "" {
		t.Fatalf("CT source response: %v %s", err, body)
	}
	createManual("qa-ct-other-kind-by-ID", "manual-before-ct-rename")
	other, err := h.store.GetDiscoverySourceByName(t.Context(), h.tenant, "qa-ct-other-kind-by-ID")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("rename by source ID", func(t *testing.T) {
		status, body := putCT(other.Name, created.Source.ID, "ct-cannot-rename-over-manual")
		if status != http.StatusConflict {
			t.Fatalf("CT collided with manual source by ID: %d %s", status, body)
		}
		assertDiscoverySourcePreserved(t, h, other)
	})
}

func assertDiscoverySourcePreserved(t *testing.T, h *servedHarness, before store.DiscoverySource) {
	t.Helper()
	after, err := h.store.GetDiscoverySourceByName(t.Context(), h.tenant, before.Name)
	if err != nil {
		t.Fatal(err)
	}
	if after.ID != before.ID || after.Kind != before.Kind || !bytes.Equal(after.Config, before.Config) {
		t.Fatalf("source changed: before=%+v after=%+v", before, after)
	}
}
