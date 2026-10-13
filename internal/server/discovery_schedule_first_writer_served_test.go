// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestServedDiscoveryScheduleNameConflictPrecedesEventAppend(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", tok,
		"schedule-first-writer-source", map[string]any{
			"name": "schedule-first-writer-source", "kind": "manual", "config": map[string]any{
				"findings": []any{map[string]any{"kind": "x509_certificate", "ref": "qa-public-cert"}},
			},
		})
	if status != http.StatusCreated {
		t.Fatalf("create source: status %d body %s", status, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatal(err)
	}
	first := map[string]any{"source_id": source.ID, "name": "one-served-schedule", "interval_seconds": 300, "enabled": true}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/schedules", tok,
		"schedule-first-writer-first", first)
	if status != http.StatusCreated {
		t.Fatalf("create first schedule: status %d body %s", status, body)
	}
	firstBody := append([]byte(nil), body...)
	before, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/schedules", tok,
		"schedule-first-writer-first", first)
	if status != http.StatusCreated || !bytes.Equal(body, firstBody) {
		t.Fatalf("same-key response recovery: status %d body %s, want %s", status, body, firstBody)
	}
	if after, err := h.log.LastSequence(t.Context()); err != nil || after != before {
		t.Fatalf("same-key retry appended event: before=%d after=%d err=%v", before, after, err)
	}
	second := map[string]any{"source_id": source.ID, "name": "one-served-schedule", "interval_seconds": 600, "enabled": true}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/schedules", tok,
		"schedule-first-writer-second", second)
	if status != http.StatusConflict {
		t.Fatalf("conflicting second schedule: status %d body %s", status, body)
	}
	if after, err := h.log.LastSequence(t.Context()); err != nil || after != before {
		t.Fatalf("conflicting served create appended event: before=%d after=%d err=%v", before, after, err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/schedules?limit=10", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list schedules: status %d body %s", status, body)
	}
	var listed struct {
		Items []struct {
			Name            string `json:"name"`
			IntervalSeconds int    `json:"interval_seconds"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Items) != 1 || listed.Items[0].Name != "one-served-schedule" || listed.Items[0].IntervalSeconds != 300 {
		t.Fatalf("first schedule changed after refused create: %+v", listed.Items)
	}
}
