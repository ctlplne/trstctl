// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/switchkit"
)

func TestServedSwitchingImportMarksYearZeroUnparseableBeforeAppend(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "certs:write")
	request := map[string]any{
		"name":   "year-zero fixture",
		"export": "fingerprint_sha256,not_after\n" + strings.Repeat("a", 64) + ",0000-01-01\n",
	}
	code, body := secretsReq(t, h, http.MethodPost, "/api/v1/switching/imports/preview", token, request)
	if code != http.StatusOK {
		t.Fatalf("preview = %d: %s", code, body)
	}
	var preview struct {
		Digest string         `json:"digest"`
		Counts map[string]int `json:"counts"`
	}
	if err := json.Unmarshal(body, &preview); err != nil || preview.Counts[switchkit.OutcomeUnparseable] != 1 {
		t.Fatalf("year-zero preview = %+v, err=%v", preview, err)
	}
	request["preview_digest"] = preview.Digest
	code, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/switching/imports", token, "n0004-year-zero", request)
	if code != http.StatusCreated {
		t.Fatalf("apply = %d: %s", code, body)
	}
	var imported struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &imported); err != nil || imported.ID == "" {
		t.Fatalf("import receipt = %s, err=%v", body, err)
	}
	rows, err := h.store.ListSwitchingImportRows(t.Context(), h.tenant, imported.ID, "", "", 0, 10)
	if err != nil || len(rows) != 1 || rows[0].Outcome != switchkit.OutcomeUnparseable || rows[0].NotAfter != nil {
		t.Fatalf("stored year-zero import rows = %+v, err=%v", rows, err)
	}
}
