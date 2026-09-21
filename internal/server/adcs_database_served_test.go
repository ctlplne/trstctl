// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// F4 end-to-end through the served binary: a relay POSTs certutil rows from an
// AD CS CA database, the control plane parses and summarizes them by
// disposition, and the per-CA lifecycle breakdown reads back. This exercises
// the production callers of adcs.ParseDBRow and adcs.Summarize, which had none.
func TestServedADCSDatabaseIngestionAndVisibility(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "adcs-operator", []string{
		"discovery:read", "discovery:write",
	})

	// certutil-shaped rows: the disposition codes are certutil's own (20 issued,
	// 9 pending, 21 revoked, 31 denied, 30 failed, 99 an unrecognized code).
	rows := []map[string]string{
		{"RequestID": "101", "SerialNumber": "0a0b0c", "CommonName": "web1.corp", "Request.Disposition": "20", "NotAfter": "2027-01-01 00:00:00"},
		{"RequestID": "102", "SerialNumber": "0a0b0d", "CommonName": "web2.corp", "Request.Disposition": "20"}, // issued, NotAfter unparseable -> unparsed
		{"RequestID": "103", "CommonName": "pending.corp", "Request.Disposition": "9"},                         // PENDING a CA manager
		{"RequestID": "104", "SerialNumber": "0a0b0e", "CommonName": "old.corp", "Request.Disposition": "21", "Request.RevokedWhen": "2026-06-01 00:00:00"},
		{"RequestID": "105", "CommonName": "denied.corp", "Request.Disposition": "31"},
		{"RequestID": "106", "CommonName": "failed.corp", "Request.Disposition": "30"},
		{"RequestID": "107", "CommonName": "future.corp", "Request.Disposition": "99"}, // unrecognized -> unknown, never failed
		{"CommonName": "no-request-id.corp", "Request.Disposition": "20"},              // no RequestID -> rejected, not counted as issued
	}
	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/adcs/ca-database/ingest", token, "adcs-ingest-1", map[string]any{
		"ca_config": "DC01\\Corp Issuing CA",
		"rows":      rows,
		"source":    "relay-dc01",
	})
	if code != http.StatusOK {
		t.Fatalf("ingest = %d body=%s", code, body)
	}
	var ingested struct {
		Issued       int `json:"issued"`
		Pending      int `json:"pending"`
		Revoked      int `json:"revoked"`
		Denied       int `json:"denied"`
		Failed       int `json:"failed"`
		Unknown      int `json:"unknown"`
		Unparsed     int `json:"unparsed"`
		Total        int `json:"total"`
		RowsRead     int `json:"rows_read"`
		RowsRejected int `json:"rows_rejected"`
	}
	if err := json.Unmarshal(body, &ingested); err != nil {
		t.Fatalf("decode ingest: %v", err)
	}
	// The load-bearing distinctions: pending is NOT failed, an unrecognized code
	// is unknown NOT failed, an unparseable-expiry issued row is flagged
	// unparsed, and the id-less row is rejected rather than folded into issued.
	if ingested.Issued != 2 || ingested.Pending != 1 || ingested.Revoked != 1 ||
		ingested.Denied != 1 || ingested.Failed != 1 || ingested.Unknown != 1 {
		t.Fatalf("disposition counts = %+v; pending/denied/failed/unknown must stay distinct", ingested)
	}
	if ingested.Unparsed != 1 {
		t.Fatalf("unparsed = %d, want 1: an issued row whose expiry could not be read is a visibility gap", ingested.Unparsed)
	}
	if ingested.RowsRead != 8 || ingested.RowsRejected != 1 || ingested.Total != 7 {
		t.Fatalf("read=%d rejected=%d total=%d; the id-less row must be rejected, not dropped silently",
			ingested.RowsRead, ingested.RowsRejected, ingested.Total)
	}

	// Read back the served lifecycle visibility.
	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/adcs/ca-database", token, "", nil)
	if code != http.StatusOK {
		t.Fatalf("list = %d body=%s", code, body)
	}
	var list struct {
		Items []struct {
			CAConfig string `json:"ca_config"`
			Pending  int    `json:"pending"`
			Issued   int    `json:"issued"`
			Source   string `json:"source"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Items) != 1 || list.Items[0].CAConfig != "DC01\\Corp Issuing CA" ||
		list.Items[0].Pending != 1 || list.Items[0].Source != "relay-dc01" {
		t.Fatalf("served visibility = %+v, want the one CA with its pending count and source", list.Items)
	}

	// A second sweep of the same CA REPLACES the summary (latest wins), not
	// accumulates — the read model is the current state, not a running total.
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/adcs/ca-database/ingest", token, "adcs-ingest-2", map[string]any{
		"ca_config": "DC01\\Corp Issuing CA",
		"rows":      []map[string]string{{"RequestID": "201", "Request.Disposition": "20"}},
		"source":    "relay-dc01",
	})
	if code != http.StatusOK {
		t.Fatalf("second ingest = %d body=%s", code, body)
	}
	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/adcs/ca-database", token, "", nil)
	if code != http.StatusOK {
		t.Fatalf("list-2 = %d", code)
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 || list.Items[0].Issued != 1 || list.Items[0].Pending != 0 {
		t.Fatalf("after re-sweep = %+v, want the latest breakdown (1 issued, 0 pending), not an accumulation", list.Items)
	}
}
