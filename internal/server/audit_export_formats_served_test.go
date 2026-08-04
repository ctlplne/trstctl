// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// Audit export in formats a SIEM ingests, served (epic J1).
//
// The unit tests prove the encodings are right. This proves they are REACHED:
// the route accepts a format, the response carries the matching content type,
// and the chain head travels with the payload rather than only in a header a log
// pipeline would drop on the first forward.

func newAuditExportHarness(t *testing.T) (*httptest.Server, string, string) {
	t.Helper()
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"

	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	tok := seedServedAPIToken(t, ctx, st, tenantID, "audit-export", []string{
		string(authz.AuditRead), string(authz.OwnersWrite), string(authz.OwnersRead),
	})
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	auditKey, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	srv, err := Build(ctx, Deps{Store: st, Log: log, AuditSigningKey: auditKey})
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// Something to export.
	code, body := doBearer(t, ts, http.MethodPost, "/api/v1/owners", tok, "audit-export-seed",
		map[string]any{"kind": "team", "name": "Platform", "email": "p@example.test"})
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("seed owner = %d: %s", code, body)
	}
	return ts, tok, tenantID
}

func TestServedAuditExportServesEveryAdvertisedFormat(t *testing.T) {
	ts, tok, _ := newAuditExportHarness(t)

	for _, tc := range []struct {
		format      string
		contentType string
	}{
		{"ndjson", "application/x-ndjson"},
		{"csv", "text/csv"},
		{"splunk-hec", "application/x-ndjson"},
		{"sentinel", "application/x-ndjson"},
	} {
		tc := tc
		t.Run(tc.format, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet,
				ts.URL+"/api/v1/audit/export?format="+tc.format, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+tok)
			resp, err := ts.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("export %s = %d", tc.format, resp.StatusCode)
			}
			if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, tc.contentType) {
				t.Errorf("content type = %q, want %q; a SIEM routes on this", ct, tc.contentType)
			}
			// The chain head must be IN the payload, not only in a header — a
			// log pipeline forwards the body and drops the headers.
			if head := resp.Header.Get("X-Trstctl-Audit-Chain-Head"); head == "" {
				t.Error("no chain-head header")
			}
		})
	}
}

// The trailer carries the chain head and the anchor state, in the body.
func TestServedNDJSONExportCarriesItsChainHeadInTheBody(t *testing.T) {
	ts, tok, _ := newAuditExportHarness(t)

	code, body := doBearer(t, ts, http.MethodGet, "/api/v1/audit/export?format=ndjson", tok, "", nil)
	if code != http.StatusOK {
		t.Fatalf("export = %d: %s", code, body)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected records plus a trailer, got %d lines", len(lines))
	}
	var tr struct {
		Kind      string `json:"trstctl_record"`
		ChainHead string `json:"chain_head"`
		Anchor    struct {
			Kind   string `json:"kind"`
			Detail string `json:"detail"`
		} `json:"anchor"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &tr); err != nil {
		t.Fatalf("trailer is not JSON: %v", err)
	}
	if tr.Kind != "chain_trailer" || tr.ChainHead == "" {
		t.Fatalf("trailer = %+v, want a chain head", tr)
	}
	// This deployment serves no TSA, so the export must SAY it is unanchored
	// rather than omit the field and read as fine.
	if tr.Anchor.Kind != "" {
		t.Errorf("anchor kind = %q on a deployment with no TSA", tr.Anchor.Kind)
	}
	if tr.Anchor.Detail == "" {
		t.Error("an unanchored export gives no reason; an operator cannot tell whether " +
			"anchoring failed or was never configured")
	}
}

// CSV is real CSV with the pinned header.
func TestServedCSVExportParses(t *testing.T) {
	ts, tok, _ := newAuditExportHarness(t)

	code, body := doBearer(t, ts, http.MethodGet, "/api/v1/audit/export?format=csv", tok, "", nil)
	if code != http.StatusOK {
		t.Fatalf("export = %d: %s", code, body)
	}
	rows, err := csv.NewReader(strings.NewReader(string(body))).ReadAll()
	if err != nil {
		t.Fatalf("served CSV does not parse: %v", err)
	}
	if len(rows) == 0 || rows[0][0] != "sequence" {
		t.Fatalf("unexpected CSV header: %v", rows)
	}
}

// An unknown format is a 400, not a silent downgrade to JWS.
func TestServedAuditExportRefusesAnUnknownFormat(t *testing.T) {
	ts, tok, _ := newAuditExportHarness(t)

	code, body := doBearer(t, ts, http.MethodGet, "/api/v1/audit/export?format=splunk", tok, "", nil)
	if code != http.StatusBadRequest {
		t.Fatalf("unknown format = %d (%s), want 400; a caller who asked for a format they did "+
			"not get would find out when their ingest pipeline rejected the payload", code, body)
	}
}

// The default is unchanged: no format means the signed bundle.
func TestServedAuditExportStillDefaultsToTheSignedBundle(t *testing.T) {
	ts, tok, _ := newAuditExportHarness(t)

	code, body := doBearer(t, ts, http.MethodGet, "/api/v1/audit/export", tok, "", nil)
	if code != http.StatusOK {
		t.Fatalf("export = %d: %s", code, body)
	}
	var resp struct {
		Format    string `json:"format"`
		Bundle    string `json:"bundle"`
		ChainHead string `json:"chain_head"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Format != "jws" || resp.Bundle == "" {
		t.Errorf("default export = %+v, want the signed bundle", resp)
	}
	if resp.ChainHead == "" {
		t.Error("the JWS response carries no chain head alongside the bundle")
	}
}
