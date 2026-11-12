// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
)

// P5-L6 against a stock search engine: with the shipped ingest pipeline and
// index template installed, the elastic feed's records index with each
// event's own data unindexed, and every chain trailer is searchable by its
// own mapped fields (trstctl_trailer). Run by runners/p5l6-lab-proof.sh
// (OpenSearch 3.9.0); skipped otherwise.
func TestAuditFeedIndexTemplateMapsTheTrailerP5L6(t *testing.T) {
	esURL := os.Getenv("TRSTCTL_P5L6_LAB_ES")
	if esURL == "" {
		t.Skip("run runners/p5l6-lab-proof.sh (a local search engine)")
	}
	es := func(method, path string, body []byte) (int, []byte) {
		t.Helper()
		req, err := http.NewRequest(method, esURL+path, bytes.NewReader(body)) // #nosec G704 -- the runner's own lab search engine (CWE-918)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req) // #nosec G704 -- the runner's own lab search engine (CWE-918)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		out, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		return resp.StatusCode, out
	}
	for path, file := range map[string]string{
		"/_ingest/pipeline/trstctl-audit": "../../deploy/elastic/trstctl-audit-pipeline.json",
		"/_index_template/trstctl-audit":  "../../deploy/elastic/trstctl-audit-index-template.json",
	} {
		content, err := os.ReadFile(file) // #nosec G304 G703 -- the repository's own shipped content (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		if status, body := es(http.MethodPut, path, content); status != http.StatusOK {
			t.Fatalf("install %s: HTTP %d %s", path, status, body)
		}
	}
	const index = "trstctl-audit-p5l6"
	es(http.MethodDelete, "/"+index, nil)

	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.OutboundEnvCredentialRefs = []string{"env:TRSTCTL_P5L6_ES_KEY"}
	})
	t.Setenv("TRSTCTL_P5L6_ES_KEY", "p5l6-lab-key")
	token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "p5l6-lab-operator", []string{
		string(authz.AuditRead), string(authz.AuditWrite), string(authz.OwnersWrite), string(authz.PrivateEgress),
	})
	putAuditFeedAUD52(t, h, token, "50505050-5050-4505-8505-505050505601", map[string]any{
		"name": "P5-L6 lab", "provider": "elastic", "endpoint_url": esURL + "/" + index + "/_bulk",
		"token_ref": "env:TRSTCTL_P5L6_ES_KEY", "interval_seconds": 300, "batch_size": 100, "enabled": true, // #nosec G101 -- token_ref is a non-secret environment locator (CWE-798)
		"allow_private_endpoint": true, "private_egress_cidrs": []string{"127.0.0.1/32", "::1/128"},
	})
	ownerName := fmt.Sprintf("P5-L6 lab team %d", time.Now().UnixNano())
	if status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/owners", token, "p5l6-lab-owner", map[string]any{
		"kind": "team", "name": ownerName, "email": "p5l6-lab@example.test",
	}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed an audit record: HTTP %d %s", status, body)
	}
	if _, err := h.store.SystemPool().Exec(t.Context(),
		`UPDATE audit_feed_destinations SET next_run_at = now() - interval '1 second' WHERE tenant_id = $1`, h.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.RunAuditFeedSchedulerOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.outbox.Dispatch(t.Context(), h.srv.obHandler); err != nil {
		t.Fatal(err)
	}
	assertAuditFeedStatusAUD52(t, getAuditFeedsAUD52(t, h, token), "50505050-5050-4505-8505-505050505601", "delivered", 1)
	es(http.MethodPost, "/"+index+"/_refresh", nil)

	search := func(query string) []map[string]any {
		t.Helper()
		status, body := es(http.MethodGet, "/"+index+"/_search?size=100&q="+url.QueryEscape(query), nil)
		var out struct {
			Hits struct {
				Hits []struct {
					Source map[string]any `json:"_source"`
				} `json:"hits"`
			} `json:"hits"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &out) != nil {
			t.Fatalf("search %q: HTTP %d %s", query, status, body)
		}
		var docs []map[string]any
		for _, hit := range out.Hits.Hits {
			docs = append(docs, hit.Source)
		}
		return docs
	}
	trailers := search("event.kind:chain_trailer")
	if len(trailers) == 0 {
		t.Fatal("no document was marked a chain trailer")
	}
	mapped, _ := trailers[0]["trstctl_trailer"].(map[string]any)
	data, _ := trailers[0]["trstctl"].(map[string]any)["data"].(map[string]any)
	head, _ := mapped["chain_head"].(string)
	if head == "" || head != data["chain_head"] || mapped["batch_id"] != data["batch_id"] {
		t.Fatalf("trailer mapped %v from data %v", mapped, data)
	}
	if got := search(`trstctl_trailer.chain_head:"` + head + `"`); len(got) != 1 {
		t.Fatalf("a term query on the trailer's chain head found %d documents, want 1", len(got))
	}
	if records := search("event.kind:trstctl_record"); len(records) == 0 {
		t.Fatal("no audit record was marked trstctl_record")
	}
	// Each event's own data stays in _source, unindexed: searching it finds
	// nothing, so two event types can never conflict over a field.
	if got := search(`trstctl.data.name:"` + ownerName + `"`); len(got) != 0 {
		t.Fatalf("event data was indexed: %d hits", len(got))
	}
	status, body := es(http.MethodGet, "/"+index+"/_mapping", nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"data":{"type":"object","enabled":false}`) {
		t.Fatalf("index mapping: HTTP %d %s", status, body)
	}
	t.Logf("trailer %s for batch %v is a term query away; %d trailers indexed", head, mapped["batch_id"], len(trailers))
}
