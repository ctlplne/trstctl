// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// A233-L3: a tenant's audit feeds have distinct names. A second feed with a
// name another feed holds is a command refusal, a 409 problem body, and
// nothing is appended. It used to append the configuration event and fail its
// projection on the (tenant, name) index: the caller got a 500 and the event
// log kept an event that no projection could apply, so a rebuild stopped at
// it.
func TestServedAuditFeedDuplicateNameIsAConflictA233L3(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.OutboundEnvCredentialRefs = []string{"env:A233_SPLUNK_TOKEN"}
	})
	token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "a233-audit-operator", []string{
		string(authz.AuditRead), string(authz.AuditWrite),
	})
	feed := func(name string) map[string]any {
		return map[string]any{ // #nosec G101 -- token_ref is a non-secret environment locator (CWE-798).
			"name": name, "provider": "splunk-hec",
			"endpoint_url": "https://splunk.example.test/services/collector/event",
			"token_ref":    "env:A233_SPLUNK_TOKEN", "interval_seconds": 300, "batch_size": 100, "enabled": true,
		}
	}
	const first, second = "23323323-3233-4233-8233-233233233201", "23323323-3233-4233-8233-233233233202"
	if status, body := doBearer(t, h.ts, http.MethodPut, "/api/v1/audit/feeds/"+first, token, "a233-l3-first", feed("Security lake")); status != http.StatusOK {
		t.Fatalf("first feed: %d %s", status, body)
	}
	before, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	status, body := doBearer(t, h.ts, http.MethodPut, "/api/v1/audit/feeds/"+second, token, "a233-l3-second", feed(" Security lake "))
	var problem struct {
		Status int    `json:"status"`
		Title  string `json:"title"`
		Detail string `json:"detail"`
	}
	if status != http.StatusConflict || json.Unmarshal(body, &problem) != nil || problem.Status != http.StatusConflict ||
		!strings.Contains(problem.Detail, `"Security lake"`) {
		t.Fatalf("a second feed with the first's name = %d %s, want a 409 problem naming it", status, body)
	}
	after, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("the refused feed appended %d event(s)", after-before)
	}
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("the read model no longer rebuilds: %v", err)
	}
	// The effect-free preview names the same conflict.
	if status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/audit/feeds/"+second+"/preview", token, "", feed("Security lake")); status != http.StatusConflict {
		t.Fatalf("preview of a held name = %d %s, want 409", status, body)
	}

	// A log that already holds such an event (appended before this check
	// existed) rebuilds: the configuration applies as the no-op it was live,
	// and the name stays with the feed that held it.
	poisoned, err := json.Marshal(projections.AuditFeedDestinationConfigured{ // #nosec G101 -- token_ref is a non-secret environment locator (CWE-798).
		ID: "23323323-3233-4233-8233-233233233203", Name: "Security lake", Provider: "splunk-hec",
		EndpointURL: "https://splunk.example.test/services/collector/event", TokenRef: "env:A233_SPLUNK_TOKEN",
		IntervalSeconds: 300, BatchSize: 100, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.log.Append(t.Context(), events.Event{Type: projections.EventAuditFeedDestinationConfigured, TenantID: h.tenant, Data: poisoned}); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("a log holding a pre-check duplicate does not rebuild: %v", err)
	}
	if _, found, err := h.store.GetAuditFeed(t.Context(), h.tenant, "23323323-3233-4233-8233-233233233203"); err != nil || found {
		t.Fatalf("the duplicate configuration projected a feed: %v %v", found, err)
	}
	if held, found, err := h.store.GetAuditFeed(t.Context(), h.tenant, first); err != nil || !found || held.Name != "Security lake" {
		t.Fatalf("the first feed lost its name: %+v %v %v", held, found, err)
	}
	// The first feed keeps its name; a feed may keep its own name, and the
	// second feed may take a free one.
	if status, body := doBearer(t, h.ts, http.MethodPut, "/api/v1/audit/feeds/"+first, token, "a233-l3-first-again", feed("Security lake")); status != http.StatusOK {
		t.Fatalf("the first feed re-saved under its own name: %d %s", status, body)
	}
	if status, body := doBearer(t, h.ts, http.MethodPut, "/api/v1/audit/feeds/"+second, token, "a233-l3-second-free", feed("Archive lake")); status != http.StatusOK {
		t.Fatalf("the second feed under a free name: %d %s", status, body)
	}
}
