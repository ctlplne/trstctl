// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
)

// P5-L4: an Elasticsearch audit feed presents token_ref's credential as an
// API key (the default), with basic auth (the credential is user:password)
// or as a bearer token. The scheme is Elasticsearch's alone, from a closed
// set, and a basic-auth credential that is not user:password fails the
// batch with nothing sent.
func TestServedElasticAuditFeedAuthSchemesP5L4(t *testing.T) {
	apiKey, basic, bearer, noColon := newP5Elastic(t), newP5Elastic(t), newP5Elastic(t), newP5Elastic(t)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.OutboundEnvCredentialRefs = []string{"env:TRSTCTL_P5L4_KEY", "env:TRSTCTL_P5L4_BASIC", "env:TRSTCTL_P5L4_BEARER", "env:TRSTCTL_P5L4_NOCOLON"}
	})
	t.Setenv("TRSTCTL_P5L4_KEY", "p5l4-key")
	t.Setenv("TRSTCTL_P5L4_BASIC", "elastic-writer:p5l4-pass")
	t.Setenv("TRSTCTL_P5L4_BEARER", "p5l4-bearer")
	t.Setenv("TRSTCTL_P5L4_NOCOLON", "p5l4-no-colon")
	token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "p5l4-operator", []string{
		string(authz.AuditRead), string(authz.AuditWrite), string(authz.OwnersWrite), string(authz.PrivateEgress),
	})
	feeds := []struct {
		id, scheme, ref, want string
		es                    *p5Elastic
	}{
		{"50505050-5050-4505-8505-505050505401", "", "env:TRSTCTL_P5L4_KEY", "api_key", apiKey},
		{"50505050-5050-4505-8505-505050505402", "basic", "env:TRSTCTL_P5L4_BASIC", "basic", basic},
		{"50505050-5050-4505-8505-505050505403", "bearer", "env:TRSTCTL_P5L4_BEARER", "bearer", bearer},
		{"50505050-5050-4505-8505-505050505404", "basic", "env:TRSTCTL_P5L4_NOCOLON", "basic", noColon},
	}
	for i, feed := range feeds {
		body := map[string]any{
			"name": "P5-L4 elastic " + strconv.Itoa(i), "provider": "elastic", "endpoint_url": feed.es.server.URL + "/trstctl-audit/_bulk",
			"token_ref": feed.ref, "interval_seconds": 300, "batch_size": 100, "enabled": true, // #nosec G101 -- token_ref is a non-secret environment locator (CWE-798)
			"allow_private_endpoint": true, "private_egress_cidrs": []string{"127.0.0.1/32", "::1/128"},
		}
		if feed.scheme != "" {
			body["auth_scheme"] = feed.scheme
		}
		putAuditFeedAUD52(t, h, token, feed.id, body)
	}
	status, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/audit/feeds", token, "", nil)
	var listed struct {
		Items []struct {
			ID         string `json:"id"`
			AuthScheme string `json:"auth_scheme"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &listed) != nil {
		t.Fatalf("list feeds: HTTP %d %s", status, body)
	}
	schemes := map[string]string{}
	for _, item := range listed.Items {
		schemes[item.ID] = item.AuthScheme
	}
	for _, feed := range feeds {
		if schemes[feed.id] != feed.want {
			t.Fatalf("feed %s reports auth_scheme %q, want %q", feed.id, schemes[feed.id], feed.want)
		}
	}

	// The scheme is Elasticsearch's alone, from a closed set.
	for name, refused := range map[string]map[string]any{
		"splunk": {"name": "P5-L4 splunk", "provider": "splunk-hec", "endpoint_url": apiKey.server.URL + "/services/collector/event", "auth_scheme": "bearer"},
		"digest": {"name": "P5-L4 digest", "provider": "elastic", "endpoint_url": apiKey.server.URL + "/trstctl-audit/_bulk", "auth_scheme": "digest"},
	} {
		refused["token_ref"], refused["interval_seconds"], refused["batch_size"], refused["enabled"] = "env:TRSTCTL_P5L4_KEY", 300, 100, true // #nosec G101 -- token_ref is a non-secret environment locator (CWE-798)
		refused["allow_private_endpoint"], refused["private_egress_cidrs"] = true, []string{"127.0.0.1/32"}
		if status, body := doBearer(t, h.ts, http.MethodPut, "/api/v1/audit/feeds/50505050-5050-4505-8505-505050505409", token, "p5l4-refused-"+name, refused); status != http.StatusBadRequest {
			t.Fatalf("%s: HTTP %d %s, want 400", name, status, body)
		}
	}

	ownerName := "P5-L4 team " + strconv.FormatInt(time.Now().UnixNano(), 10)
	if status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/owners", token, "p5l4-owner", map[string]any{
		"kind": "team", "name": ownerName, "email": "p5l4@example.test",
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
	if got := apiKey.auth(); got != "ApiKey p5l4-key" {
		t.Fatalf("api_key feed authorization = %q", got)
	}
	if got, want := basic.auth(), "Basic "+base64.StdEncoding.EncodeToString([]byte("elastic-writer:p5l4-pass")); got != want {
		t.Fatalf("basic feed authorization = %q, want %q", got, want)
	}
	if got := bearer.auth(); got != "Bearer p5l4-bearer" {
		t.Fatalf("bearer feed authorization = %q", got)
	}
	if len(apiKey.sequences()) == 0 || len(basic.sequences()) == 0 || len(bearer.sequences()) == 0 {
		t.Fatal("a feed delivered no records")
	}
	list := getAuditFeedsAUD52(t, h, token)
	for _, feed := range feeds[:3] {
		assertAuditFeedStatusAUD52(t, list, feed.id, "delivered", 1)
	}
	// Nothing reached the collector; the batch waits (its outbox error is the
	// classified code, never the credential) until the credential is fixed.
	if noColon.auth() != "" || len(noColon.sequences()) != 0 {
		t.Fatalf("a basic credential without user:password reached the collector: %q", noColon.auth())
	}
	assertAuditFeedStatusAUD52(t, list, feeds[3].id, "retrying", 0)
	var lastError string
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT o.last_error FROM audit_feed_destinations f
		   JOIN outbox o ON o.tenant_id = f.tenant_id AND o.idempotency_key = f.last_outbox_key
		  WHERE f.tenant_id = $1 AND f.id = $2`, h.tenant, feeds[3].id).Scan(&lastError); err != nil {
		t.Fatal(err)
	}
	if lastError != "external_delivery_failed" || strings.Contains(lastError, "p5l4-no-colon") {
		t.Fatalf("the waiting batch's reason = %q", lastError)
	}
}
