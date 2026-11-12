// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// OD-4 Done-when: a leaked-secret scan collects Microsoft Teams channel
// messages from Microsoft Graph and Confluence content by CQL, against
// stand-ins written from their public API references, and finds the leaks
// in them. Each finding names its Teams message (team, channel, message,
// the message it replies to, the poster and their address) or its
// Confluence content (ID, type, space) and never the content; a wrong token
// fails its run; a Graph next page on another origin is refused; a Teams
// finding is linked to the poster's owner by address; the scan posture lists
// both providers. The live Teams and Confluence runs are a
// Track B proof.
func TestServedTeamsAndConfluenceCollectionOD4(t *testing.T) {
	const team, channel, poster = "2f3a9d1e-6c41-4b0e-9a57-0c1d2e3f4a5b", "19:ops0general@thread.tacv2", "7c9e6679-7425-40de-944b-e07fc1f90ae7"
	messages := "/v1.0/teams/" + team + "/channels/" + channel + "/messages"
	var graph *httptest.Server
	graph = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer od4-graph-value" {
			http.Error(w, `{"error":{"code":"InvalidAuthenticationToken"}}`, http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == messages && r.URL.Query().Get("$skiptoken") == "":
			_, _ = fmt.Fprintf(w, `{"value":[
{"id":"1001","createdDateTime":"2026-11-05T10:00:00Z","lastModifiedDateTime":"2026-11-05T10:00:00Z","from":{"user":{"id":"%[1]s"}},"body":{"content":"deploying"},
 "replies":[{"id":"1002","replyToId":"1001","createdDateTime":"2026-11-05T10:05:00Z","lastModifiedDateTime":"2026-11-05T10:05:00Z","from":{"user":{"id":"%[1]s"}},"body":{"content":"use LEAK-OD4-teams"}}]}],
"@odata.nextLink":"%[2]s%[3]s?$top=50&$expand=replies&$skiptoken=p2"}`, poster, graph.URL, messages)
		case r.URL.Path == messages && r.URL.Query().Get("$skiptoken") == "p2":
			_, _ = fmt.Fprint(w, `{"value":[{"id":"1003","createdDateTime":"2026-11-06T08:00:00Z","lastModifiedDateTime":"2026-11-06T08:00:00Z","body":{"content":"all good"}}]}`)
		case r.URL.Path == "/v1.0/users/"+poster:
			_, _ = fmt.Fprintf(w, `{"id":"%s","mail":"dev@example.test"}`, poster)
		default:
			http.Error(w, `{"error":{"code":"NotFound"}}`, http.StatusNotFound)
		}
	}))
	t.Cleanup(graph.Close)
	offsite := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"value":[],"@odata.nextLink":"https://graph.example.invalid/v1.0/next"}`)
	}))
	t.Cleanup(offsite.Close)
	confluence := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wiki/rest/api/content/search" || r.Header.Get("Authorization") != "Bearer od4-wiki-value" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("cursor") == "" {
			_, _ = fmt.Fprint(w, `{"results":[{"id":"201","type":"page","title":"Runbook","space":{"key":"ENG"},"body":{"storage":{"value":"<p>fine</p>"}}}],
"_links":{"next":"/rest/api/content/search?cql=space%3DENG&cursor=c2&limit=50&expand=body.storage,version,space"}}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"results":[{"id":"202","type":"comment","space":{"key":"ENG"},"body":{"storage":{"value":"<p>password LEAK-OD4-confluence</p>"}}}],"_links":{}}`)
	}))
	t.Cleanup(confluence.Close)

	t.Setenv("TRSTCTL_OD4_GRAPH", "od4-graph-value")
	t.Setenv("TRSTCTL_OD4_WIKI", "od4-wiki-value")
	t.Setenv("TRSTCTL_OD4_WRONG", "not-the-value")
	scanner := &a174MarkerScanner{marker: "LEAK-OD4"}
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil),
		allowOutboundEnvCredentialRefs("env:TRSTCTL_OD4_GRAPH", "env:TRSTCTL_OD4_WIKI", "env:TRSTCTL_OD4_WRONG"),
		func(d *Deps) { d.SecretScanner = scanner })
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "discovery:read", string(authz.PrivateEgress))
	owner, err := h.store.CreateOwner(context.Background(), store.Owner{TenantID: h.tenant, Kind: store.OwnerWorkload, Name: "od4 platform", Email: "dev@example.test"})
	if err != nil {
		t.Fatal(err)
	}

	ingest := func(provider, source string, collect map[string]any) string {
		t.Helper()
		collect["allow_private_endpoint"], collect["private_egress_cidrs"] = true, []string{"127.0.0.1/32"}
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/third-party/"+provider+"/ingest", tok, "od4-"+source,
			map[string]any{"source": source, "event": "od4", "collect": collect})
		var receipt struct {
			RunID string `json:"run_id"`
		}
		if status != http.StatusAccepted || json.Unmarshal(body, &receipt) != nil || receipt.RunID == "" {
			t.Fatalf("ingest %s: HTTP %d %s", source, status, body)
		}
		return receipt.RunID
	}
	runs := map[string]string{
		"teams":      ingest("teams", "ops-teams", map[string]any{"base_url": graph.URL, "token_ref": "env:TRSTCTL_OD4_GRAPH", "team": team, "channels": []string{channel}}),           // #nosec G101 -- env: references to test-only stand-in values (CWE-798)
		"confluence": ingest("confluence", "eng-wiki", map[string]any{"base_url": confluence.URL + "/wiki", "token_ref": "env:TRSTCTL_OD4_WIKI", "cql": "space = ENG"}),                // #nosec G101 -- env: references to test-only stand-in values (CWE-798)
		"wrong":      ingest("teams", "ops-teams-wrong", map[string]any{"base_url": graph.URL, "token_ref": "env:TRSTCTL_OD4_WRONG", "team": team, "channels": []string{channel}}),     // #nosec G101 -- env: references to test-only stand-in values (CWE-798)
		"offsite":    ingest("teams", "ops-teams-offsite", map[string]any{"base_url": offsite.URL, "token_ref": "env:TRSTCTL_OD4_GRAPH", "team": team, "channels": []string{channel}}), // #nosec G101 -- env: references to test-only stand-in values (CWE-798)
	}
	runStatus := func(runID string) (string, string) {
		var status, detail string
		_ = h.store.SystemPool().QueryRow(t.Context(), `SELECT status, coalesce(error, '') FROM discovery_runs WHERE tenant_id = $1 AND id = $2`, h.tenant, runID).Scan(&status, &detail)
		return status, detail
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		h.srv.dispatchOnce(context.Background())
		done := 0
		for _, runID := range runs {
			if status, _ := runStatus(runID); status == "succeeded" || status == "failed" {
				done++
			}
		}
		if done == len(runs) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("collections did not finish: %v", runs)
		}
		time.Sleep(100 * time.Millisecond)
	}
	type finding struct {
		Metadata map[string]any `json:"metadata"`
	}
	ownerOf := func(f finding) string {
		id, _ := f.Metadata["owner_id"].(string)
		return id
	}
	findings := func(name string) []finding {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+runs[name], tok, nil)
		var list struct {
			Items []finding `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &list) != nil {
			t.Fatalf("%s findings: HTTP %d %s", name, status, body)
		}
		if strings.Contains(string(body), "LEAK-OD4") || strings.Contains(string(body), "Runbook") {
			t.Fatalf("%s findings carry collected content: %s", name, body)
		}
		return list.Items
	}
	object := func(f finding) map[string]any {
		o, _ := f.Metadata["provider_object"].(map[string]any)
		return o
	}
	for _, name := range []string{"teams", "confluence"} {
		if status, detail := runStatus(runs[name]); status != "succeeded" {
			t.Fatalf("%s run = %s %s", name, status, detail)
		}
	}
	teams := findings("teams")
	if len(teams) != 1 {
		t.Fatalf("teams findings = %+v", teams)
	}
	for key, want := range map[string]string{"kind": "teams_message", "team_id": team, "channel_id": channel, "message_id": "1002",
		"reply_to_id": "1001", "user": poster, "user_email": "dev@example.test"} {
		if got := object(teams[0])[key]; got != want {
			t.Fatalf("teams finding %s = %v, want %s (%+v)", key, got, want, teams[0])
		}
	}
	if ownerOf(teams[0]) != owner.ID {
		t.Fatalf("the Teams finding's owner = %q, want the poster's owner %s", ownerOf(teams[0]), owner.ID)
	}
	wiki := findings("confluence")
	if len(wiki) != 1 || object(wiki[0])["kind"] != "confluence_content" || object(wiki[0])["content_id"] != "202" ||
		object(wiki[0])["content_type"] != "comment" || object(wiki[0])["space_key"] != "ENG" {
		t.Fatalf("confluence findings = %+v", wiki)
	}
	if status, detail := runStatus(runs["wrong"]); status != "failed" || !strings.Contains(detail, "401") || strings.Contains(detail, "not-the-value") {
		t.Fatalf("a wrong Graph token = %s %q", status, detail)
	}
	if status, detail := runStatus(runs["offsite"]); status != "failed" || !strings.Contains(detail, "next page leaves") {
		t.Fatalf("an off-origin Graph next page = %s %q", status, detail)
	}

	// The scan posture lists both providers and their ingest paths.
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/scans/third-party", tok, nil)
	var posture struct {
		Providers []struct {
			ID string `json:"id"`
		} `json:"providers"`
		IngestPaths []string `json:"ingest_paths"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &posture) != nil {
		t.Fatalf("posture = %d %s", status, body)
	}
	var ids []string
	for _, p := range posture.Providers {
		ids = append(ids, p.ID)
	}
	if got := strings.Join(ids, ","); !strings.Contains(got, "teams") || !strings.Contains(got, "confluence") ||
		!strings.Contains(strings.Join(posture.IngestPaths, " "), "/third-party/confluence/ingest") {
		t.Fatalf("posture providers = %s, paths %v", got, posture.IngestPaths)
	}
}
