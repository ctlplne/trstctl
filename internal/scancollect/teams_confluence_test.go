// SPDX-License-Identifier: BUSL-1.1

package scancollect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	od4Team    = "2f3a9d1e-6c41-4b0e-9a57-0c1d2e3f4a5b"
	od4Channel = "19:ops0general@thread.tacv2"
	od4Poster  = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
)

// OD-4: a Teams channel's messages and replies are read from Microsoft
// Graph (pages and further replies followed on Graph's own origin) and
// written as the Teams export layout: messages.json per channel, each
// message naming its team and channel, replies beside it; deleted and older
// messages are left out; users.json holds the posters' addresses.
func TestCollectTeamsWritesTheExportLayoutOD4(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer graph-token" {
			http.Error(w, `{"error":{"code":"InvalidAuthenticationToken"}}`, http.StatusUnauthorized)
			return
		}
		base := "/v1.0/teams/" + od4Team + "/channels/" + od4Channel + "/messages"
		switch {
		case r.URL.Path == base && r.URL.Query().Get("$skiptoken") == "" && r.URL.Query().Get("$expand") == "replies":
			_, _ = fmt.Fprintf(w, `{"value":[
{"id":"1001","createdDateTime":"2026-11-05T10:00:00Z","lastModifiedDateTime":"2026-11-05T10:00:00Z","deletedDateTime":null,
 "from":{"user":{"id":"%[1]s","displayName":"Dev"}},"body":{"contentType":"html","content":"deploy key LEAK-OD4-message"},
 "replies":[{"id":"1002","replyToId":"1001","createdDateTime":"2026-11-05T10:05:00Z","lastModifiedDateTime":"2026-11-05T10:05:00Z","from":{"user":{"id":"%[1]s"}},"body":{"content":"first reply"}}],
 "replies@odata.nextLink":"%[2]s%[3]s/1001/replies?$skiptoken=r2"},
{"id":"1003","createdDateTime":"2026-11-05T11:00:00Z","lastModifiedDateTime":"2026-11-05T11:00:00Z","deletedDateTime":"2026-11-05T12:00:00Z","body":{"content":""}},
{"id":"1004","createdDateTime":"2026-10-01T09:00:00Z","lastModifiedDateTime":"2026-10-01T09:00:00Z","body":{"content":"old LEAK-OD4-old"}}],
"@odata.nextLink":"%[2]s%[3]s?$top=50&$expand=replies&$skiptoken=p2"}`, od4Poster, srv.URL, base)
		case r.URL.Path == base && r.URL.Query().Get("$skiptoken") == "p2":
			_, _ = fmt.Fprint(w, `{"value":[{"id":"1005","createdDateTime":"2026-11-06T08:00:00Z","lastModifiedDateTime":"2026-11-06T08:00:00Z","body":{"content":"second page"}}]}`)
		case r.URL.Path == base+"/1001/replies" && r.URL.Query().Get("$skiptoken") == "r2":
			_, _ = fmt.Fprint(w, `{"value":[{"id":"1006","replyToId":"1001","createdDateTime":"2026-11-05T10:30:00Z","lastModifiedDateTime":"2026-11-05T10:30:00Z","body":{"content":"late reply LEAK-OD4-reply"}}]}`)
		case r.URL.Path == "/v1.0/users/"+od4Poster && r.URL.Query().Get("$select") == "id,mail":
			_, _ = fmt.Fprintf(w, `{"id":"%s","mail":"dev@example.test"}`, od4Poster)
		default:
			http.Error(w, `{"error":{"code":"NotFound"}}`, http.StatusNotFound)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	res, err := Collect(context.Background(), dir, Request{Provider: ProviderTeams, BaseURL: srv.URL, Token: []byte("graph-token"),
		Team: od4Team, Channels: []string{od4Channel}, Since: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Doer: srv.Client()})
	if err != nil || res.Items != 4 {
		t.Fatalf("collect = %+v %v, want the message, its two replies and the second page", res, err)
	}
	var messages []map[string]any
	if err := json.Unmarshal([]byte(readFile(t, dir, "channel-1/messages.json")), &messages); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, m := range messages {
		ids = append(ids, m["id"].(string))
		identity, _ := m["channelIdentity"].(map[string]any)
		if identity["teamId"] != od4Team || identity["channelId"] != od4Channel || m["replies"] != nil {
			t.Fatalf("message %v = %+v", m["id"], m)
		}
	}
	if strings.Join(ids, ",") != "1001,1002,1006,1005" {
		t.Fatalf("messages = %v, want the deleted and the older message left out", ids)
	}
	if channels := readFile(t, dir, "channels.json"); !strings.Contains(channels, od4Channel) || !strings.Contains(channels, `"channel-1"`) {
		t.Fatalf("channels.json = %s", channels)
	}
	if users := readFile(t, dir, "users.json"); !strings.Contains(users, "dev@example.test") {
		t.Fatalf("users.json = %s", users)
	}

	// A next page on another origin is refused before anything is sent there.
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"value":[],"@odata.nextLink":"https://graph.example.invalid/v1.0/next"}`)
	}))
	defer elsewhere.Close()
	if _, err := Collect(context.Background(), t.TempDir(), Request{Provider: ProviderTeams, BaseURL: elsewhere.URL, Token: []byte("graph-token"),
		Team: od4Team, Channels: []string{od4Channel}, Doer: elsewhere.Client()}); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "next page leaves") {
		t.Fatalf("a next page on another origin = %v", err)
	}
	if _, err := Collect(context.Background(), t.TempDir(), Request{Provider: ProviderTeams, BaseURL: srv.URL, Token: []byte("wrong"),
		Team: od4Team, Channels: []string{od4Channel}, Doer: srv.Client()}); !errors.Is(err, ErrRefused) {
		t.Fatalf("bad credentials = %v", err)
	}
	for name, req := range map[string]Request{
		"team":    {Team: "not-a-guid", Channels: []string{od4Channel}},
		"channel": {Team: od4Team, Channels: []string{"general"}},
		"none":    {Team: od4Team},
	} {
		req.Provider, req.BaseURL, req.Token, req.Doer = ProviderTeams, srv.URL, []byte("graph-token"), srv.Client()
		if _, err := Collect(context.Background(), t.TempDir(), req); !errors.Is(err, ErrRefused) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// OD-4: Confluence content is read by CQL from the search (Confluence's own
// site-relative next links followed) and written as content.json, the
// search results.
func TestCollectConfluenceWritesTheExportLayoutOD4(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wiki/rest/api/content/search" || r.Header.Get("Authorization") != "Basic "+"b3BzQGV4YW1wbGUudGVzdDpjb25mbHVlbmNlLXRva2Vu" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		queries = append(queries, r.URL.Query().Get("cql"))
		if r.URL.Query().Get("expand") != "body.storage,version,space" {
			http.Error(w, "bad expand", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("cursor") == "" {
			_, _ = fmt.Fprint(w, `{"results":[
{"id":"101","type":"page","title":"Runbook","space":{"key":"ENG"},"body":{"storage":{"value":"<p>LEAK-OD4-page</p>"}}},
{"id":"not-an-id","type":"page"},
{"id":"102","type":"comment","space":{"key":"ENG"},"body":{"storage":{"value":"<p>see above</p>"}}}],
"size":3,"_links":{"base":"https://example.invalid/wiki","next":"/rest/api/content/search?cql=space%3DENG&cursor=abc&limit=50&expand=body.storage,version,space"}}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"results":[{"id":"103","type":"blogpost","space":{"key":"ENG"},"body":{"storage":{"value":"<p>news</p>"}}}],"size":1,"_links":{}}`)
	}))
	defer srv.Close()
	dir := t.TempDir()
	res, err := Collect(context.Background(), dir, Request{Provider: ProviderConfluence, BaseURL: srv.URL + "/wiki", Username: "ops@example.test",
		Token: []byte("confluence-token"), CQL: "space = ENG", Since: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Doer: srv.Client()})
	if err != nil || res.Items != 3 {
		t.Fatalf("collect = %+v %v", res, err)
	}
	if len(queries) != 2 || queries[0] != `(space = ENG) AND lastmodified >= "2026-11-01 00:00"` {
		t.Fatalf("queries = %q", queries)
	}
	var export struct {
		Results []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(readFile(t, dir, "content.json")), &export); err != nil || len(export.Results) != 3 ||
		export.Results[0].ID != "101" || export.Results[2].Type != "blogpost" {
		t.Fatalf("content.json = %+v %v", export, err)
	}

	// A next link that is not relative to the site is refused.
	offsite := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"results":[{"id":"1","type":"page"}],"_links":{"next":"https://example.invalid/rest/api/content/search?cursor=x"}}`)
	}))
	defer offsite.Close()
	if _, err := Collect(context.Background(), t.TempDir(), Request{Provider: ProviderConfluence, BaseURL: offsite.URL, Token: []byte("t"),
		CQL: "space = ENG", Doer: offsite.Client()}); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "not on the site") {
		t.Fatalf("an off-site next link = %v", err)
	}
	if _, err := Collect(context.Background(), t.TempDir(), Request{Provider: ProviderConfluence, BaseURL: srv.URL + "/wiki", Token: []byte("x"),
		CQL: "space = ENG", Doer: srv.Client()}); !errors.Is(err, ErrRefused) {
		t.Fatalf("bad credentials = %v", err)
	}
}
