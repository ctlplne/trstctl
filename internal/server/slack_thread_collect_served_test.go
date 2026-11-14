// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
)

// N6-L1: a native Slack collection reads each thread's replies
// (conversations.replies, cursor pages), filed as Slack's export files them,
// so a secret posted in a reply is found and its finding names the reply and
// the thread it sits in. The stand-in follows Slack's API reference: the
// channel history holds the thread's parent (with its reply_count) but not
// its replies.
func TestServedNativeLeakScanReadsSlackThreadRepliesN6L1(t *testing.T) {
	const channel, parentTS, replyTS = "C0N6L1OPS", "1762246800.000100", "1762250400.000200"
	var mu sync.Mutex
	var replyPages []string
	slack := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer n6l1-slack-token" {
			_, _ = fmt.Fprint(w, `{"ok":false,"error":"invalid_auth"}`)
			return
		}
		q := r.URL.Query()
		switch r.URL.Path {
		case "/api/conversations.history":
			_, _ = fmt.Fprintf(w, `{"ok":true,"messages":[{"ts":"1762243200.000050","text":"good morning"},`+
				`{"ts":%q,"thread_ts":%q,"reply_count":2,"text":"the deploy thread"}],"has_more":false}`, parentTS, parentTS)
		case "/api/conversations.replies":
			mu.Lock()
			replyPages = append(replyPages, q.Get("channel")+"/"+q.Get("ts")+"/"+q.Get("cursor"))
			mu.Unlock()
			if q.Get("channel") != channel || q.Get("ts") != parentTS {
				_, _ = fmt.Fprint(w, `{"ok":false,"error":"thread_not_found"}`)
				return
			}
			if q.Get("cursor") == "" {
				_, _ = fmt.Fprintf(w, `{"ok":true,"messages":[{"ts":%q,"thread_ts":%q,"reply_count":2,"text":"the deploy thread"},`+
					`{"ts":"1762248600.000150","thread_ts":%q,"text":"which key?"}],"has_more":true,"response_metadata":{"next_cursor":"n6l1-page-2"}}`,
					parentTS, parentTS, parentTS)
				return
			}
			_, _ = fmt.Fprintf(w, `{"ok":true,"messages":[{"ts":%q,"thread_ts":%q,"text":"use LEAK-N6L1-reply"}],"has_more":false}`, replyTS, parentTS)
		default:
			_, _ = fmt.Fprint(w, `{"ok":false,"error":"unknown_method"}`)
		}
	}))
	t.Cleanup(slack.Close)
	t.Setenv("TRSTCTL_N6L1_SLACK", "n6l1-slack-token")
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil),
		allowOutboundEnvCredentialRefs("env:TRSTCTL_N6L1_SLACK"),
		func(d *Deps) { d.SecretScanner = &a174MarkerScanner{marker: "LEAK-N6L1"} })
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "discovery:read", string(authz.PrivateEgress))

	collect := map[string]any{"base_url": slack.URL, "token_ref": "env:TRSTCTL_N6L1_SLACK", "channels": []string{channel}, // #nosec G101 -- an env: reference to a test-only stand-in token, no credential value (CWE-798)
		"allow_private_endpoint": true, "private_egress_cidrs": []string{"127.0.0.1/32"}}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/third-party/slack/ingest", tok, "n6l1-ops-threads",
		map[string]any{"source": "ops-slack-threads", "event": "n6l1", "collect": collect})
	var receipt struct {
		RunID string `json:"run_id"`
	}
	if status != http.StatusAccepted || json.Unmarshal(body, &receipt) != nil || receipt.RunID == "" {
		t.Fatalf("ingest: HTTP %d %s", status, body)
	}
	var runStatus, runError string
	deadline := time.Now().Add(30 * time.Second)
	for {
		h.srv.dispatchOnce(context.Background())
		_ = h.store.SystemPool().QueryRow(t.Context(), `SELECT status, coalesce(error, '') FROM discovery_runs WHERE tenant_id = $1 AND id = $2`,
			h.tenant, receipt.RunID).Scan(&runStatus, &runError)
		if runStatus == "succeeded" || runStatus == "failed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the collection did not finish: %s", runStatus)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if runStatus != "succeeded" {
		t.Fatalf("the collection = %s %q", runStatus, runError)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+receipt.RunID, tok, nil)
	var list struct {
		Items []struct {
			Metadata map[string]any `json:"metadata"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &list) != nil {
		t.Fatalf("findings: HTTP %d %s", status, body)
	}
	if strings.Contains(string(body), "LEAK-N6L1") {
		t.Fatalf("the findings carry collected content: %s", body)
	}
	if len(list.Items) != 1 {
		t.Fatalf("findings = %s; want the one in the thread's reply", body)
	}
	object, _ := list.Items[0].Metadata["provider_object"].(map[string]any)
	if object["channel_id"] != channel || object["message_ts"] != replyTS || object["thread_ts"] != parentTS {
		t.Fatalf("the finding's object = %+v; want the reply %s in thread %s of %s", object, replyTS, parentTS, channel)
	}
	// The history's two messages and the thread's two replies; the parent,
	// also on the thread's first page, is kept once.
	if items := list.Items[0].Metadata["collected_items"]; items != float64(4) || list.Items[0].Metadata["collection_truncated"] != false {
		t.Fatalf("the finding's collection = %v items, truncated %v", items, list.Items[0].Metadata["collection_truncated"])
	}
	mu.Lock()
	pages := strings.Join(replyPages, ",")
	mu.Unlock()
	if want := channel + "/" + parentTS + "/," + channel + "/" + parentTS + "/n6l1-page-2"; pages != want {
		t.Fatalf("thread pages read = %s; want %s", pages, want)
	}
	if h.logContains(t, "LEAK-N6L1") || h.logContains(t, "n6l1-slack-token") {
		t.Fatal("collected content or the collection token reached the event log")
	}
	t.Logf("N6L1_THREAD_REPLY_OK channel=%s message_ts=%s thread_ts=%s items=4", channel, replyTS, parentTS)
}
