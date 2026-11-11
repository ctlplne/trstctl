// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
)

// N8-L1: an approval request is posted to Slack once, even when the answer to
// the post is lost. Slack kept the message but the connection dropped before
// trstctl recorded it, so the outbox delivers the post again; the retry finds
// the first message by the metadata it was posted with and records it instead
// of posting a second. That check needs the channel's history, which trstctl
// asks for at install: an install made before (granted only posting and the
// channel list) says it does not check, and installing again turns it on.
func TestServedSlackApprovalPostedOnceAfterALostAnswerN8L1(t *testing.T) {
	stand := newN8SlackStandIn(t)
	stand.scope = "chat:write,channels:read,groups:read"
	t.Setenv("TRSTCTL_N8L1_CLIENT_SECRET", "n8-client-secret")
	t.Setenv("TRSTCTL_N8L1_SIGNING", "n8l1-signing-secret")
	slackCfg := config.SlackAppConfig{ClientID: "n8-client", ClientSecretRef: "env:TRSTCTL_N8L1_CLIENT_SECRET", SigningSecretRef: "env:TRSTCTL_N8L1_SIGNING", // #nosec G101 -- env: references to test-only values, no credential (CWE-798)
		APIBase: stand.URL, PublicURL: "https://trstctl.example.test", AllowPrivateAPI: true, PrivateEgressCIDRs: []string{"127.0.0.1/32"}}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.RequireApproval, d.RequiredApprovals = true, 1
		d.SlackApp = slackCfg
	})
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "n8l1-admin@example.test",
		string(authz.ConnectorsRead), string(authz.ConnectorsWrite))
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "n8l1-requester@example.test",
		string(authz.OwnersWrite), string(authz.IdentitiesWrite), string(authz.CertsRequest), string(authz.CertsIssue), string(authz.IdentitiesRead))
	call := func(token, method, path, key string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReqKey(t, h, method, path, token, key, body)
		if status != want {
			t.Fatalf("%s %s = %d, want %d: %s", method, path, status, want, raw)
		}
		return raw
	}
	// Served tests share their tenant's database while each has its own
	// event log: an install another test left behind would outrank this
	// test's install events, so this test starts and ends uninstalled.
	uninstall := func(key string) {
		if status, raw := secretsReqKey(t, h, http.MethodDelete, "/api/v1/integrations/slack", admin, key, nil); status != http.StatusNoContent && status != http.StatusConflict {
			t.Errorf("uninstall = %d %s", status, raw)
		}
	}
	uninstall("n8l1-uninstall-before")
	t.Cleanup(func() { uninstall("n8l1-uninstall-after") })
	install := func(key string) {
		t.Helper()
		var start struct {
			AuthorizeURL string `json:"authorize_url"`
		}
		if err := json.Unmarshal(call(admin, http.MethodPost, "/api/v1/integrations/slack/install", key, map[string]any{}, http.StatusOK), &start); err != nil {
			t.Fatal(err)
		}
		consent, err := url.Parse(start.AuthorizeURL)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(consent.Query().Get("scope"), "channels:history") {
			t.Errorf("the consent URL asks for %q, want the channel history too", consent.Query().Get("scope"))
		}
		resp, err := h.ts.Client().Get(h.ts.URL + "/integrations/slack/oauth/callback?code=n8-code&state=" + url.QueryEscape(consent.Query().Get("state")))
		if err != nil {
			t.Fatal(err)
		}
		page, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("callback = %d %s", resp.StatusCode, page)
		}
	}
	checks := func() bool {
		t.Helper()
		var status struct {
			Installed          bool `json:"installed"`
			DuplicatePostCheck bool `json:"duplicate_post_check"`
		}
		if err := json.Unmarshal(call(admin, http.MethodGet, "/api/v1/integrations/slack", "", nil, http.StatusOK), &status); err != nil || !status.Installed {
			t.Fatalf("the install's status: %v", err)
		}
		return status.DuplicatePostCheck
	}

	// An install that granted only posting and the channel list checks
	// nothing; installing again with the history granted checks.
	install("n8l1-install-old")
	call(admin, http.MethodPut, "/api/v1/integrations/slack/approval-channel", "n8l1-channel", map[string]any{"channel_id": "C0SECURITY"}, http.StatusOK)
	if checks() {
		t.Error("an install without the channel history says it checks for an earlier post")
	}
	stand.mu.Lock()
	stand.scope = "chat:write,channels:read,groups:read,channels:history,groups:history"
	stand.mu.Unlock()
	install("n8l1-install-again")
	if !checks() {
		t.Error("an install with the channel history granted says it does not check for an earlier post")
	}

	// Slack keeps the first post, but its answer never arrives.
	stand.mu.Lock()
	stand.dropPostAnswers = 1
	stand.mu.Unlock()
	var owner, identity struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(call(requester, http.MethodPost, "/api/v1/owners", "n8l1-owner", map[string]any{"kind": "workload", "name": "n8l1-payments"}, http.StatusCreated), &owner)
	_ = json.Unmarshal(call(requester, http.MethodPost, "/api/v1/identities", "n8l1-identity", map[string]any{"kind": "x509_certificate", "name": "n8l1-api.example.test", "owner_id": owner.ID}, http.StatusCreated), &identity)
	call(requester, http.MethodPost, "/api/v1/identities/"+identity.ID+"/transitions", "n8l1-issue", map[string]any{"to": "issued", "reason": "n8l1"}, http.StatusForbidden)

	posted := func() (string, []string) {
		t.Helper()
		stand.mu.Lock()
		defer stand.mu.Unlock()
		var request string
		var stamps []string
		for _, post := range stand.posts {
			raw, _ := json.Marshal(post)
			if post["channel"] != "C0SECURITY" || !strings.Contains(string(raw), `"action_id":"approve"`) {
				continue
			}
			stamps = append(stamps, post["ts"].(string))
			if meta, ok := post["metadata"].(map[string]any); ok {
				if payload, ok := meta["event_payload"].(map[string]any); ok {
					request, _ = payload["approval_request"].(string)
				}
			}
		}
		return request, stamps
	}
	var request string
	var recorded string
	for deadline := time.Now().Add(30 * time.Second); recorded == ""; {
		h.srv.dispatchOnce(context.Background())
		if request, _ = posted(); request != "" {
			if m, err := h.store.GetSlackApprovalMessage(context.Background(), h.tenant, request); err == nil {
				recorded = m.MessageTS
			}
		}
		if time.Now().After(deadline) {
			_, stamps := posted()
			t.Fatalf("the approval request's message was never recorded (posts %v)", stamps)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Later deliveries post nothing more either.
	for i := 0; i < 5; i++ {
		h.srv.dispatchOnce(context.Background())
		time.Sleep(50 * time.Millisecond)
	}
	if _, stamps := posted(); len(stamps) != 1 || stamps[0] != recorded {
		t.Fatalf("the approval request was posted as %v and recorded as %q, want one message recorded", stamps, recorded)
	}
	stand.mu.Lock()
	reads := stand.historyReads
	stand.mu.Unlock()
	if reads == 0 {
		t.Fatal("no post read the channel's history")
	}
}
