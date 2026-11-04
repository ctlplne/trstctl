// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/slackapp"
)

// n8SlackStandIn plays Slack's Web API from its reference: the OAuth code
// exchange, the channel list, and posting and updating messages.
type n8SlackStandIn struct {
	*httptest.Server
	mu      sync.Mutex
	posts   []map[string]any
	updates []map[string]any
}

func newN8SlackStandIn(t *testing.T) *n8SlackStandIn {
	s := &n8SlackStandIn{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		switch r.URL.Path {
		case "/api/oauth.v2.access":
			id, secret, ok := r.BasicAuth()
			if err := r.ParseForm(); err != nil || !ok || id != "n8-client" || secret != "n8-client-secret" || r.PostForm.Get("code") != "n8-code" {
				_, _ = fmt.Fprint(w, `{"ok":false,"error":"invalid_code"}`)
				return
			}
			_, _ = fmt.Fprint(w, `{"ok":true,"token_type":"bot","access_token":"xoxb-n8-bot-token","bot_user_id":"U0BOT","app_id":"A0N8","team":{"id":"T0N8TEAM","name":"N8 Workspace"}}`)
		case "/api/conversations.list":
			if r.Header.Get("Authorization") != "Bearer xoxb-n8-bot-token" {
				_, _ = fmt.Fprint(w, `{"ok":false,"error":"invalid_auth"}`)
				return
			}
			_, _ = fmt.Fprint(w, `{"ok":true,"channels":[{"id":"C0SECURITY","name":"security-approvals","is_member":true}]}`)
		case "/api/chat.postMessage", "/api/chat.update":
			if r.Header.Get("Authorization") != "Bearer xoxb-n8-bot-token" {
				_, _ = fmt.Fprint(w, `{"ok":false,"error":"invalid_auth"}`)
				return
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if r.URL.Path == "/api/chat.update" {
				s.updates = append(s.updates, body)
				_, _ = fmt.Fprint(w, `{"ok":true}`)
				return
			}
			s.posts = append(s.posts, body)
			_, _ = fmt.Fprintf(w, `{"ok":true,"channel":"%v","ts":"1762246800.00%04d"}`, body["channel"], len(s.posts))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

// N8: an operator installs trstctl's Slack app through Slack's consent screen
// (the bot token sealed, the state single-use), picks the approval channel
// from the channels the app sees, and members link their Slack users with a
// one-time code typed into Slack. An approval request is posted with Approve
// and Deny buttons; a press decides it through the API's own approval route as
// the linked member — the requester's own press is refused, an unlinked
// user's press is refused, a request Slack did not sign is refused — and the
// message is updated with the outcome.
func TestServedSlackAppApprovesFromButtonsN8(t *testing.T) {
	stand := newN8SlackStandIn(t)
	signing := []byte("n8-signing-secret")
	t.Setenv("TRSTCTL_N8_CLIENT_SECRET", "n8-client-secret")
	t.Setenv("TRSTCTL_N8_SIGNING", string(signing))
	slackCfg := config.SlackAppConfig{ClientID: "n8-client", ClientSecretRef: "env:TRSTCTL_N8_CLIENT_SECRET", SigningSecretRef: "env:TRSTCTL_N8_SIGNING", // #nosec G101 -- env: references to test-only values, no credential (CWE-798)
		APIBase: stand.URL, PublicURL: "https://trstctl.example.test", AllowPrivateAPI: true, PrivateEgressCIDRs: []string{"127.0.0.1/32"}}
	if err := slackCfg.Validate(); err != nil {
		t.Fatalf("the Slack app as configured: %v", err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.RequireApproval, d.RequiredApprovals = true, 1
		d.SlackApp = slackCfg
	})
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "slack-admin@example.test",
		string(authz.ConnectorsRead), string(authz.ConnectorsWrite), string(authz.AccessWrite), string(authz.AccessRead), "access:role.assign")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "slack-requester@example.test",
		string(authz.OwnersWrite), string(authz.IdentitiesWrite), string(authz.CertsRequest), string(authz.CertsIssue), string(authz.IdentitiesRead))
	reviewer := seedScopedTokenSubject(t, h.store, h.tenant, "slack-reviewer@example.test", string(authz.CertsIssue), string(authz.IdentitiesRead))
	call := func(token, method, path, key string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReqKey(t, h, method, path, token, key, body)
		if status != want {
			t.Fatalf("%s %s = %d, want %d: %s", method, path, status, want, raw)
		}
		return raw
	}
	public := func(method, path string, header http.Header, body string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, h.ts.URL+path, strings.NewReader(body))
		for k, v := range header {
			req.Header[k] = v
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw)
	}
	signed := func(path string, form url.Values) (int, string) {
		body := form.Encode()
		return public(http.MethodPost, path, slackapp.Sign(signing, time.Now(), []byte(body)), body)
	}

	// Install: the consent URL's state comes back once with Slack's code.
	var start struct {
		AuthorizeURL string `json:"authorize_url"`
	}
	if err := json.Unmarshal(call(admin, http.MethodPost, "/api/v1/integrations/slack/install", "n8-install", map[string]any{}, http.StatusOK), &start); err != nil {
		t.Fatal(err)
	}
	consent, err := url.Parse(start.AuthorizeURL)
	if err != nil || consent.Query().Get("redirect_uri") != "https://trstctl.example.test/integrations/slack/oauth/callback" {
		t.Fatalf("authorize URL = %s", start.AuthorizeURL)
	}
	state := consent.Query().Get("state")
	callback := "/integrations/slack/oauth/callback?code=n8-code&state=" + url.QueryEscape(state)
	if status, page := public(http.MethodGet, callback, nil, ""); status != http.StatusOK || !strings.Contains(page, "N8 Workspace") {
		t.Fatalf("callback = %d %s", status, page)
	}
	if status, _ := public(http.MethodGet, callback, nil, ""); status != http.StatusBadRequest {
		t.Fatalf("a replayed state = %d, want 400", status)
	}
	if strings.Contains(string(call(admin, http.MethodGet, "/api/v1/integrations/slack", "", nil, http.StatusOK)), "xoxb") || h.logContains(t, "xoxb-n8-bot-token") {
		t.Fatal("the bot token reached the API or the event log")
	}
	call(admin, http.MethodPut, "/api/v1/integrations/slack/approval-channel", "n8-channel", map[string]any{"channel_id": "C0NOTSEEN"}, http.StatusBadGateway)
	status := call(admin, http.MethodPut, "/api/v1/integrations/slack/approval-channel", "n8-channel-2", map[string]any{"channel_id": "C0SECURITY"}, http.StatusOK)
	if !strings.Contains(string(status), `"approval_channel_name":"security-approvals"`) {
		t.Fatalf("status after the channel pick = %s", status)
	}

	// Members link their Slack users by typing a one-time code into Slack.
	for _, subject := range []string{"slack-reviewer@example.test", "slack-requester@example.test"} {
		call(admin, http.MethodPut, "/api/v1/access/members/"+subject, "n8-member-"+subject, map[string]any{"display_name": subject, "roles": []string{"operator"}, "source": "manual"}, http.StatusOK)
	}
	link := func(token, slackUser string) {
		t.Helper()
		var code struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal(call(token, http.MethodPost, "/api/v1/integrations/slack/link-codes", "n8-link-"+slackUser, map[string]any{}, http.StatusCreated), &code); err != nil || code.Code == "" {
			t.Fatalf("link code: %v", err)
		}
		if status, answer := signed("/integrations/slack/commands", url.Values{"command": {"/trstctl"}, "text": {"link " + code.Code},
			"team_id": {"T0N8TEAM"}, "user_id": {slackUser}}); status != http.StatusOK || !strings.Contains(answer, "linked") {
			t.Fatalf("link %s = %d %s", slackUser, status, answer)
		}
		if status, answer := signed("/integrations/slack/commands", url.Values{"command": {"/trstctl"}, "text": {"link " + code.Code},
			"team_id": {"T0N8TEAM"}, "user_id": {"U0THIEF"}}); status != http.StatusOK || !strings.Contains(answer, "already used") {
			t.Fatalf("a reused link code = %d %s", status, answer)
		}
	}
	link(reviewer, "U0REVIEWER")
	link(requester, "U0REQUESTER")

	// An approval request is posted with its buttons.
	var owner, identity struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(call(requester, http.MethodPost, "/api/v1/owners", "n8-owner", map[string]any{"kind": "workload", "name": "n8-payments"}, http.StatusCreated), &owner)
	_ = json.Unmarshal(call(requester, http.MethodPost, "/api/v1/identities", "n8-identity", map[string]any{"kind": "x509_certificate", "name": "n8-api.example.test", "owner_id": owner.ID}, http.StatusCreated), &identity)
	call(requester, http.MethodPost, "/api/v1/identities/"+identity.ID+"/transitions", "n8-issue", map[string]any{"to": "issued", "reason": "n8"}, http.StatusForbidden)
	var buttons string
	for deadline := time.Now().Add(15 * time.Second); buttons == ""; {
		h.srv.dispatchOnce(context.Background())
		stand.mu.Lock()
		for _, post := range stand.posts {
			raw, _ := json.Marshal(post)
			if post["channel"] == "C0SECURITY" && strings.Contains(string(raw), `"action_id":"approve"`) {
				buttons = string(raw)
			}
		}
		stand.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("the approval request was not posted to Slack")
		}
		time.Sleep(50 * time.Millisecond)
	}
	var post struct {
		Blocks []struct {
			Elements []struct {
				ActionID string `json:"action_id"`
				Value    string `json:"value"`
			} `json:"elements"`
		} `json:"blocks"`
	}
	_ = json.Unmarshal([]byte(buttons), &post)
	value := post.Blocks[1].Elements[0].Value
	requestID := strings.SplitN(value, "|", 2)[0]
	press := func(slackUser, action string) (int, string) {
		payload, _ := json.Marshal(map[string]any{"type": "block_actions", "team": map[string]any{"id": "T0N8TEAM"}, "user": map[string]any{"id": slackUser},
			"container": map[string]any{"channel_id": "C0SECURITY", "message_ts": "1762246800.000001"},
			"actions":   []any{map[string]any{"action_id": action, "value": value, "action_ts": "1762246801.000001"}}})
		return signed("/integrations/slack/interactions", url.Values{"payload": {string(payload)}})
	}
	if status, answer := press("U0REQUESTER", "approve"); status != http.StatusOK || !strings.Contains(answer, "refused") {
		t.Fatalf("the requester's own press = %d %s", status, answer)
	}
	if status, answer := press("U0NOBODY", "approve"); status != http.StatusOK || !strings.Contains(answer, "not linked") {
		t.Fatalf("an unlinked user's press = %d %s", status, answer)
	}
	forged, _ := json.Marshal(map[string]any{"type": "block_actions", "team": map[string]any{"id": "T0N8TEAM"}, "user": map[string]any{"id": "U0REVIEWER"},
		"actions": []any{map[string]any{"action_id": "approve", "value": value}}})
	if status, _ := public(http.MethodPost, "/integrations/slack/interactions", http.Header{"X-Slack-Request-Timestamp": {fmt.Sprint(time.Now().Unix())},
		"X-Slack-Signature": {"v0=00"}}, url.Values{"payload": {string(forged)}}.Encode()); status != http.StatusUnauthorized {
		t.Fatalf("an unsigned press = %d, want 401", status)
	}
	if status, answer := press("U0REVIEWER", "approve"); status != http.StatusOK || strings.Contains(answer, "refused") {
		t.Fatalf("the reviewer's press = %d %s", status, answer)
	}
	listed := string(call(reviewer, http.MethodGet, "/api/v1/approval-requests", "", nil, http.StatusOK))
	if !strings.Contains(listed, requestID) || !strings.Contains(listed, `"status":"approved"`) {
		t.Fatalf("approval requests after the press = %s", listed)
	}
	message, err := h.store.GetSlackApprovalMessage(t.Context(), h.tenant, requestID)
	if err != nil || message.Decision != "approve" || message.DecidedBy != "slack-reviewer@example.test" || message.SlackUserID != "U0REVIEWER" {
		t.Fatalf("recorded Slack decision = %+v %v", message, err)
	}
	stand.mu.Lock()
	updated := len(stand.updates) == 1 && strings.Contains(fmt.Sprint(stand.updates[0]["text"]), "approved by slack-reviewer@example.test")
	stand.mu.Unlock()
	if !updated {
		t.Fatalf("the message was not updated with the outcome: %v", stand.updates)
	}

	call(admin, http.MethodDelete, "/api/v1/integrations/slack", "n8-uninstall", nil, http.StatusNoContent)
	if status := string(call(admin, http.MethodGet, "/api/v1/integrations/slack", "", nil, http.StatusOK)); !strings.Contains(status, `"installed":false`) {
		t.Fatalf("status after uninstall = %s", status)
	}
	t.Logf("N8_SLACK_APP_OK request=%s", requestID)
}
