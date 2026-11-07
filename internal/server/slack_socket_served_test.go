// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/websocket"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
)

// a277SocketStandIn adds Slack's Socket Mode to the N8 stand-in, from
// Slack's reference: apps.connections.open with the app-level token returns
// a WebSocket URL; over it Slack sends hello, then deliveries trstctl
// acknowledges by envelope id. Replies to button presses go to the
// payload's response_url.
type a277SocketStandIn struct {
	*n8SlackStandIn
	mu        sync.Mutex
	conns     []*websocket.Conn
	acks      map[string]json.RawMessage
	responses []string
	opened    int
}

func newA277SocketStandIn(t *testing.T) *a277SocketStandIn {
	s := &a277SocketStandIn{n8SlackStandIn: newN8SlackStandIn(t), acks: map[string]json.RawMessage{}}
	webAPI := s.Config.Handler
	mux := http.NewServeMux()
	mux.Handle("/link/", websocket.Server{Handshake: func(*websocket.Config, *http.Request) error { return nil }, Handler: func(ws *websocket.Conn) {
		s.mu.Lock()
		s.conns = append(s.conns, ws)
		s.mu.Unlock()
		_ = websocket.JSON.Send(ws, map[string]any{"type": "hello", "num_connections": 1})
		for {
			var ack struct {
				EnvelopeID string          `json:"envelope_id"`
				Payload    json.RawMessage `json:"payload"`
			}
			if err := websocket.JSON.Receive(ws, &ack); err != nil {
				return
			}
			s.mu.Lock()
			s.acks[ack.EnvelopeID] = ack.Payload
			s.mu.Unlock()
		}
	}})
	mux.HandleFunc("/api/apps.connections.open", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer xapp-a277-app-token" {
			_, _ = fmt.Fprint(w, `{"ok":false,"error":"invalid_auth"}`)
			return
		}
		s.mu.Lock()
		s.opened++
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "url": "ws" + strings.TrimPrefix(s.URL, "http") + "/link/?ticket=a277"})
	})
	mux.HandleFunc("/response/", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		s.mu.Lock()
		s.responses = append(s.responses, string(raw))
		s.mu.Unlock()
		_, _ = fmt.Fprint(w, `{"ok":true}`)
	})
	mux.Handle("/", webAPI)
	s.Config.Handler = mux
	return s
}

// deliver sends one envelope over the open connection and waits for its
// acknowledgement.
func (s *a277SocketStandIn) deliver(t *testing.T, kind string, payload any) json.RawMessage {
	t.Helper()
	id := uuid.NewString()
	raw, _ := json.Marshal(payload)
	a201Await(t, "a socket mode connection", func() bool { s.mu.Lock(); defer s.mu.Unlock(); return len(s.conns) > 0 })
	s.mu.Lock()
	conn := s.conns[len(s.conns)-1]
	s.mu.Unlock()
	if err := websocket.JSON.Send(conn, map[string]any{"envelope_id": id, "type": kind, "payload": json.RawMessage(raw), "accepts_response_payload": kind == "slash_commands"}); err != nil {
		t.Fatalf("deliver %s: %v", kind, err)
	}
	var ack json.RawMessage
	a201Await(t, "the envelope's acknowledgement", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		var ok bool
		ack, ok = s.acks[id]
		return ok
	})
	return ack
}

func (s *a277SocketStandIn) lastResponse() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.responses) == 0 {
		return ""
	}
	return s.responses[len(s.responses)-1]
}

// TestServedSlackSocketModeApprovalStartsTheSessionA277: with the Slack app
// in Socket Mode trstctl serves no Slack endpoint; it opens the connection
// itself. Members link their Slack users with a slash command delivered over
// it; a privileged session's approval request is posted with buttons whose
// values trstctl signed; two linked reviewers' presses, delivered over the
// connection, approve it, and the requester's session then starts. A
// replayed press and an altered one are refused and change nothing.
func TestServedSlackSocketModeApprovalStartsTheSessionA277(t *testing.T) {
	stand := newA277SocketStandIn(t)
	t.Setenv("TRSTCTL_A277_CLIENT_SECRET", "n8-client-secret")
	t.Setenv("TRSTCTL_A277_APP_TOKEN", "xapp-a277-app-token")
	slackCfg := config.SlackAppConfig{ClientID: "n8-client", ClientSecretRef: "env:TRSTCTL_A277_CLIENT_SECRET", AppTokenRef: "env:TRSTCTL_A277_APP_TOKEN", // #nosec G101 -- env: references to test-only values, no credential (CWE-798)
		APIBase: stand.URL, PublicURL: "https://trstctl.example.test", AllowPrivateAPI: true, PrivateEgressCIDRs: []string{"127.0.0.1/32"}}
	if err := slackCfg.Validate(); err != nil {
		t.Fatalf("the Socket Mode app as configured: %v", err)
	}
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)
	adminDSNRef := pamPostgresAdminFileRef(t, pgDSN)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		wirePAMPostgresProvider(d, adminDSNRef, time.Minute)
		d.PAM = PAMConfig{Enabled: true, MaxTTL: time.Minute, Attestors: []attest.Attestor{servedPAMAttestor{}}}
		d.SlackApp = slackCfg
	})
	startServedExternalCADispatcher(t, h)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go h.srv.RunSlackSocketMode(ctx)

	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a277-admin", "connectors:read", "connectors:write", "access:read", "access:write",
		"access:targets.write", "access:role.assign")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "a277-requester", "access:read", "access:write")
	reviewers := map[string]string{
		"U0REVONE": seedScopedTokenSubject(t, h.store, h.tenant, "a277-reviewer-1", "access:read", "access:approve"),
		"U0REVTWO": seedScopedTokenSubject(t, h.store, h.tenant, "a277-reviewer-2", "access:read", "access:approve"),
	}
	call := func(token, method, path, key string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReqKey(t, h, method, path, token, key, body)
		if status != want {
			t.Fatalf("%s %s = %d, want %d: %s", method, path, status, want, raw)
		}
		return raw
	}
	public := func(method, path string) (int, string, string) {
		req, _ := http.NewRequest(method, h.ts.URL+path, strings.NewReader("payload=%7B%7D"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return resp.StatusCode, resp.Header.Get("Content-Type"), string(raw)
	}

	// No inbound endpoint for Slack's deliveries is served: a request to
	// either request URL reaches no Slack handler (which would refuse an
	// unsigned delivery with 401), only the console's page or a not-found.
	for _, path := range []string{"/integrations/slack/interactions", "/integrations/slack/commands"} {
		status, contentType, body := public(http.MethodPost, path)
		if status == http.StatusUnauthorized || strings.Contains(body, "unauthorized") ||
			(status != http.StatusNotFound && status != http.StatusMethodNotAllowed && !strings.HasPrefix(contentType, "text/html")) {
			t.Fatalf("%s reached a Slack handler in Socket Mode: %d %s %s", path, status, contentType, body)
		}
	}

	// Install (the browser's redirect) and the approval channel.
	var start struct {
		AuthorizeURL string `json:"authorize_url"`
	}
	_ = json.Unmarshal(call(admin, http.MethodPost, "/api/v1/integrations/slack/install", "a277-install", map[string]any{}, http.StatusOK), &start)
	consent, _ := url.Parse(start.AuthorizeURL)
	cb, _ := http.NewRequest(http.MethodGet, h.ts.URL+"/integrations/slack/oauth/callback?code=n8-code&state="+url.QueryEscape(consent.Query().Get("state")), nil)
	if resp, err := h.ts.Client().Do(cb); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("install callback: %v", err)
	}
	call(admin, http.MethodPut, "/api/v1/integrations/slack/approval-channel", "a277-channel", map[string]any{"channel_id": "C0SECURITY"}, http.StatusOK)

	// Reviewers link their Slack users with /trstctl link over the connection.
	for slackUser, token := range reviewers {
		subject := map[string]string{"U0REVONE": "a277-reviewer-1", "U0REVTWO": "a277-reviewer-2"}[slackUser]
		call(admin, http.MethodPut, "/api/v1/access/members/"+subject, "a277-member-"+subject, map[string]any{"display_name": subject, "roles": []string{"operator"}, "source": "manual"}, http.StatusOK)
		var code struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(call(token, http.MethodPost, "/api/v1/integrations/slack/link-codes", "a277-link-"+slackUser, map[string]any{}, http.StatusCreated), &code)
		ack := stand.deliver(t, "slash_commands", map[string]any{"command": "/trstctl", "text": "link " + code.Code, "team_id": "T0N8TEAM", "user_id": slackUser})
		if !strings.Contains(string(ack), "linked to "+subject) {
			t.Fatalf("link %s over the connection: %s", slackUser, ack)
		}
	}

	// The session request's approval is posted with signed buttons.
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/targets", admin, "a277-register",
		map[string]any{"id": "orders-pg", "target_type": "postgres", "provider_id": "pam-pg-provider", "allowed_roles": []string{"readonly"}}); status != http.StatusCreated {
		t.Fatalf("register: %d %s", status, body)
	}
	session := map[string]any{"request_id": uuid.NewString(), "target_type": "postgres", "target_id": "orders-pg", "role": "readonly",
		"reason": "INC-77 read the orders ledger", "method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")), "ttl_seconds": 30}
	var pending api.PAMApprovalRequest
	if err := json.Unmarshal(call(requester, http.MethodPost, "/api/v1/access/session-requests", "a277-request", session, http.StatusAccepted), &pending); err != nil {
		t.Fatal(err)
	}
	var value string
	a201Await(t, "the approval request is posted to Slack", func() bool {
		h.srv.dispatchOnce(context.Background())
		stand.n8SlackStandIn.mu.Lock()
		defer stand.n8SlackStandIn.mu.Unlock()
		for _, post := range stand.posts {
			raw, _ := json.Marshal(post)
			var p struct {
				Channel string `json:"channel"`
				Blocks  []struct {
					Elements []struct {
						ActionID string `json:"action_id"`
						Value    string `json:"value"`
					} `json:"elements"`
				} `json:"blocks"`
			}
			if json.Unmarshal(raw, &p) != nil || p.Channel != "C0SECURITY" || len(p.Blocks) < 2 {
				continue
			}
			for _, el := range p.Blocks[1].Elements {
				if el.ActionID == "approve" {
					value = el.Value
				}
			}
		}
		return value != ""
	})
	if strings.Contains(value, pending.IntentDigest) || !strings.HasPrefix(value, "v1.") {
		t.Fatalf("the button's value is not a signed decision: %s", value)
	}
	press := func(slackUser, v string) {
		t.Helper()
		stand.deliver(t, "interactive", map[string]any{"type": "block_actions", "team": map[string]any{"id": "T0N8TEAM"}, "user": map[string]any{"id": slackUser},
			"container":    map[string]any{"channel_id": "C0SECURITY", "message_ts": "1762246800.000001"},
			"response_url": stand.URL + "/response/" + slackUser,
			"actions":      []any{map[string]any{"action_id": "approve", "value": v, "action_ts": "1762246801.000001"}}})
	}
	approvals := func() int {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/approval-requests", reviewers["U0REVONE"], nil)
		var listed struct {
			Items []struct {
				ID            string `json:"id"`
				ApprovalCount int    `json:"approval_count"`
			} `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &listed) != nil {
			t.Fatalf("approval requests: %d %s", status, body)
		}
		for _, it := range listed.Items {
			if it.ID == pending.ApprovalRequestID {
				return it.ApprovalCount
			}
		}
		return -1
	}
	press("U0REVONE", value)
	a201Await(t, "the first reviewer's approval", func() bool { return approvals() == 1 })

	// A replayed press is refused and changes nothing.
	press("U0REVONE", value)
	a201Await(t, "the replay's refusal", func() bool { return strings.Contains(stand.lastResponse(), "already used") })
	// An altered decision — the digest swapped, the signature kept — is
	// refused.
	parts := strings.Split(value, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var d map[string]any
	_ = json.Unmarshal(payload, &d)
	d["d"] = strings.Repeat("0", 64)
	alteredPayload, _ := json.Marshal(d)
	press("U0REVTWO", parts[0]+"."+base64.RawURLEncoding.EncodeToString(alteredPayload)+"."+parts[2])
	a201Await(t, "the altered decision's refusal", func() bool { return strings.Contains(stand.lastResponse(), "altered") })
	if got := approvals(); got != 1 {
		t.Fatalf("a refused press changed the approvals: %d", got)
	}

	// The second reviewer approves; the session starts.
	press("U0REVTWO", value)
	a201Await(t, "the second reviewer's approval", func() bool { return approvals() == 2 })
	session["approval_request_id"], session["intent_digest"] = pending.ApprovalRequestID, pending.IntentDigest
	opened := servedPAMOpen(t, h, requester, "a277-open", session)
	if opened.Status != "active" || opened.Postgres == nil {
		t.Fatalf("the approved session did not start: %+v", opened)
	}
	stand.mu.Lock()
	connections := stand.opened
	stand.mu.Unlock()
	if connections < 1 {
		t.Fatal("trstctl never opened its Socket Mode connection")
	}
}
