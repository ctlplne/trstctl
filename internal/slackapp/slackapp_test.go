// SPDX-License-Identifier: BUSL-1.1

package slackapp

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

// N8: the install exchanges a code for a bot token; the bot lists channels,
// posts an approval message and updates it; every request Slack sends is
// checked against the signing secret and a five-minute window.
func TestSlackAppInstallChannelsAndMessagesN8(t *testing.T) {
	var posted, updated map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/oauth.v2.access":
			id, secret, ok := r.BasicAuth()
			if err := r.ParseForm(); err != nil || !ok || id != "client-1" || secret != "client-secret" || r.PostForm.Get("code") != "code-1" {
				_, _ = fmt.Fprint(w, `{"ok":false,"error":"invalid_code"}`)
				return
			}
			_, _ = fmt.Fprint(w, `{"ok":true,"token_type":"bot","access_token":"xoxb-bot-token","bot_user_id":"U0BOT","app_id":"A0APP","team":{"id":"T0TEAM","name":"Acme"}}`)
		case "/api/conversations.list":
			if r.Header.Get("Authorization") != "Bearer xoxb-bot-token" {
				_, _ = fmt.Fprint(w, `{"ok":false,"error":"invalid_auth"}`)
				return
			}
			if r.URL.Query().Get("cursor") == "" {
				_, _ = fmt.Fprint(w, `{"ok":true,"channels":[{"id":"C0SEC","name":"security","is_member":true},{"id":"bad","name":"x"}],"response_metadata":{"next_cursor":"p2"}}`)
				return
			}
			_, _ = fmt.Fprint(w, `{"ok":true,"channels":[{"id":"G0OPS","name":"ops","is_private":true}],"response_metadata":{"next_cursor":""}}`)
		case "/api/chat.postMessage":
			_ = json.NewDecoder(r.Body).Decode(&posted)
			_, _ = fmt.Fprint(w, `{"ok":true,"channel":"C0SEC","ts":"1762246800.000100"}`)
		case "/api/chat.update":
			_ = json.NewDecoder(r.Body).Decode(&updated)
			_, _ = fmt.Fprint(w, `{"ok":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := Client{BaseURL: srv.URL, Doer: srv.Client()}
	if u := c.AuthorizeURL("client-1", "https://trstctl.example/cb", "state-1"); !strings.Contains(u, "/oauth/v2/authorize?") || !strings.Contains(u, "scope=chat%3Awrite") {
		t.Fatalf("authorize URL = %s", u)
	}
	install, err := c.Exchange(context.Background(), "client-1", []byte("client-secret"), "code-1", "https://trstctl.example/cb")
	if err != nil || install.TeamID != "T0TEAM" || install.BotUserID != "U0BOT" || string(install.BotToken) != "xoxb-bot-token" {
		t.Fatalf("exchange = %+v %v", install, err)
	}
	if _, err := c.Exchange(context.Background(), "client-1", []byte("client-secret"), "stale", "https://trstctl.example/cb"); !errors.Is(err, ErrRefused) {
		t.Fatalf("a refused code = %v", err)
	}
	channels, err := c.Channels(context.Background(), install.BotToken, 10)
	if err != nil || len(channels) != 2 || channels[0].ID != "C0SEC" || channels[1].ID != "G0OPS" {
		t.Fatalf("channels = %+v %v", channels, err)
	}
	msg, err := c.Post(context.Background(), install.BotToken, "C0SEC", "approve?", []any{map[string]any{"type": "section"}})
	if err != nil || msg.TS != "1762246800.000100" || posted["channel"] != "C0SEC" {
		t.Fatalf("post = %+v %v %v", msg, err, posted)
	}
	if err := c.Update(context.Background(), install.BotToken, msg, "approved", nil); err != nil || updated["ts"] != msg.TS {
		t.Fatalf("update = %v %v", err, updated)
	}
	if _, err := c.Post(context.Background(), install.BotToken, "#general", "x", nil); !errors.Is(err, ErrRefused) {
		t.Fatalf("a channel name instead of an ID = %v", err)
	}
}

func TestVerifyRequestN8(t *testing.T) {
	signing := []byte("8f742231b10e8888abcd99yyyzzz85a5")
	body := []byte("payload=%7B%22type%22%3A%22block_actions%22%7D")
	now := time.Unix(1762246800, 0)
	header := Sign(signing, now, body)
	if err := VerifyRequest(signing, header, body, now.Add(time.Minute)); err != nil {
		t.Fatalf("a signed request = %v", err)
	}
	for name, check := range map[string]func() error{
		"tampered body": func() error { return VerifyRequest(signing, header, append([]byte{}, append(body, 'x')...), now) },
		"other secret":  func() error { return VerifyRequest([]byte("other"), header, body, now) },
		"stale":         func() error { return VerifyRequest(signing, header, body, now.Add(6*time.Minute)) },
		"future":        func() error { return VerifyRequest(signing, header, body, now.Add(-6*time.Minute)) },
		"unsigned": func() error {
			return VerifyRequest(signing, http.Header{"X-Slack-Request-Timestamp": header["X-Slack-Request-Timestamp"]}, body, now)
		},
		"not hex": func() error {
			h := header.Clone()
			h.Set("X-Slack-Signature", "v0=zz")
			return VerifyRequest(signing, h, body, now)
		},
	} {
		if check() == nil {
			t.Fatalf("%s request verified", name)
		}
	}
}

// N8-L1: a tagged post keeps its tag as Slack message metadata, and
// FindTagged finds the one message this app posted with the tag, paging the
// channel's recent history: a message with another request's tag, or the same
// tag from another app, is not it. A token without the history scopes is
// refused, and CanFindTagged says so from the granted scopes.
func TestFindTaggedFindsOnlyThisAppsTaggedMessageN8L1(t *testing.T) {
	var posted map[string]any
	var since string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer xoxb-no-history" {
			_, _ = fmt.Fprint(w, `{"ok":false,"error":"missing_scope"}`)
			return
		}
		switch r.URL.Path {
		case "/api/chat.postMessage":
			_ = json.NewDecoder(r.Body).Decode(&posted)
			_, _ = fmt.Fprint(w, `{"ok":true,"channel":"C0SEC","ts":"1762246800.000100"}`)
		case "/api/conversations.history":
			q := r.URL.Query()
			if q.Get("channel") != "C0SEC" || q.Get("include_all_metadata") != "true" {
				_, _ = fmt.Fprint(w, `{"ok":false,"error":"channel_not_found"}`)
				return
			}
			since = q.Get("oldest")
			if q.Get("cursor") == "" {
				_, _ = fmt.Fprint(w, `{"ok":true,"messages":[
					{"ts":"1762246800.000300","app_id":"A0APP","metadata":{"event_type":"trstctl_approval_request","event_payload":{"approval_request":"req-2"}}},
					{"ts":"1762246800.000200","app_id":"A0OTHER","metadata":{"event_type":"trstctl_approval_request","event_payload":{"approval_request":"req-1"}}},
					{"ts":"1762246800.000150","text":"a person's message"}],
					"response_metadata":{"next_cursor":"p2"}}`)
				return
			}
			_, _ = fmt.Fprint(w, `{"ok":true,"messages":[
				{"ts":"1762246800.000100","bot_profile":{"app_id":"A0APP"},"metadata":{"event_type":"trstctl_approval_request","event_payload":{"approval_request":"req-1"}}}],
				"response_metadata":{"next_cursor":""}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := Client{BaseURL: srv.URL, Doer: srv.Client()}
	ctx := context.Background()
	tag := Tag{EventType: "trstctl_approval_request", Fields: map[string]string{"approval_request": "req-1"}}
	if _, err := c.PostTagged(ctx, []byte("xoxb-bot-token"), "C0SEC", "Approval requested", []any{}, tag); err != nil {
		t.Fatal(err)
	}
	meta, _ := posted["metadata"].(map[string]any)
	payload, _ := meta["event_payload"].(map[string]any)
	if meta["event_type"] != "trstctl_approval_request" || payload["approval_request"] != "req-1" {
		t.Fatalf("the post's metadata = %v", posted["metadata"])
	}
	oldest := time.Unix(1762160400, 0)
	msg, found, err := c.FindTagged(ctx, []byte("xoxb-bot-token"), "C0SEC", "A0APP", tag, oldest, 5)
	if err != nil || !found || msg.TS != "1762246800.000100" || msg.Channel != "C0SEC" {
		t.Fatalf("FindTagged = %+v %v %v, want this app's req-1 message on the second page", msg, found, err)
	}
	if since != "1762160400.000000" {
		t.Fatalf("history read from %q", since)
	}
	if _, found, err := c.FindTagged(ctx, []byte("xoxb-bot-token"), "C0SEC", "A0APP", tag, oldest, 1); err != nil || found {
		t.Fatalf("one page found %v (%v); the message is on the second", found, err)
	}
	if _, found, err := c.FindTagged(ctx, []byte("xoxb-no-history"), "C0SEC", "A0APP", tag, oldest, 5); !errors.Is(err, ErrRefused) || found {
		t.Fatalf("a token without the history = %v %v, want refused", found, err)
	}
	if !CanFindTagged(BotScopes) || !CanFindTagged("chat:write, channels:history,groups:history") ||
		CanFindTagged("chat:write,channels:read,groups:read") || CanFindTagged("chat:write,channels:history") || CanFindTagged("") {
		t.Fatal("CanFindTagged does not follow the granted history scopes")
	}
}
