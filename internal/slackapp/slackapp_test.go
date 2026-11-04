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
