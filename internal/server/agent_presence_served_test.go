// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
)

func TestServedAgentPresenceUsesTheRunningChannelInterval(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withAgentChannel)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.srv.serveAgentChannel(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	const agentName = "presence-contract-agent"
	identity := enrollAgent(t, h, agentName, "agent.trstctl.local")
	creds, err := identity.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(ln.Addr().String(), creds)
	if err != nil {
		t.Fatalf("dial agent channel: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := transport.NewAgentClient(conn)
	if _, err := client.Heartbeat(context.Background(), &transport.HeartbeatRequest{Version: "presence-test", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}

	token := seedScopedToken(t, h.store, h.tenant, "agents:read")
	statusCode, body := secretsReq(t, h, http.MethodGet, "/api/v1/agents", token, nil)
	if statusCode != http.StatusOK {
		t.Fatalf("list agents: status %d body %s", statusCode, body)
	}
	var response struct {
		Agents []struct {
			ID         string `json:"id"`
			Status     string `json:"status"`
			LastSeenAt string `json:"last_seen_at"`
			Presence   struct {
				State       string `json:"state"`
				Online      bool   `json:"online"`
				EvaluatedAt string `json:"evaluated_at"`
				FreshUntil  string `json:"fresh_until"`
				Detail      string `json:"detail"`
			} `json:"presence"`
		} `json:"agents"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode agents response: %v (%s)", err, body)
	}
	wantID := agentRowID(h.tenant, agentName)
	for _, got := range response.Agents {
		if got.ID != wantID {
			continue
		}
		if got.Status != "active" || got.Presence.State != "online" || !got.Presence.Online || got.Presence.Detail == "" {
			t.Fatalf("served lifecycle/presence contradiction: %+v", got)
		}
		lastSeen, err := time.Parse(time.RFC3339, got.LastSeenAt)
		if err != nil {
			t.Fatalf("parse last_seen_at: %v", err)
		}
		freshUntil, err := time.Parse(time.RFC3339, got.Presence.FreshUntil)
		if err != nil {
			t.Fatalf("parse fresh_until: %v", err)
		}
		if got := freshUntil.Sub(lastSeen); got != 30*time.Second {
			t.Fatalf("served freshness window = %s, want two configured 15s intervals", got)
		}
		if _, err := time.Parse(time.RFC3339, got.Presence.EvaluatedAt); err != nil {
			t.Fatalf("parse evaluated_at: %v", err)
		}
		return
	}
	t.Fatalf("agent %s missing from response: %s", wantID, body)
}
