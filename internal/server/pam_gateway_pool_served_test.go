// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// TestServedGatewayPoolFailsOverA278 is A278 part 1's Done-when on three
// gateways: a pool shares a target's sessions, each started on the least
// loaded healthy member, which alone can claim it (its lease). Stopping one
// gateway — its heartbeats cease — marks it lost: the session it owned is
// revoked by the gateway-health actor and reads ended with A255's bounded
// uncertainty, new sessions start only on the other two, a draining member
// takes none, and the stopped gateway, back again, cannot claim the session
// it lost.
func TestServedGatewayPoolFailsOverA278(t *testing.T) {
	if testing.Short() {
		t.Skip("starts PostgreSQL")
	}
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)
	adminDSNRef := pamPostgresAdminFileRef(t, pgDSN)
	// Gateways of their own names: no job another test left behind names them.
	h := newRoleHarnessNamedWithEventOptions(t, "a278-gw-one", []string{mtls.AgentRoleGateway}, []string{relay.KindAccessGatewaySession}, nil, func(d *Deps) {
		wirePAMPostgresProvider(d, adminDSNRef, time.Minute)
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, ExpiryInterval: 100 * time.Millisecond,
			GatewayLostAfter: 2 * time.Second, Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startServedExternalCADispatcher(t, h.servedHarness)
	go h.srv.RunPAMSessionExpiry(ctx)

	// Three gateways: the harness's own and two more on the same channel.
	clients := map[string]*transport.AgentClient{agentRowID(h.tenant, h.agent): h.client}
	addresses := map[string]string{agentRowID(h.tenant, h.agent): "127.0.0.1:47101"}
	for i, name := range []string{"a278-gw-two", "a278-gw-three"} {
		a := enrollAgentWithRoles(t, h.servedHarness, name, h.serverName, []string{mtls.AgentRoleGateway})
		creds, err := a.Credentials()
		if err != nil {
			t.Fatal(err)
		}
		conn, err := transport.Dial(h.channelAddr, creds)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		id := agentRowID(h.tenant, name)
		clients[id] = transport.NewAgentClient(conn)
		addresses[id] = []string{"127.0.0.1:47102", "127.0.0.1:47103"}[i]
	}
	ids := make([]string, 0, 3)
	for id := range clients {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	primary := agentRowID(h.tenant, h.agent)

	// Every gateway heartbeats until it is stopped.
	var mu sync.Mutex
	stopped := map[string]bool{}
	beat := func(id string) {
		_, _ = clients[id].Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: id, Version: "a278", Status: "active"})
	}
	for _, id := range ids {
		beat(id)
	}
	go func() {
		for ctx.Err() == nil {
			for _, id := range ids {
				mu.Lock()
				down := stopped[id]
				mu.Unlock()
				if !down {
					beat(id)
				}
			}
			time.Sleep(250 * time.Millisecond)
		}
	}()

	operator := seedScopedTokenSubject(t, h.store, h.tenant, "a278-operator", "access:read", "access:targets.write")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "a278-requester", "access:read", "access:write")
	reviewerOne := seedScopedTokenSubject(t, h.store, h.tenant, "a278-reviewer-1", "access:approve")
	reviewerTwo := seedScopedTokenSubject(t, h.store, h.tenant, "a278-reviewer-2", "access:approve")
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", operator, "a278-target", map[string]any{
		"id": "orders-pg", "target_type": "postgres", "provider_id": "pam-pg-provider", "allowed_roles": []string{"readonly"},
		"gateway_agent_id": primary, "gateway_address": addresses[primary]}); status != http.StatusCreated {
		t.Fatalf("register target = %d %s", status, body)
	}
	members := func(draining string) []map[string]any {
		out := []map[string]any{}
		for _, id := range ids {
			out = append(out, map[string]any{"agent_id": id, "address": addresses[id], "draining": id == draining})
		}
		return out
	}
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/gateway-pools/site-a", operator, "a278-pool", map[string]any{"members": members("")})
	var pool struct {
		Revision int64 `json:"revision"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &pool) != nil || pool.Revision != 1 {
		t.Fatalf("save the pool = %d %s", status, body)
	}

	n := 0
	open := func() servedPAMSessionResponse {
		t.Helper()
		n++
		return servedPAMReviewedOpen(t, h.servedHarness, requester, reviewerOne, reviewerTwo, "a278-open-"+strconv.Itoa(n), map[string]any{
			"target_type": "postgres", "target_id": "orders-pg", "role": "readonly", "reason": "CHG-278 read the ledger",
			"method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")), "ttl_seconds": 60})
	}
	owner := map[string]string{} // session -> gateway
	for range 3 {
		s := open()
		if s.Gateway == nil || s.Gateway.Address != addresses[s.Gateway.AgentID] {
			t.Fatalf("a pooled session's gateway: %+v", s.Gateway)
		}
		owner[s.ID] = s.Gateway.AgentID
	}
	used := []string{}
	for _, g := range owner {
		used = append(used, g)
	}
	sort.Strings(used)
	if !slices.Equal(used, ids) {
		t.Fatalf("three sessions on three idle gateways went to %v, want one each on %v", used, ids)
	}
	// Each gateway's lease: it can claim its own session's job and no other.
	claimFor := func(id string) []string {
		t.Helper()
		resp, err := clients[id].ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindAccessGatewaySession}, Limit: 10, LeaseSeconds: 60})
		if err != nil {
			t.Fatalf("claim as %s: %v", id, err)
		}
		var sessions []string
		for _, job := range resp.Jobs {
			var intent accessgateway.SessionIntent
			if json.Unmarshal(job.Payload, &intent) == nil {
				sessions = append(sessions, intent.SessionID)
			}
		}
		return sessions
	}
	lostGateway := ids[1]
	var lostSession string
	for sessionID, gateway := range owner {
		got := claimFor(gateway)
		if len(got) != 1 || got[0] != sessionID {
			t.Fatalf("gateway %s claimed %v, want only its own session %s", gateway, got, sessionID)
		}
		if gateway == lostGateway {
			lostSession = sessionID
		}
	}

	// Stop one gateway: its heartbeats cease.
	mu.Lock()
	stopped[lostGateway] = true
	mu.Unlock()
	read := func(id string) map[string]any {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+id, requester, nil)
		var out map[string]any
		if status != http.StatusOK || json.Unmarshal(body, &out) != nil {
			t.Fatalf("read session %s = %d %s", id, status, body)
		}
		return out
	}
	a201Await(t, "the lost gateway's session ends", func() bool {
		s := read(lostSession)
		return s["gateway_lost"] == true && (s["status"] == "revoked" || s["status"] == "revoking")
	})
	ended := read(lostSession)
	if ended["uncertain_until"] != ended["expires_at"] || ended["revocation_requested_by"] != "trstctl:gateway-health" {
		t.Fatalf("the lost gateway's session is not bounded by its native deadline: %v", ended)
	}
	for sessionID, gateway := range owner {
		if gateway != lostGateway {
			if s := read(sessionID); s["status"] != "active" || s["gateway_lost"] == true {
				t.Fatalf("a healthy gateway's session changed: %v", s)
			}
		}
	}
	healthOf := func() map[string]string {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/gateway-pools", operator, nil)
		var listed struct {
			Items []struct {
				Revision int64 `json:"revision"`
				Members  []struct {
					AgentID string `json:"agent_id"`
					Health  string `json:"health"`
				} `json:"members"`
			} `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &listed) != nil || len(listed.Items) != 1 {
			t.Fatalf("list pools = %d %s", status, body)
		}
		out := map[string]string{}
		for _, m := range listed.Items[0].Members {
			out[m.AgentID] = m.Health
		}
		pool.Revision = listed.Items[0].Revision
		return out
	}
	if health := healthOf(); health[lostGateway] != "lost" || health[ids[0]] != "healthy" || health[ids[2]] != "healthy" {
		t.Fatalf("pool health after the stop: %v", health)
	}

	// New sessions start only on the other two.
	for range 2 {
		if s := open(); s.Gateway == nil || s.Gateway.AgentID == lostGateway {
			t.Fatalf("a new session started on the lost gateway: %+v", s.Gateway)
		}
	}
	// A draining member takes none either.
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/gateway-pools/site-a", operator, "a278-drain",
		map[string]any{"members": members(ids[2]), "revision": pool.Revision}); status != http.StatusOK {
		t.Fatalf("drain = %d %s", status, body)
	}
	if health := healthOf(); health[ids[2]] != "draining" {
		t.Fatalf("pool health after the drain: %v", health)
	}
	for range 2 {
		if s := open(); s.Gateway == nil || s.Gateway.AgentID != ids[0] {
			t.Fatalf("with one gateway lost and one draining, a session started on %+v", s.Gateway)
		}
	}

	// The stopped gateway comes back: the session it lost is no longer its.
	mu.Lock()
	stopped[lostGateway] = false
	mu.Unlock()
	beat(lostGateway)
	if got := claimFor(lostGateway); slices.Contains(got, lostSession) {
		t.Fatalf("the returning gateway claimed the session it lost: %v", got)
	}
}
