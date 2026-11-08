// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	fleet "trstctl.com/trstctl/internal/agentupgrade"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/objectstore/s3test"
)

// TestServedDrainedUpgradeLosesNoRecordingA278 is A278 part 2's Done-when: a
// pooled gateway drains before it upgrades, and the drained upgrade loses no
// recording. A recorded PostgreSQL session runs through gateway A. An upgrade
// campaign dispatches A's upgrade: A then reads draining with the upgrade
// pending, new sessions go to gateway B, A is not handed its upgrade job while
// the session lives, and the campaign waits on it rather than scoring it
// silent once the verify grace has passed. The session ends; its recording is
// sealed with its final chunk and verifies; only then does A claim the
// upgrade.
func TestServedDrainedUpgradeLosesNoRecordingA278(t *testing.T) {
	if testing.Short() {
		t.Skip("starts PostgreSQL")
	}
	token := "ghp_" + strings.Repeat("D", 36)
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)
	adminDSNRef := pamPostgresAdminFileRef(t, pgDSN)
	objects := s3test.NewServer(t)
	auditKey, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gatewayAddr := raw.Addr().String()
	h := newRoleHarnessNamedWithEventOptions(t, "a278d-gw-one", []string{mtls.AgentRoleGateway},
		[]string{relay.KindAccessGatewaySession, relay.KindAgentUpgrade}, nil, func(d *Deps) {
			wirePAMPostgresProvider(d, adminDSNRef, 5*time.Minute)
			d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, ExpiryInterval: 50 * time.Millisecond,
				Attestors: []attest.Attestor{servedPAMAttestor{}}}
			d.ArchiveObjectStore = objects.Open(t)
			d.AuditSigningKey = auditKey
		})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startServedExternalCADispatcher(t, h.servedHarness)
	go h.srv.RunPAMSessionExpiry(ctx)
	gatewayA := agentRowID(h.tenant, h.agent)
	b := enrollAgentWithRoles(t, h.servedHarness, "a278d-gw-two", h.serverName, []string{mtls.AgentRoleGateway})
	creds, err := b.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(h.channelAddr, creds)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	clientB := transport.NewAgentClient(conn)
	gatewayB := agentRowID(h.tenant, "a278d-gw-two")
	// A gateway's row is made by its first heartbeat: beat once, in order,
	// before anything names the gateways.
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: gatewayA, Version: "a278-old", Status: "active"}); err != nil {
		t.Fatalf("gateway A's first heartbeat: %v", err)
	}
	if _, err := clientB.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: gatewayB, Version: "a278-old", Status: "active"}); err != nil {
		t.Fatalf("gateway B's first heartbeat: %v", err)
	}
	var beats sync.WaitGroup
	beats.Add(1)
	go func() {
		defer beats.Done()
		for ctx.Err() == nil {
			_, _ = h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: gatewayA, Version: "a278-old", Status: "active"})
			_, _ = clientB.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: gatewayB, Version: "a278-old", Status: "active"})
			time.Sleep(250 * time.Millisecond)
		}
	}()
	t.Cleanup(func() { cancel(); beats.Wait() })
	a201Await(t, "both gateways read back", func() bool {
		_, errA := h.store.GetAgent(ctx, h.tenant, gatewayA)
		_, errB := h.store.GetAgent(ctx, h.tenant, gatewayB)
		return errA == nil && errB == nil
	})

	operator := seedScopedTokenSubject(t, h.store, h.tenant, "a278d-operator", "access:read", "access:targets.write")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "a278d-requester", "access:read", "access:write")
	reviewerOne := seedScopedTokenSubject(t, h.store, h.tenant, "a278d-reviewer-1", "access:approve")
	reviewerTwo := seedScopedTokenSubject(t, h.store, h.tenant, "a278d-reviewer-2", "access:approve")
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", operator, "a278d-target", map[string]any{
		"id": "pg-drain", "target_type": "postgres", "provider_id": "pam-pg-provider", "allowed_roles": []string{"readonly"},
		"gateway_agent_id": gatewayA, "gateway_address": gatewayAddr}); status != http.StatusCreated {
		t.Fatalf("register target = %d %s", status, body)
	}
	savePool := func(key string, revision int64, drainB bool) int64 {
		t.Helper()
		body := map[string]any{"members": []map[string]any{
			{"agent_id": gatewayA, "address": gatewayAddr},
			{"agent_id": gatewayB, "address": "127.0.0.1:47202", "draining": drainB},
		}}
		if revision > 0 {
			body["revision"] = revision
		}
		status, raw := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/gateway-pools/site-d", operator, key, body)
		var saved struct {
			Revision int64 `json:"revision"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &saved) != nil {
			t.Fatalf("save pool = %d %s", status, raw)
		}
		return saved.Revision
	}
	// B drains at first, so the recorded session starts on A, whose gateway
	// runs here.
	revision := savePool("a278d-pool", 0, true)

	cert, err := mtls.NewRenewingServerCertificate(h.srv.AgentCACertPEM(), []string{"127.0.0.1"}, func(csr []byte) ([]byte, error) {
		resp, err := h.client.SignGatewayServerCertificate(context.Background(), &transport.SignGatewayServerCertificateRequest{CSRDER: csr, Hosts: []string{"127.0.0.1"}})
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(resp.CertificatePEM)
		if block == nil {
			return nil, fmt.Errorf("not PEM")
		}
		return block.Bytes, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cert.Close)
	ln, err := mtls.GatewayWrapListener(raw, cert)
	if err != nil {
		t.Fatal(err)
	}
	var gatewayLog lockedBuffer
	gw, err := accessgateway.New(accessgateway.Config{Channel: &sshCollectionServedChannel{t: t, h: h}, Listener: ln,
		ClaimInterval: 100 * time.Millisecond, ExtendInterval: 200 * time.Millisecond,
		Logf: func(format string, args ...any) {
			_, _ = gatewayLog.Write([]byte(strings.TrimSpace(fmt.Sprintf(format, args...)) + "\n"))
		}})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gw.Run(ctx) }()
	api := httptest.NewServer(h.srv.Handler())
	defer api.Close()

	n := 0
	open := func() servedPAMSessionResponse {
		t.Helper()
		n++
		return servedPAMReviewedOpen(t, h.servedHarness, requester, reviewerOne, reviewerTwo, fmt.Sprintf("a278d-open-%d", n), map[string]any{
			"target_type": "postgres", "target_id": "pg-drain", "role": "readonly", "ttl_seconds": 120, "reason": "CHG-278 drain proof",
			"method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine"))})
	}
	recorded := open()
	if recorded.Gateway == nil || recorded.Gateway.AgentID != gatewayA {
		t.Fatalf("the recorded session started on %+v, want gateway A", recorded.Gateway)
	}
	ticketFile := filepath.Join(t.TempDir(), "ticket")
	if err := os.WriteFile(ticketFile, []byte(recorded.Gateway.Ticket+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var cliOut lockedBuffer
	tunnelCtx, stopTunnel := context.WithCancel(ctx)
	tunnelDone := make(chan struct{})
	go func() {
		defer close(tunnelDone)
		cli.Run(tunnelCtx, []string{"access", "sessions", "connect", recorded.ID, "--ticket-file", ticketFile, "--listen", "127.0.0.1:0"},
			cli.Env{Server: api.URL, Token: requester, Tenant: h.tenant, HTTPClient: api.Client()}, strings.NewReader(""), &cliOut, &cliOut)
	}()
	listen := regexp.MustCompile(`connect your client to (127\.0\.0\.1:\d+)`)
	a201Await(t, "the tunnel to gateway A", func() bool { return listen.MatchString(cliOut.String()) })
	pgCtx, pgCancel := context.WithTimeout(ctx, 30*time.Second)
	client, err := pgconn.Connect(pgCtx, "postgres://client@"+listen.FindStringSubmatch(cliOut.String())[1]+"/postgres?sslmode=disable")
	pgCancel()
	if err != nil {
		t.Fatalf("connect through gateway A: %v (gateway: %s)", err, gatewayLog.String())
	}
	if r := client.ExecParams(ctx, "SELECT current_user, '"+token+"' AS note FROM generate_series(1, 25)", nil, nil, nil, nil).Read(); r.Err != nil {
		t.Fatalf("query through gateway A: %v", r.Err)
	}

	// B takes sessions again; A's upgrade is dispatched by a campaign.
	savePool("a278d-undrain", revision, false)
	if err := h.srv.orch.AssignAgentUpgradeRing(ctx, h.tenant, gatewayA, string(fleet.RingCanary)); err != nil {
		t.Fatal(err)
	}
	artifacts := []fleet.Artifact{{OS: "linux", Arch: "amd64", URL: "https://artifacts.example/trstctl-agent", SHA256: strings.Repeat("ab", 32)}}
	if _, err := h.srv.orch.OpenAgentUpgradeCampaign(ctx, h.tenant, "a278-new", "a278d-operator", artifacts, 0); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.RunAgentUpgradeCampaignOnce(ctx, h.tenant); err != nil {
		t.Fatalf("dispatch the canary ring: %v", err)
	}
	member := func(id string) map[string]any {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/gateway-pools", operator, nil)
		var listed struct {
			Items []struct {
				Members []map[string]any `json:"members"`
			} `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &listed) != nil || len(listed.Items) != 1 {
			t.Fatalf("list pools = %d %s", status, body)
		}
		for _, m := range listed.Items[0].Members {
			if m["agent_id"] == id {
				return m
			}
		}
		t.Fatalf("no member %s", id)
		return nil
	}
	if a := member(gatewayA); a["upgrade_pending"] != true || a["health"] != "draining" || a["live_sessions"] != float64(1) {
		t.Fatalf("gateway A with its upgrade queued: %v", a)
	}
	// New sessions go to B; A is not handed its upgrade while its session lives.
	if next := open(); next.Gateway == nil || next.Gateway.AgentID != gatewayB {
		t.Fatalf("a new session started on %+v while A drains", next.Gateway)
	}
	claimUpgrade := func() int {
		t.Helper()
		resp, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindAgentUpgrade}, Limit: 5, LeaseSeconds: 60})
		if err != nil {
			t.Fatalf("claim the upgrade: %v", err)
		}
		return len(resp.Jobs)
	}
	if got := claimUpgrade(); got != 0 {
		t.Fatalf("gateway A was handed its upgrade with a live session: %d jobs", got)
	}
	// Past the verify grace, a draining gateway is waited for, not silent.
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE agent_upgrade_dispatches SET dispatched_at = now() - interval '1 hour' WHERE tenant_id = $1`, h.tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.RunAgentUpgradeCampaignOnce(ctx, h.tenant); err != nil {
		t.Fatal(err)
	}
	if c, active, err := h.store.ActiveAgentUpgradeCampaign(ctx, h.tenant); err != nil || !active || c.Status == fleet.StateHalted {
		t.Fatalf("the campaign halted on a draining gateway: %+v %v %v", c, active, err)
	}

	// The session ends: its recording is sealed with its final chunk.
	_ = client.Close(ctx)
	stopTunnel()
	<-tunnelDone
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+recorded.ID+"/revoke", requester,
		"a278d-end", map[string]any{"reason": "the work is done"}); status != http.StatusAccepted {
		t.Fatalf("end the session = %d %s", status, body)
	}
	a201Await(t, "the drained session's recording is sealed", func() bool {
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+recorded.ID+"/recording", requester, nil)
		var rec struct {
			Status        string `json:"status"`
			Chunks        int    `json:"chunks"`
			FinalReceived bool   `json:"final_received"`
		}
		return status == http.StatusOK && json.Unmarshal(body, &rec) == nil && rec.Status == "sealed" && rec.Chunks > 0 && rec.FinalReceived
	})
	if status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+recorded.ID+"/recording/verify", requester, nil); status != http.StatusOK || !strings.Contains(string(body), `"verified":true`) {
		t.Fatalf("verify the drained session's recording = %d %s", status, body)
	}
	if text := recordingText(t, h, recorded.ID); !strings.Contains(text, "complete: SELECT 25") || strings.Contains(text, token) {
		t.Fatalf("the drained session's recording is incomplete or unmasked:\n%s", text)
	}
	// Only now is A handed its upgrade.
	a201Await(t, "gateway A claims its upgrade once drained", func() bool { return claimUpgrade() == 1 })
}
