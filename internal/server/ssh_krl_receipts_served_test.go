// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/sshkrlreceipt"
)

// krlAgent is one enrolled agent on the served agent channel.
type krlAgent struct {
	name     string
	client   *transport.AgentClient
	identity *agent.Agent
	issuedAt int64
}

func enrollKRLAgent(t *testing.T, h *servedHarness, addr, name string, roles []string) *krlAgent {
	t.Helper()
	a := enrollAgentWithRoles(t, h, name, "agent.trstctl.local", roles)
	creds, err := a.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(addr, creds)
	if err != nil {
		t.Fatalf("dial agent channel: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &krlAgent{name: name, client: transport.NewAgentClient(conn), identity: a, issuedAt: time.Now().UTC().Unix() - 60}
}

func (a *krlAgent) report(t *testing.T, tenant string, receipt sshkrlreceipt.Receipt) error {
	t.Helper()
	a.issuedAt++
	signed, err := transport.SignedSSHKRLReceipt(a.identity.Identity(), tenant, a.name, receipt, a.issuedAt)
	if err != nil {
		t.Fatalf("sign receipt: %v", err)
	}
	_, err = a.client.Heartbeat(context.Background(), &transport.HeartbeatRequest{Status: "active", Version: "a109", SSHKRL: signed})
	return err
}

type krlFleetView struct {
	Served struct {
		KRLVersion uint64 `json:"krl_version"`
		SHA256     string `json:"sha256"`
	} `json:"served"`
	Summary map[string]int `json:"summary"`
	Hosts   []struct {
		Agent            string `json:"agent"`
		State            string `json:"state"`
		Outcome          string `json:"outcome"`
		InstalledVersion uint64 `json:"installed_version"`
		InstalledSHA256  string `json:"installed_sha256"`
		Dropped          *struct {
			Serials uint64 `json:"serials"`
			KeyIDs  int    `json:"key_ids"`
		} `json:"dropped"`
		SignerFingerprint string `json:"signer_fingerprint"`
	} `json:"hosts"`
}

func krlFleet(t *testing.T, h *servedHarness, token string) (krlFleetView, []byte) {
	t.Helper()
	code, body := secretsReq(t, h, http.MethodGet, "/api/v1/ssh/krl/receipts", token, nil)
	var view krlFleetView
	if code != http.StatusOK || json.Unmarshal(body, &view) != nil {
		t.Fatalf("KRL receipts = %d %s", code, body)
	}
	return view, body
}

// A109: an enrolled host agent's signed KRL receipt, read back from its
// RevokedKeys file, is verified against the agent's certificate, recorded on
// the heartbeat event, and compared with the served list: current, behind, or
// refusing with what the served list would drop. Only a host-role agent may
// report one, a receipt must name the agent's own tenant and be newer than the
// last, and a projection rebuild reproduces the view.
func TestServedSSHKRLReceiptsShowWhatEachHostEnforces(t *testing.T) {
	ctx := context.Background()
	h := newServedHarnessWithEventOptions(t, config.Protocols{SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		nil, withAgentChannel)
	registerServedTenant(t, h, "KRL receipts tenant")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	chCtx, chCancel := context.WithCancel(context.Background())
	chDone := make(chan struct{})
	go func() { defer close(chDone); h.srv.serveAgentChannel(chCtx, ln) }()
	t.Cleanup(func() { chCancel(); <-chDone })
	host := enrollKRLAgent(t, h, ln.Addr().String(), "edge-1", []string{mtls.AgentRoleHost})
	relay := enrollKRLAgent(t, h, ln.Addr().String(), "relay-1", []string{mtls.AgentRoleNetwork})
	token := seedScopedToken(t, h.store, h.tenant, "certs:write", "certs:read")

	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/certificates/revoke", token, "a109-revoke-7", map[string]any{"serial": 7}); status != http.StatusOK {
		t.Fatalf("revoke = %d %s", status, body)
	}
	served := servedKRL(t, h)
	servedSHA := crypto.SHA256Hex(served)
	now := time.Now().UTC().Unix()
	current := sshkrlreceipt.Receipt{KRLTenantID: h.tenant, InstalledVersion: 1, InstalledSHA256: servedSHA,
		Outcome: sshkrlreceipt.OutcomeInstalled, FetchedVersion: 1, FetchedSHA256: servedSHA,
		CheckedAtUnix: now, InstalledAtUnix: now, PollEverySeconds: 30}
	if err := host.report(t, h.tenant, current); err != nil {
		t.Fatalf("host receipt: %v", err)
	}
	view, body := krlFleet(t, h, token)
	if view.Served.SHA256 != servedSHA || len(view.Hosts) != 1 || view.Hosts[0].Agent != "edge-1" || view.Hosts[0].State != "current" ||
		view.Summary["current"] != 1 || view.Hosts[0].SignerFingerprint == "" {
		t.Fatalf("after install: %s", body)
	}
	if bytes.Contains(body, []byte(`"signature"`)) || bytes.Contains(body, []byte(`"statement"`)) {
		t.Fatalf("receipt evidence bytes leaked: %s", body)
	}

	// A new revocation the host has not fetched yet leaves it behind.
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/certificates/revoke", token, "a109-revoke-8", map[string]any{"serial": 8}); status != http.StatusOK {
		t.Fatalf("revoke = %d %s", status, body)
	}
	if view, body := krlFleet(t, h, token); view.Hosts[0].State != "behind" || view.Summary["behind"] != 1 {
		t.Fatalf("after a new revocation: %s", body)
	}

	// The host refuses a served list that would drop its revocations.
	refused := current
	refused.Outcome, refused.FetchedVersion, refused.FetchedSHA256 = sshkrlreceipt.OutcomeRefusedDropsRevocations, 2, crypto.SHA256Hex(servedKRL(t, h))
	refused.DroppedSerials, refused.DroppedKeyIDs = 3, 1
	if err := host.report(t, h.tenant, refused); err != nil {
		t.Fatalf("refusal receipt: %v", err)
	}
	view, body = krlFleet(t, h, token)
	if view.Hosts[0].State != "refusing" || view.Hosts[0].Outcome != "refused_drops_revocations" || view.Hosts[0].Dropped == nil ||
		view.Hosts[0].Dropped.Serials != 3 || view.Hosts[0].Dropped.KeyIDs != 1 || view.Summary["refusing"] != 1 {
		t.Fatalf("after a refusal: %s", body)
	}

	// Only a host agent reports, about its own tenant, and never older news.
	if err := relay.report(t, h.tenant, current); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("network relay receipt = %v; want PermissionDenied", err)
	}
	foreign := current
	foreign.KRLTenantID = "22222222-2222-2222-2222-222222222222"
	signed, err := transport.SignedSSHKRLReceipt(host.identity.Identity(), foreign.KRLTenantID, host.name, foreign, host.issuedAt+1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.client.Heartbeat(ctx, &transport.HeartbeatRequest{Status: "active", SSHKRL: signed}); status.Code(err) != codes.InvalidArgument && status.Code(err) != codes.PermissionDenied {
		t.Fatalf("receipt for another tenant = %v", err)
	}
	host.issuedAt -= 10
	if err := host.report(t, h.tenant, current); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("older receipt = %v; want FailedPrecondition", err)
	}
	host.issuedAt += 20
	tampered, err := transport.SignedSSHKRLReceipt(host.identity.Identity(), h.tenant, host.name, current, host.issuedAt)
	if err != nil {
		t.Fatal(err)
	}
	tampered.Receipt.CheckedAtUnix++ // still a valid receipt, no longer the signed one
	if _, err := host.client.Heartbeat(ctx, &transport.HeartbeatRequest{Status: "active", SSHKRL: tampered}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("tampered receipt = %v; want PermissionDenied", err)
	}

	// A watcher that stopped checking is stale whatever it last said.
	stale := current
	stale.Outcome, stale.FetchedVersion, stale.FetchedSHA256 = sshkrlreceipt.OutcomeCurrent, current.InstalledVersion, current.InstalledSHA256
	stale.CheckedAtUnix = time.Now().UTC().Add(-time.Hour).Unix()
	if err := host.report(t, h.tenant, stale); err != nil {
		t.Fatalf("stale receipt: %v", err)
	}
	if view, body := krlFleet(t, h, token); view.Hosts[0].State != "stale" || view.Summary["stale"] != 1 {
		t.Fatalf("after the watcher stopped: %s", body)
	}

	// The receipt is replayable evidence: a rebuild yields the same view.
	before, _ := krlFleet(t, h, token)
	if err := projections.New(h.store).Rebuild(ctx, h.log); err != nil {
		t.Fatalf("rebuild projections: %v", err)
	}
	after, body := krlFleet(t, h, token)
	if len(after.Hosts) != 1 || after.Hosts[0] != before.Hosts[0] {
		t.Fatalf("rebuilt view differs: %s", body)
	}
}
