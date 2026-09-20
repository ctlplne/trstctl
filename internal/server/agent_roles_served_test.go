// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"

	"strings"
	"trstctl.com/trstctl/internal/agent"
	agentrelay "trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/events"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// Role-gated agent enrollment, proven on the assembled binary (epic A2).
//
// An agent runs either on the host it serves, or in the network segment in front
// of something that cannot host an agent at all — a load balancer, an appliance,
// a cloud certificate store. The second kind holds the credentials that drive
// those devices, which is why it is a grant and not a startup flag.
//
// These drive the whole path: an operator's grant is recorded at mint, stamped by
// the CA into the enrolled certificate, and read back at claim time to decide what
// work the agent is handed.

// roleHarness is a served control plane with the agent channel mounted and one
// agent enrolled under a named capability grant.
type roleHarness struct {
	*servedHarness
	client      *transport.AgentClient
	agent       string
	channelAddr string
	serverName  string
	// identity signs this harness's job receipts (epic A1).
	identity *agent.Agent
}

func (h *roleHarness) report(t *testing.T, jobID int64, attempt int,
	outcome, detail, evidenceDigest string) *transport.ReportJobResultRequest {
	t.Helper()
	return signedJobReport(t, h.identity, jobID, attempt, outcome, detail, evidenceDigest)
}

func newRoleHarness(t *testing.T, roles []string, claimable ...string) *roleHarness {
	return newRoleHarnessWithDeps(t, roles, claimable)
}

// newRoleHarnessWithDeps keeps the standard real signer/agent fixture while
// allowing an assembled feature test to turn on the same licensed route seam
// production wiring would enable. Existing role tests use newRoleHarness and
// therefore retain their exact default dependency set.
func newRoleHarnessWithDeps(t *testing.T, roles, claimable []string, options ...func(*Deps)) *roleHarness {
	return newRoleHarnessWithEventOptions(t, roles, claimable, nil, options...)
}

func newRoleHarnessWithEventOptions(t *testing.T, roles, claimable []string, eventOptions []events.OpenOption, options ...func(*Deps)) *roleHarness {
	t.Helper()
	deps := []func(*Deps){withAgentChannel, func(d *Deps) {
		d.AgentClaimableJobKinds = claimable
	}}
	deps = append(deps, options...)
	h := newServedHarnessWithEventOptions(t, config.Protocols{}, eventOptions, deps...)
	if !h.srv.AgentChannelServed() {
		t.Fatal("agent channel is not served")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	chCtx, chCancel := context.WithCancel(context.Background())
	chDone := make(chan struct{})
	go func() { defer close(chDone); h.srv.serveAgentChannel(chCtx, ln) }()
	t.Cleanup(func() { chCancel(); <-chDone })

	const serverName = "agent.trstctl.local"
	cn := "role-agent"
	a := enrollAgentWithRoles(t, h, cn, serverName, roles)
	creds, err := a.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(ln.Addr().String(), creds)
	if err != nil {
		t.Fatalf("dial agent channel: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &roleHarness{
		servedHarness: h,
		client:        transport.NewAgentClient(conn),
		agent:         cn,
		channelAddr:   ln.Addr().String(),
		serverName:    serverName,
		identity:      a,
	}
}

// TestServedHostAgentCannotClaimRelayWork is the point of the epic. The operator
// enabled endpoint.verify, and a HOST agent asks for it. Its certificate says host,
// so the work stays in the queue — the agent is not handed a job whose vantage it
// does not have.
func TestServedHostAgentCannotClaimRelayWork(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, "endpoint.verify")
	seedRoleJob(t, ctx, h, "endpoint.verify", "verify:edge-1")

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{
		Kinds: []string{"endpoint.verify"}, Limit: 5, LeaseSeconds: 60,
	})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed.Jobs) != 0 {
		t.Fatalf("host agent was handed %d relay jobs, want 0", len(claimed.Jobs))
	}
}

// TestServedNetworkAgentClaimsRelayWork is the same request from an agent an
// operator actually granted the relay role — it gets the work. Without this the
// test above would pass for the wrong reason (nothing claimable at all).
func TestServedNetworkAgentClaimsRelayWork(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, "endpoint.verify")
	seedRoleJob(t, ctx, h, "endpoint.verify", "verify:edge-2")

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{
		Kinds: []string{"endpoint.verify"}, Limit: 5, LeaseSeconds: 60,
	})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed.Jobs) != 1 {
		t.Fatalf("network agent claimed %d relay jobs, want 1", len(claimed.Jobs))
	}
}

// TestServedNetworkAgentCannotClaimHostLocalWork is the gate in the other
// direction: a relay has no filesystem of the appliance's to enumerate, so
// discovery.run is not its work either. The role is a vantage, not a rank.
func TestServedNetworkAgentCannotClaimHostLocalWork(t *testing.T) {
	ctx := context.Background()
	// trust.distribute is the host-vantage example here. discovery.run used to
	// be, until C2 re-homed segment sweeps onto relays — a vantage question, not
	// a filesystem one. The property under test is unchanged.
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, "trust.distribute")
	seedRoleJob(t, ctx, h, "trust.distribute", "trust:seg-1")

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{
		Kinds: []string{"trust.distribute"}, Limit: 5, LeaseSeconds: 60,
	})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed.Jobs) != 0 {
		t.Fatalf("network agent was handed %d host-local jobs, want 0", len(claimed.Jobs))
	}
}

// TestServedDualRoleAgentClaimsBoth: the user's actual topology — one binary that
// serves its own host AND relays for the appliance beside it.
func TestServedDualRoleAgentClaimsBoth(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t,
		[]string{mtls.AgentRoleHost, mtls.AgentRoleNetwork},
		"discovery.run", "endpoint.verify")
	seedRoleJob(t, ctx, h, "discovery.run", "discover:dual-1")
	seedRoleJob(t, ctx, h, "endpoint.verify", "verify:dual-1")

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{
		Kinds: []string{"discovery.run", "endpoint.verify"}, Limit: 5, LeaseSeconds: 60,
	})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed.Jobs) != 2 {
		t.Fatalf("dual-role agent claimed %d jobs, want 2", len(claimed.Jobs))
	}
}

// TestServedAgentWithNoGrantIsHostOnly pins the upgrade path on the served binary:
// a token minted with no roles at all — every enrollment before this epic — yields
// an agent that does host work and is refused relay work. Not one that does
// nothing, and not one that does everything.
func TestServedAgentWithNoGrantIsHostOnly(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, nil, "trust.distribute", "endpoint.verify")
	seedRoleJob(t, ctx, h, "trust.distribute", "trust:legacy-1")
	seedRoleJob(t, ctx, h, "endpoint.verify", "verify:legacy-1")

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{
		Kinds: []string{"trust.distribute", "endpoint.verify"}, Limit: 5, LeaseSeconds: 60,
	})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed.Jobs) != 1 {
		t.Fatalf("grant-less agent claimed %d jobs, want 1 (host work only)", len(claimed.Jobs))
	}
	if claimed.Jobs[0].Kind != "trust.distribute" {
		t.Fatalf("grant-less agent claimed %q, want trust.distribute", claimed.Jobs[0].Kind)
	}
}

// TestServedRelayReachRecordsARefusal: a host agent reaching for relay work is
// either a misconfiguration or the thing this gate exists to catch. Both are worth
// an operator seeing, so the reach is recorded rather than silently dropped.
func TestServedRelayReachRecordsARefusal(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, "endpoint.verify")
	seedRoleJob(t, ctx, h, "endpoint.verify", "verify:refused-1")

	if _, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{
		Kinds: []string{"endpoint.verify"}, Limit: 5, LeaseSeconds: 60,
	}); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if !h.hasEvent(t, "agent.jobs.role_refused") {
		t.Fatal("out-of-role claim left no evidence in the event log")
	}
}

// seedRoleJob puts one claimable job of the given kind in the tenant's queue.
func seedRoleJob(t *testing.T, ctx context.Context, h *roleHarness, destination, idemKey string) {
	t.Helper()
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key)
			 VALUES ($1, $2, $3, $4)`,
			h.tenant, destination, []byte(`{"target":"edge-1"}`), idemKey)
		return err
	}); err != nil {
		t.Fatalf("seed claimable job: %v", err)
	}
}

// TestServedAgentRoleReachesTheConsole closes the loop this epic is judged on: a
// relay heartbeats, and the fleet the Agents page reads reports it as a relay.
// Without this the role would be enforced but invisible, and an operator would
// have no way to see which of their agents holds appliance credentials.
func TestServedAgentRoleReachesTheConsole(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork})

	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{
		AgentID: h.agent, Version: "test-1.0", Status: "active",
	}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}

	agents, err := h.store.ListAgentsPage(ctx, h.tenant, nil, store.ZeroUUID, 20)
	if err != nil {
		t.Fatalf("list agents: %v", err)
	}
	var found *store.Agent
	for i := range agents {
		if agents[i].Name == h.agent {
			found = &agents[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("agent %q is not in the fleet the console reads", h.agent)
	}
	if len(found.Roles) != 1 || found.Roles[0] != mtls.AgentRoleNetwork {
		t.Fatalf("console fleet shows roles %v for a relay, want [network]", found.Roles)
	}
}

// seedRoleJobWithDemand seeds a claimable job carrying a per-row role demand,
// the way the enqueue classifier stamps one (epic A3).
func seedRoleJobWithDemand(t *testing.T, ctx context.Context, h *roleHarness, destination, idemKey, demand string) {
	t.Helper()
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, required_agent_role, required_agent_id)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			h.tenant, destination, []byte(`{"target":"edge-1"}`), idemKey, demand, agentRowID(h.tenant, h.agent))
		return err
	}); err != nil {
		t.Fatalf("seed claimable job: %v", err)
	}
}

// TestServedPerRowDemandSplitsConnectorDeploys is the closing of A2's stated
// gap, proven on the assembled binary: connector.deploy is claimable by both
// roles at the KIND level, and the per-row demand stamped from the target's
// vantage decides which deploys each agent actually receives. A host agent
// asking for connector.deploy gets the nginx deploy and not the F5 deploy; the
// ACM deploy — a cloud store with no host and no segment — goes to nobody.
func TestServedPerRowDemandSplitsConnectorDeploys(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, "connector.deploy")
	seedRoleJobWithDemand(t, ctx, h, "connector.deploy", "deploy:nginx-1", "host")
	seedRoleJobWithDemand(t, ctx, h, "connector.deploy", "deploy:f5-1", "network")
	seedRoleJobWithDemand(t, ctx, h, "connector.deploy", "deploy:acm-1", "control_plane")

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{
		Kinds: []string{"connector.deploy"}, Limit: 10, LeaseSeconds: 60,
	})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed.Jobs) != 1 {
		t.Fatalf("host agent claimed %d connector deploys, want exactly the host-vantage one", len(claimed.Jobs))
	}
	if claimed.Jobs[0].IdempotencyKey != "deploy:nginx-1" {
		t.Fatalf("host agent claimed %q, want deploy:nginx-1", claimed.Jobs[0].IdempotencyKey)
	}
}

// TestServedRelayReceivesOnlyRelayDeploys is the same split from the relay's
// side, and the ACM row stays unclaimable even for a dual-role agent.
func TestServedRelayReceivesOnlyRelayDeploys(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t,
		[]string{mtls.AgentRoleHost, mtls.AgentRoleNetwork}, "connector.deploy")
	seedRoleJobWithDemand(t, ctx, h, "connector.deploy", "deploy:f5-2", "network")
	seedRoleJobWithDemand(t, ctx, h, "connector.deploy", "deploy:acm-2", "control_plane")

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{
		Kinds: []string{"connector.deploy"}, Limit: 10, LeaseSeconds: 60,
	})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed.Jobs) != 1 || claimed.Jobs[0].IdempotencyKey != "deploy:f5-2" {
		t.Fatalf("dual-role agent claimed %v, want exactly [deploy:f5-2] — the cloud-store deploy must stay with the control plane", claimed.Jobs)
	}
}

// TestServedDryRunProducesAPlanAndChangesNothing is D5's acceptance on the
// assembled binary: a relay claims a connector.test job, redeems, reports its
// plan, and the control plane records a receipt that says whether a deploy
// would work — with no deploy having happened.
func TestServedDryRunProducesAPlanAndChangesNothing(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, "connector.test")
	seedRoleJobWithDemand(t, ctx, h, "connector.test", "test:edge-f5", "network")

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{
		Kinds: []string{"connector.test"}, Limit: 5, LeaseSeconds: 60,
	})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed.Jobs) != 1 {
		t.Fatalf("relay claimed %d test jobs, want 1", len(claimed.Jobs))
	}
	job := claimed.Jobs[0]

	// The relay reports the plan it produced. Here it reports a blocked one,
	// which is the case that must NOT read as a passing test.
	plan := `{"connector":"f5","target":"edge-f5","ready":false,` +
		`"steps":[{"name":"reachability","status":"failed","detail":"connection refused"}]}`
	if _, err := h.client.ReportJobResult(ctx,
		h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, plan, "")); err != nil {
		t.Fatalf("report: %v", err)
	}

	receipts, err := h.store.ListConnectorDeliveryReceiptsPage(ctx, h.tenant, "", store.ZeroUUID, 50)
	if err != nil {
		t.Fatalf("list receipts: %v", err)
	}
	var got *store.ConnectorDeliveryReceipt
	for i := range receipts {
		if receipts[i].Destination == "connector.test" && receipts[i].Status == servedstatus.ConnectorTestBlocked {
			got = &receipts[i]
			break
		}
	}
	if got == nil {
		t.Fatalf("no blocked dry-run receipt was recorded; receipts = %+v", receipts)
	}
	if !strings.Contains(got.Detail, "connection refused") {
		t.Errorf("the receipt does not name the cause: %q", got.Detail)
	}
	// A blocked dry-run must never read as a delivery.
	for _, r := range receipts {
		if r.Status == servedstatus.ConnectorDelivered {
			t.Fatal("a dry-run produced a delivered receipt; nothing was deployed")
		}
	}
}

// TestServedHostDryRunReachesTheTargetAndChangesNothing is F7's host-vantage
// preview proof on the assembled control plane and shipping agent runtime. A
// host-role agent claims the real connector.test row over mTLS, validates its
// operator-owned filesystem/command boundary, handshakes the listener, and
// reports the plan. The target bytes are compared before and after so
// "preview" is an observed zero-write boundary, not only a UI label.
func TestServedHostDryRunReachesTheTargetAndChangesNothing(t *testing.T) {
	ctx := t.Context()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, agentrelay.KindConnectorTest)

	listener, err := tlsprobe.NewServingTestServer("apache.example.test")
	if err != nil {
		t.Fatalf("start Apache preview listener: %v", err)
	}
	defer listener.Close()

	root := t.TempDir()
	certPath := filepath.Join(root, "site.crt")
	keyPath := filepath.Join(root, "site.key")
	beforeCert := []byte("bootstrap certificate")
	beforeKey := []byte("bootstrap private key")
	if err := os.WriteFile(certPath, beforeCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, beforeKey, 0o600); err != nil {
		t.Fatal(err)
	}

	targetConfig, err := json.Marshal(map[string]string{
		"cert_path": certPath, "key_path": keyPath,
		"verify_address": listener.Addr, "verify_server_name": "apache.example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(agentrelay.DeployIntent{
		Connector:        "apache",
		Target:           "payments Apache",
		TargetID:         "target-apache-preview",
		TargetConfig:     targetConfig,
		VerifyAddress:    listener.Addr,
		VerifyServerName: "apache.example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx,
			`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, required_agent_role, required_agent_id)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			h.tenant, agentrelay.KindConnectorTest, payload, "preview:apache:served", mtls.AgentRoleHost, agentRowID(h.tenant, h.agent))
		return execErr
	}); err != nil {
		t.Fatalf("seed host preview: %v", err)
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	profile := connector.LocalOpsConfig{
		AllowedRoots: []string{root},
		Actions: []connector.LocalAction{{
			LogicalName: "apachectl", Command: executable, PassArgs: true,
		}},
	}
	channel := &servedHostRelayChannel{client: h.client, identity: h.identity}
	executed, err := agentrelay.RunOnceWithHost(ctx, channel, http.DefaultClient, profile, 1, 60)
	if err != nil {
		t.Fatalf("run served host preview: %v", err)
	}
	if executed != 1 || !channel.lastAccepted || channel.lastOutcome != transport.JobOutcomeExecuted {
		t.Fatalf("served host preview = executed %d accepted %t outcome %q detail %q",
			executed, channel.lastAccepted, channel.lastOutcome, channel.lastDetail)
	}
	var plan agentrelay.Plan
	if err := json.Unmarshal([]byte(channel.lastDetail), &plan); err != nil {
		t.Fatalf("decode served host preview plan: %v", err)
	}
	if !plan.Ready || plan.Endpoint != listener.Addr || len(plan.WouldMutate) < 3 {
		t.Fatalf("served host preview plan = %+v, want ready target-bound plan", plan)
	}

	afterCert, err := os.ReadFile(certPath) // #nosec G304 -- path is a t.TempDir fixture (CWE-22).
	if err != nil {
		t.Fatal(err)
	}
	afterKey, err := os.ReadFile(keyPath) // #nosec G304 -- path is a t.TempDir fixture (CWE-22).
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterCert, beforeCert) || !bytes.Equal(afterKey, beforeKey) {
		t.Fatalf("served host preview changed target files: cert=%q key=%q", afterCert, afterKey)
	}

	receipts, err := h.store.ListConnectorDeliveryReceiptsPage(ctx, h.tenant, "", store.ZeroUUID, 50)
	if err != nil {
		t.Fatalf("list host preview receipts: %v", err)
	}
	for _, receipt := range receipts {
		if receipt.Destination == agentrelay.KindConnectorTest && receipt.Status == servedstatus.ConnectorTestPlanned {
			if !strings.Contains(receipt.Detail, listener.Addr) {
				t.Fatalf("planned receipt does not identify the listener: %q", receipt.Detail)
			}
			return
		}
	}
	t.Fatalf("no dry_run_planned receipt recorded; receipts = %+v", receipts)
}
