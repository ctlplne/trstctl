// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"net"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
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
	client *transport.AgentClient
	agent  string
}

func newRoleHarness(t *testing.T, roles []string, claimable ...string) *roleHarness {
	t.Helper()
	h := newServedHarness(t, config.Protocols{}, withAgentChannel, func(d *Deps) {
		d.AgentClaimableJobKinds = claimable
	})
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
	return &roleHarness{servedHarness: h, client: transport.NewAgentClient(conn), agent: cn}
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
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, "discovery.run")
	seedRoleJob(t, ctx, h, "discovery.run", "discover:seg-1")

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{
		Kinds: []string{"discovery.run"}, Limit: 5, LeaseSeconds: 60,
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
	h := newRoleHarness(t, nil, "discovery.run", "endpoint.verify")
	seedRoleJob(t, ctx, h, "discovery.run", "discover:legacy-1")
	seedRoleJob(t, ctx, h, "endpoint.verify", "verify:legacy-1")

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{
		Kinds: []string{"discovery.run", "endpoint.verify"}, Limit: 5, LeaseSeconds: 60,
	})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed.Jobs) != 1 {
		t.Fatalf("grant-less agent claimed %d jobs, want 1 (host work only)", len(claimed.Jobs))
	}
	if claimed.Jobs[0].Kind != "discovery.run" {
		t.Fatalf("grant-less agent claimed %q, want discovery.run", claimed.Jobs[0].Kind)
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
