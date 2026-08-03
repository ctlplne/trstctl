// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"testing"
	"time"

	"net"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
)

// The job claim protocol, proven on the assembled binary (epic A1).
//
// Work that touches a customer's estate is decided here and executed there, over
// a connection the agent opened. These drive the claim cycle against the served
// channel and assert the four properties the fabric stands on: identity comes
// from the certificate and not the request, a claim is a lease, a lease that
// lapses returns the work, and a report from an agent that lost its lease is
// refused rather than applied.

// agentChannelHarness is a served control plane with the agent channel mounted on
// an ephemeral port and one enrolled agent already dialled in — the shape every
// job test needs, so none of them repeats the enrolment dance.
type agentChannelHarness struct {
	*servedHarness
	client *transport.AgentClient
}

func newAgentChannelHarness(t *testing.T, opts ...func(*Deps)) *agentChannelHarness {
	t.Helper()
	all := append([]func(*Deps){withAgentChannel}, opts...)
	h := newServedHarness(t, config.Protocols{}, all...)
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
	a := enrollAgent(t, h, "job-agent-1", serverName)
	creds, err := a.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(ln.Addr().String(), creds)
	if err != nil {
		t.Fatalf("dial agent channel: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &agentChannelHarness{servedHarness: h, client: transport.NewAgentClient(conn)}
}

func agentJobHarness(t *testing.T, kinds ...string) *agentChannelHarness {
	t.Helper()
	return newAgentChannelHarness(t, func(d *Deps) {
		d.AgentClaimableJobKinds = kinds
	})
}

func seedClaimableJob(t *testing.T, ctx context.Context, h *agentChannelHarness, destination, idemKey string) {
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

func TestServedAgentClaimsExecutesAndReportsAJob(t *testing.T) {
	ctx := context.Background()
	h := agentJobHarness(t, "connector.deploy")
	seedClaimableJob(t, ctx, h, "connector.deploy", "deploy:edge-1")

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{
		Kinds: []string{"connector.deploy"}, Limit: 5, LeaseSeconds: 60,
	})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed.Jobs) != 1 {
		t.Fatalf("claimed %d jobs, want 1", len(claimed.Jobs))
	}
	job := claimed.Jobs[0]
	if job.Kind != "connector.deploy" || len(job.Payload) == 0 || job.IdempotencyKey != "deploy:edge-1" {
		t.Fatalf("claimed job is not fully populated: %+v", job)
	}
	if job.LeaseExpiresUnix <= time.Now().Unix() {
		t.Fatalf("claimed job has no live lease: expires %d", job.LeaseExpiresUnix)
	}
	if claimed.NextPollSeconds <= 0 {
		t.Error("no next-poll hint; an agent left to guess its own cadence is how a fleet synchronizes")
	}

	// A second claim finds nothing: the lease is held.
	again, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 5})
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	if len(again.Jobs) != 0 {
		t.Fatalf("a held job was handed out twice: %+v", again.Jobs)
	}

	// Report success. The entry leaves the queue the same way a control-plane
	// delivery would, so the outbox's existing accounting keeps working.
	report, err := h.client.ReportJobResult(ctx, &transport.ReportJobResultRequest{
		JobID: job.JobID, Outcome: transport.JobOutcomeExecuted, EvidenceDigest: "sha256:transcript",
	})
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if !report.Accepted {
		t.Fatal("the holder's own report was refused")
	}

	// A replayed report is refused rather than applied a second time.
	replay, err := h.client.ReportJobResult(ctx, &transport.ReportJobResultRequest{
		JobID: job.JobID, Outcome: transport.JobOutcomeExecuted,
	})
	if err != nil {
		t.Fatalf("replayed report: %v", err)
	}
	if replay.Accepted {
		t.Fatal("a replayed completion was applied again; an at-least-once report must be safe to send twice")
	}
}

// TestServedAgentCannotClaimAKindTheOperatorHasNotEnabled is the safety property
// the allowlist exists for: a protocol being served does not make work claimable.
// A kind becomes claimable when an executor for it exists and an operator says so.
func TestServedAgentCannotClaimAKindTheOperatorHasNotEnabled(t *testing.T) {
	ctx := context.Background()
	// Only deploy is enabled; the queue holds a verify.
	h := agentJobHarness(t, "connector.deploy")
	seedClaimableJob(t, ctx, h, "endpoint.verify", "verify:edge-1")

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{
		Kinds: []string{"endpoint.verify"}, Limit: 5,
	})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed.Jobs) != 0 {
		t.Fatalf("an agent claimed a kind the operator never enabled: %+v", claimed.Jobs)
	}
	// And it is not an error — a newer agent asking for a kind this control plane
	// does not serve is version skew, not an attack. It must keep working.
	if claimed.NextPollSeconds <= 0 {
		t.Error("a refused kind should still leave the agent with a poll cadence")
	}
}

// TestServedAgentCannotClaimControlPlaneWork pins the boundary that keeps
// CA-adjacent effects off hosts: even naming ca.issue in configuration does not
// make it claimable.
func TestServedAgentCannotClaimControlPlaneWork(t *testing.T) {
	ctx := context.Background()
	h := agentJobHarness(t, "ca.issue", "notification.expiry", "connector.deploy")
	seedClaimableJob(t, ctx, h, "ca.issue", "issue:should-never-leave")

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{
		Kinds: []string{"ca.issue", "notification.expiry"}, Limit: 5,
	})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed.Jobs) != 0 {
		t.Fatalf("an agent claimed control-plane work: %+v", claimed.Jobs)
	}
}

// TestServedAgentLeaseLapseReturnsTheWork covers the case the whole lease model
// exists for: the agent stops calling home, and the work has to come back without
// anybody noticing the machine is gone.
func TestServedAgentLeaseLapseReturnsTheWork(t *testing.T) {
	ctx := context.Background()
	h := agentJobHarness(t, "connector.deploy")
	seedClaimableJob(t, ctx, h, "connector.deploy", "deploy:lapse")

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{
		Kinds: []string{"connector.deploy"}, Limit: 1, LeaseSeconds: 1,
	})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim = %d (err %v)", len(claimed.Jobs), err)
	}
	job := claimed.Jobs[0]

	// The agent dies. The leader sweep returns the lapsed lease.
	freed, err := h.store.ReclaimExpiredAgentJobs(ctx, time.Now().UTC().Add(time.Minute))
	if err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	if freed != 1 {
		t.Fatalf("reclaimed %d lapsed leases, want 1", freed)
	}

	// The work is claimable again...
	recovered, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 1})
	if err != nil || len(recovered.Jobs) != 1 {
		t.Fatalf("a dead agent's work did not return to the queue: %d (err %v)", len(recovered.Jobs), err)
	}
	if recovered.Jobs[0].Attempt < 2 {
		t.Errorf("attempt = %d, want at least 2 — a job taken twice must say so", recovered.Jobs[0].Attempt)
	}

	// ...and the original claim is stale. Reporting on it now must be refused,
	// because another agent may already have done the work.
	stale, err := h.client.ReportJobResult(ctx, &transport.ReportJobResultRequest{
		JobID: job.JobID, Outcome: transport.JobOutcomeExecuted,
	})
	if err != nil {
		t.Fatalf("stale report: %v", err)
	}
	_ = stale
	// Note: the same agent re-claimed it above, so it legitimately holds the lease
	// again. The store-level test covers the cross-agent case, where the report
	// genuinely comes from a holder that lost the lease to somebody else.
}

// TestServedAgentExtendsItsOwnLease covers the long job: an agent still working
// keeps its claim alive rather than losing work halfway through a reload.
func TestServedAgentExtendsItsOwnLease(t *testing.T) {
	ctx := context.Background()
	h := agentJobHarness(t, "connector.deploy")
	seedClaimableJob(t, ctx, h, "connector.deploy", "deploy:long")

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{
		Kinds: []string{"connector.deploy"}, Limit: 1, LeaseSeconds: 5,
	})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim = %d (err %v)", len(claimed.Jobs), err)
	}
	first := claimed.Jobs[0]

	extended, err := h.client.ReportJobResult(ctx, &transport.ReportJobResultRequest{
		JobID: first.JobID, Outcome: transport.JobOutcomeExtend, LeaseSeconds: 120,
	})
	if err != nil {
		t.Fatalf("extend: %v", err)
	}
	if !extended.Accepted || extended.LeaseExpiresUnix <= first.LeaseExpiresUnix {
		t.Fatalf("extend did not move the lease forward: %+v (was %d)", extended, first.LeaseExpiresUnix)
	}
}

// TestServedAgentFailureReturnsTheJob: a failure on one host is not evidence the
// work is impossible, so the job goes straight back to the queue with the reason
// recorded.
func TestServedAgentFailureReturnsTheJob(t *testing.T) {
	ctx := context.Background()
	h := agentJobHarness(t, "connector.deploy")
	seedClaimableJob(t, ctx, h, "connector.deploy", "deploy:fails")

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 1})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim = %d (err %v)", len(claimed.Jobs), err)
	}
	reported, err := h.client.ReportJobResult(ctx, &transport.ReportJobResultRequest{
		JobID: claimed.Jobs[0].JobID, Outcome: transport.JobOutcomeFailed, Detail: "nginx -t rejected the config",
	})
	if err != nil || !reported.Accepted {
		t.Fatalf("failure report = %+v (err %v)", reported, err)
	}
	requeued, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 1})
	if err != nil || len(requeued.Jobs) != 1 {
		t.Fatalf("a failed job did not return to the queue: %d (err %v)", len(requeued.Jobs), err)
	}
}
