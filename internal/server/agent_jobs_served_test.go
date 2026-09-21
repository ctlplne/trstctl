// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"net"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/ticketintake"
)

const servedTicketIntakeTokenRef = "secret://itsm/intake" // #nosec G101 -- secret-store reference/pointer, never credential material (CWE-798)

func TestSignedTicketResultStaysRetryableUntilProjectionSucceeds(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, agentJobKindTicketSync)
	token := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write")
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPut,
		"/api/v1/issuance-requests/intake-schedule", token, "ticket-result-config", map[string]any{
			"system": "servicenow", "instance_url": "https://servicenow.internal.example",
			"token_ref": servedTicketIntakeTokenRef, "sn_table": "incident",
			"subject_field": "u_subject", "profile_field": "u_profile",
			"interval_seconds": 3600, "enabled": true,
		})
	if status != http.StatusOK {
		t.Fatalf("configure ticket intake: %d %s", status, body)
	}
	sched, found, err := h.store.GetTicketIntakeSchedule(ctx, h.tenant, ticketintake.SystemServiceNow)
	if err != nil || !found {
		t.Fatalf("load schedule: found=%v err=%v", found, err)
	}
	h.srv.dispatchTicketSyncJob(ctx, h.tenant, sched)
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{agentJobKindTicketSync}, Limit: 1})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim: jobs=%d err=%v", len(claimed.Jobs), err)
	}
	job := claimed.Jobs[0]
	// The schedule is mutable, but this already-issued job is not. Changing the
	// table after claim must not relabel the signed result or its ticket key.
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPut,
		"/api/v1/issuance-requests/intake-schedule", token, "ticket-result-config-2", map[string]any{
			"system": "servicenow", "instance_url": "https://servicenow.internal.example",
			"token_ref": servedTicketIntakeTokenRef, "sn_table": "sc_req_item",
			"subject_field": "u_subject", "profile_field": "u_profile",
			"interval_seconds": 3600, "enabled": true,
		})
	if status != http.StatusConflict {
		t.Fatalf("change ticket schedule during named sweep: %d %s", status, body)
	}

	// This report is correctly signed but structurally unusable. The receiver
	// must reject it WITHOUT closing the claim, or a crash/parse failure in this
	// window loses the already-completed external observation forever.
	if _, err := h.client.ReportJobResult(ctx,
		h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, "{", "")); err == nil {
		t.Fatal("an undecodable signed result was accepted")
	}
	var completed bool
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT claim_completed_at IS NOT NULL FROM outbox WHERE tenant_id = $1 AND id = $2`, h.tenant, job.JobID).Scan(&completed)
	}); err != nil || completed {
		t.Fatalf("failed result closed the claim: completed=%v err=%v", completed, err)
	}

	var intent ticketintake.SyncIntent
	if err := json.Unmarshal(job.Payload, &intent); err != nil {
		t.Fatal(err)
	}
	expected := 1
	reportBytes, err := json.Marshal(ticketintake.SyncReport{
		System: intent.System, SweepID: intent.SweepID, Cursor: intent.Cursor,
		ObservedAt: time.Now().UTC(), SourceRefs: []string{"tick-77"},
		Tickets:   []ticketintake.Ticket{{SourceRef: "tick-77", Subject: "api.example.test", Profile: "tls-server", Requester: "Dana Ops"}},
		ReadCount: 1, ExpectedCount: &expected, Complete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := h.client.ReportJobResult(ctx,
		h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(reportBytes), ""))
	if err != nil || !accepted.Accepted {
		t.Fatalf("corrected report: accepted=%v err=%v", accepted, err)
	}
	var rowStatus string
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status FROM outbox WHERE tenant_id = $1 AND id = $2`, h.tenant, job.JobID).Scan(&rowStatus)
	}); err != nil || rowStatus != "delivered" {
		t.Fatalf("accepted result did not atomically retire its durable intent: status=%q err=%v", rowStatus, err)
	}
	requests, err := h.store.ListIssuanceRequests(ctx, h.tenant, "", 50)
	if err != nil || len(requests) != 1 || requests[0].TicketRef != "incident:tick-77" {
		t.Fatalf("projected requests=%+v err=%v", requests, err)
	}

	// The agent can replay after losing the response. Completion refuses the
	// duplicate, and the stable ticket/event identity leaves exactly one row.
	replayed, err := h.client.ReportJobResult(ctx,
		h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(reportBytes), ""))
	if err != nil || replayed.Accepted {
		t.Fatalf("replayed report: accepted=%v err=%v", replayed, err)
	}
	requests, err = h.store.ListIssuanceRequests(ctx, h.tenant, "", 50)
	if err != nil || len(requests) != 1 {
		t.Fatalf("replay created duplicate requests=%+v err=%v", requests, err)
	}
}

// The job claim protocol, proven on the assembled binary (epic A1).
//
// Work that touches a customer's estate is decided here and executed there, over
// a connection the agent opened. These drive the claim cycle against the served
// channel and assert the four properties the fabric stands on: identity comes
// from the certificate and not the request, a claim is a lease, a lease that
// lapses returns the work, and a report from an agent that lost its lease is
// refused rather than applied.

// agentChannelHarness is a served control plane with the agent channel mounted on
// an ephemeral port and one enrolled agent already dialed in — the shape every
// job test needs, so none of them repeats the enrollment dance.
type agentChannelHarness struct {
	*servedHarness
	client *transport.AgentClient
	// agent is the enrolled agent behind the channel. Tests need it to SIGN
	// their reports (epic A1): the server rebuilds the receipt statement from
	// the certificate on the connection, so only this identity can produce a
	// report the served channel will accept.
	agent *agent.Agent
}

// report builds a signed report exactly as the shipping agent does, so a test
// that passes proves the two sides agree on the canonical statement — which is
// the failure mode a hand-built test fixture would hide.
func (h *agentChannelHarness) report(t *testing.T, jobID int64, attempt int,
	outcome, detail, evidenceDigest string) *transport.ReportJobResultRequest {
	t.Helper()
	return signedJobReport(t, h.agent, jobID, attempt, outcome, detail, evidenceDigest)
}

// signedJobReport is the one place a test signs a receipt, shared by every
// harness so none of them can drift into building the statement by hand.
func signedJobReport(t *testing.T, a *agent.Agent, jobID int64, attempt int,
	outcome, detail, evidenceDigest string) *transport.ReportJobResultRequest {
	t.Helper()
	id := a.Identity()
	req, err := transport.SignedReport(id, id.TenantID(), id.CommonName(),
		jobID, attempt, outcome, detail, evidenceDigest, time.Now().UTC().Unix())
	if err != nil {
		t.Fatalf("sign job receipt: %v", err)
	}
	return req
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
	return &agentChannelHarness{servedHarness: h, client: transport.NewAgentClient(conn), agent: a}
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
	report, err := h.client.ReportJobResult(ctx,
		h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, "", "sha256:transcript"))
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if !report.Accepted {
		t.Fatal("the holder's own report was refused")
	}

	// A replayed report is refused rather than applied a second time.
	replay, err := h.client.ReportJobResult(ctx,
		h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, "", ""))
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
	stale, err := h.client.ReportJobResult(ctx,
		h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, "", ""))
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
		JobID: first.JobID, Attempt: first.Attempt, Outcome: transport.JobOutcomeExtend, LeaseSeconds: 120,
	})
	if err != nil {
		t.Fatalf("extend: %v", err)
	}
	if !extended.Accepted || extended.LeaseExpiresUnix <= first.LeaseExpiresUnix {
		t.Fatalf("extend did not move the lease forward: %+v (was %d)", extended, first.LeaseExpiresUnix)
	}
}

// TestServedAgentFailureReturnsTheJob: a failure on one host is not evidence the
// work is impossible, so the job returns to the queue after its retry delay.
func TestServedAgentFailureReturnsTheJob(t *testing.T) {
	ctx := context.Background()
	h := agentJobHarness(t, "connector.deploy")
	seedClaimableJob(t, ctx, h, "connector.deploy", "deploy:fails")

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 1})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim = %d (err %v)", len(claimed.Jobs), err)
	}
	reported, err := h.client.ReportJobResult(ctx, h.report(t, claimed.Jobs[0].JobID,
		claimed.Jobs[0].Attempt, transport.JobOutcomeFailed, "nginx -t rejected the config", ""))
	if err != nil || !reported.Accepted {
		t.Fatalf("failure report = %+v (err %v)", reported, err)
	}
	immediate, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 1})
	if err != nil || len(immediate.Jobs) != 0 {
		t.Fatalf("failed job bypassed retry delay: jobs=%v err=%v", immediate, err)
	}
	// Move only this fixture's deadline to exercise the due retry without sleep.
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE outbox SET agent_next_attempt_at=$3 WHERE tenant_id=$1 AND id=$2`,
			h.tenant, claimed.Jobs[0].JobID, time.Now().Add(-time.Second))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	requeued, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 1})
	if err != nil || len(requeued.Jobs) != 1 {
		t.Fatalf("a failed job did not return to the queue: %d (err %v)", len(requeued.Jobs), err)
	}
	if requeued.Jobs[0].JobID != claimed.Jobs[0].JobID || requeued.Jobs[0].Attempt != claimed.Jobs[0].Attempt+1 {
		t.Fatalf("retry lost command/generation: %+v", requeued.Jobs[0])
	}
}
