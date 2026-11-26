// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/hostaccounts"
	"trstctl.com/trstctl/internal/projections"
)

func TestSignedOversizedNativeFailureRefusedBeforeAppendN0010(t *testing.T) {
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, []string{hostaccounts.InventoryDestination}, func(d *Deps) {
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	ctx := t.Context()
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	hostID := agentRowID(h.tenant, h.agent)
	token := seedScopedTokenSubject(t, h.store, h.tenant, "receipt-operator", "access:read", "access:targets.write")
	path := "/api/v1/access/discovery/windows-hosts/" + hostID + "/local-administrators/runs"
	if code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, path, token, "bounded-failure", nil); code != http.StatusAccepted {
		t.Fatalf("queue status=%d body=%s", code, body)
	}
	claims, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{hostaccounts.InventoryDestination}, Limit: 1, LeaseSeconds: 120})
	if err != nil || len(claims.Jobs) != 1 {
		t.Fatalf("claim=%+v err=%v", claims, err)
	}
	job := claims.Jobs[0]
	req := h.report(t, job.JobID, job.Attempt, transport.JobOutcomeFailed, "native reader unavailable", "")
	req.EvidenceDigest = strings.Repeat("a", 33<<10)
	statement := transport.JobReceiptStatement{
		TenantID: h.tenant, AgentCommonName: h.agent, JobID: job.JobID, Attempt: job.Attempt,
		Outcome: req.Outcome, EvidenceDigest: req.EvidenceDigest, DetailDigest: transport.DetailDigest(req.Detail),
		IssuedAtUnix: req.IssuedAtUnix,
	}
	// Sign the oversized bytes directly. The shipping constructor now refuses
	// them, but an enrolled hostile agent can still sign arbitrary bytes.
	req.Signature, err = h.identity.Identity().SignStatement(statement.Canonical())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.ReportJobResult(ctx, req); err == nil {
		t.Fatal("oversized signed failure was accepted")
	}
	if err := projections.New(h.store).ProjectCatchUp(ctx, h.log); err != nil {
		t.Fatalf("rejected receipt poisoned the global event tail: %v", err)
	}
	good := h.report(t, job.JobID, job.Attempt, transport.JobOutcomeFailed, "native reader unavailable", "")
	accepted, err := h.client.ReportJobResult(ctx, good)
	if err != nil || !accepted.Accepted {
		t.Fatalf("bounded signed failure rejected: response=%+v err=%v", accepted, err)
	}
	// Defense at the final producer boundary also protects callers added after
	// this RPC: the event must be rejected before it gets a JetStream sequence.
	eventID := uuid.NewString()
	bad := projections.WindowsLocalAccountScanFailed{
		RunID: uuid.NewString(), JobID: job.JobID, Attempt: job.Attempt,
		Reason: "agent_execution_failed", ReceiptStatement: strings.Repeat("x", 33<<10),
		ReceiptSignature: "c2ln", SignerFingerprint: strings.Repeat("a", 64), At: time.Now().UTC(),
	}
	producer := &agentService{store: h.store, log: h.log}
	if err := producer.appendServiceDependentAgentEventID(ctx, h.tenant, eventID, projections.EventWindowsLocalAccountScanFailed, bad); err == nil {
		t.Fatal("producer appended an unprojectable native failure")
	}
	if _, found, err := h.log.EventByID(ctx, eventID); err != nil || found {
		t.Fatalf("unprojectable native failure reached JetStream: found=%v err=%v", found, err)
	}
}
