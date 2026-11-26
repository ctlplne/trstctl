// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
)

func TestServedRepeatedAgentRoleRefusalHasOneAuditEvent(t *testing.T) {
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{"trust.distribute"}, withIsolatedTenant)
	for i := 0; i < 3; i++ {
		response, err := h.client.ClaimJobs(t.Context(), &transport.ClaimJobsRequest{Kinds: []string{"trust.distribute"}, Limit: 1, LeaseSeconds: 30})
		if err != nil || len(response.Jobs) != 0 {
			t.Fatalf("role-refused claim %d = %+v err=%v", i, response, err)
		}
	}
	count := 0
	if err := h.log.Replay(t.Context(), 0, func(event events.Event) error {
		if event.TenantID == h.tenant && event.Type == "agent.jobs.role_refused" {
			count++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("repeated identical role refusals appended %d audit events, want one", count)
	}
}

func TestOversizedRejectedReceiptKeepsBoundedJobEvidence(t *testing.T) {
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, nil, withIsolatedTenant)
	svc, ok := h.srv.agentServiceForTest()
	if !ok {
		t.Fatal("agent service is unavailable")
	}
	var appendErr error
	appendAttempts := 0
	svc.appendAuditEvent = func(ctx context.Context, event events.Event) (events.Event, error) {
		appendAttempts++
		out, err := h.log.Append(ctx, event)
		appendErr = err
		return out, err
	}
	_, err := h.client.ReportJobResult(t.Context(), &transport.ReportJobResultRequest{
		JobID: 1, Attempt: 1, Outcome: strings.Repeat("x", 5000),
	})
	if err == nil {
		t.Fatal("unsigned oversized receipt was accepted")
	}
	found := false
	if err := h.log.Replay(t.Context(), 0, func(event events.Event) error {
		if event.TenantID != h.tenant || event.Type != "agent.job.receipt.rejected" {
			return nil
		}
		var body map[string]any
		if err := json.Unmarshal(event.Data, &body); err != nil {
			return err
		}
		reason, ok := body["reason"].(string)
		if body["job_id"] == float64(1) && ok && reason != "" &&
			body["outcome"] == "[oversized omitted]" && len(event.Data) < 4<<10 {
			found = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if appendAttempts != 1 || appendErr != nil || !found {
		t.Fatalf("oversized rejected receipt lost bounded job evidence; RPC error=%v append attempts=%d append error=%v", err, appendAttempts, appendErr)
	}
}
