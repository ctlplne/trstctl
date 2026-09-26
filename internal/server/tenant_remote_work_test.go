// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func TestServedAgentTerminalReceiptReleasesTenantLifecycle(t *testing.T) {
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, "endpoint.verify")
	ctx := events.ContextWithActor(t.Context(), events.Actor{Subject: "remote-work-admin", Roles: []string{"admin"}})
	seedRoleJob(t, ctx, h, "endpoint.verify", "remote-work-proof")
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"endpoint.verify"}, Limit: 1, LeaseSeconds: 60})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	job := claimed.Jobs[0]
	registration, err := orchestrator.ResolveLiveTenantRegistrationAuthority(ctx, h.log, h.store, h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	command := orchestrator.TenantOffboardCommand{TenantID: h.tenant, RegistrationIdentity: registration.EventID}
	prepare := func() error {
		return h.store.WithTenantServiceBarrier(ctx, h.tenant, func(work context.Context) error { return h.srv.orch.PrepareTenantOffboard(work, command) })
	}
	if err := prepare(); !errors.Is(err, store.ErrTenantServiceBusy) {
		t.Fatalf("claimed remote work allowed preparation: %v", err)
	}
	if _, err := h.client.ReportJobResult(ctx, &transport.ReportJobResultRequest{JobID: job.JobID, Attempt: job.Attempt, Outcome: transport.JobOutcomeFailed}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unsigned report: %v", err)
	}
	if err := prepare(); !errors.Is(err, store.ErrTenantServiceBusy) {
		t.Fatalf("unsigned report released remote work: %v", err)
	}
	request := h.report(t, job.JobID, job.Attempt, transport.JobOutcomeFailed, "owned test executor stopped", "")
	result, err := h.client.ReportJobResult(ctx, request)
	if err != nil || !result.Accepted {
		t.Fatalf("signed terminal report=%+v err=%v", result, err)
	}
	if err := prepare(); err != nil {
		t.Fatalf("terminal receipt did not release preparation: %v", err)
	}
	if err := h.store.WithTenantServiceBarrier(ctx, h.tenant, func(work context.Context) error { _, err := h.srv.orch.OffboardTenant(work, command); return err }); err != nil {
		t.Fatalf("terminal remote work prevented deletion: %v", err)
	}
}

func TestServedAgentReceiptWriteFailureKeepsClaimRetryable(t *testing.T) {
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, "endpoint.verify")
	ctx := t.Context()
	seedRoleJob(t, ctx, h, "endpoint.verify", "receipt-write-failure")
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"endpoint.verify"}, Limit: 1, LeaseSeconds: 60})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim=%+v err=%v", claimed, err)
	}
	job := claimed.Jobs[0]
	_, err = h.store.SystemPool().Exec(ctx, `CREATE FUNCTION qa_terminal_receipt_failure() RETURNS trigger LANGUAGE plpgsql AS $$
	BEGIN IF NEW.state='verified' THEN RAISE EXCEPTION 'owned receipt write failure'; END IF; RETURN NEW; END $$;
	CREATE TRIGGER qa_terminal_receipt_failure BEFORE INSERT OR UPDATE ON agent_job_receipts
	FOR EACH ROW EXECUTE FUNCTION qa_terminal_receipt_failure()`)
	if err != nil {
		t.Fatal(err)
	}
	remove := func() {
		t.Helper()
		if _, err := h.store.SystemPool().Exec(context.Background(), `DROP TRIGGER IF EXISTS qa_terminal_receipt_failure ON agent_job_receipts; DROP FUNCTION IF EXISTS qa_terminal_receipt_failure()`); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(remove)
	request := h.report(t, job.JobID, job.Attempt, transport.JobOutcomeFailed, "owned executor completed", "")
	result, err := h.client.ReportJobResult(ctx, request)
	if status.Code(err) != codes.Unavailable {
		t.Errorf("receipt persistence failure was acknowledged: result=%+v err=%v", result, err)
	}
	remove()
	result, err = h.client.ReportJobResult(ctx, request)
	if err != nil || !result.Accepted {
		t.Fatalf("same signed report was not retryable: %+v %v", result, err)
	}
	if err := h.store.RequireTenantAgentWorkQuiescent(ctx, h.tenant); err != nil {
		t.Fatalf("retried report did not resolve remote work: %v", err)
	}
}
