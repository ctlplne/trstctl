// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

func TestServedLateAgentReceiptResolvesOnlyOriginalAttempt(t *testing.T) {
	testServedLateAgentReceipt(t, transport.JobOutcomeFailed)
}

func TestServedLateExecutedReceiptDoesNotApplyCurrentState(t *testing.T) {
	testServedLateAgentReceipt(t, transport.JobOutcomeExecuted)
}

func testServedLateAgentReceipt(t *testing.T, outcome string) {
	t.Helper()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, "endpoint.verify")
	ctx := t.Context()
	seedRoleJob(t, ctx, h, "endpoint.verify", "late-receipt-proof")
	claim := func() transport.ClaimedJob {
		t.Helper()
		result, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"endpoint.verify"}, Limit: 1, LeaseSeconds: 60})
		if err != nil || len(result.Jobs) != 1 {
			t.Fatalf("claim=%+v err=%v", result, err)
		}
		return result.Jobs[0]
	}
	first := claim()
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE outbox SET claim_expires_at=$3 WHERE tenant_id=$1 AND id=$2`, h.tenant, first.JobID, time.Now().Add(-time.Minute))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.ReclaimExpiredAgentJobs(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	second := claim()
	if second.JobID != first.JobID || second.Attempt != first.Attempt+1 {
		t.Fatalf("unexpected successor attempt: first=%+v second=%+v", first, second)
	}
	snapshot := func() string {
		t.Helper()
		var value string
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT to_jsonb(o)::text FROM outbox o WHERE tenant_id=$1 AND id=$2`, h.tenant, first.JobID).Scan(&value)
		}); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := snapshot()
	unsigned := &transport.ReportJobResultRequest{JobID: first.JobID, Attempt: first.Attempt, Outcome: transport.JobOutcomeFailed}
	if _, err := h.client.ReportJobResult(ctx, unsigned); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unsigned late receipt accepted: %v", err)
	}
	unknown := h.report(t, first.JobID, second.Attempt+1, transport.JobOutcomeFailed, "unissued attempt", "")
	if result, err := h.client.ReportJobResult(ctx, unknown); err != nil || result.Accepted || result.ReceiptRecorded {
		t.Fatalf("unissued generation accepted: %+v %v", result, err)
	}
	other := enrollAgentWithRoles(t, h.servedHarness, "different-recipient", h.serverName, []string{mtls.AgentRoleNetwork})
	credentials, err := other.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(h.channelAddr, credentials)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	otherRequest := signedJobReport(t, other, first.JobID, first.Attempt, outcome, "not my claim", "")
	if result, err := transport.NewAgentClient(conn).ReportJobResult(ctx, otherRequest); err != nil || result.Accepted || result.ReceiptRecorded {
		t.Fatalf("different tenant agent stole original completion authority: %+v %v", result, err)
	}
	// This is deliberately not an endpoint-verification transcript: a late
	// executed report must not reach the live observation parser/projector.
	original := h.report(t, first.JobID, first.Attempt, outcome, "original executor has stopped", "")
	for i := 0; i < 2; i++ {
		result, err := h.client.ReportJobResult(ctx, original)
		if err != nil || result.Accepted || !result.ReceiptRecorded || result.LeaseExpiresUnix != 0 {
			t.Fatalf("original signed completion cannot recover after reclaim (send %d): %+v %v", i, result, err)
		}
	}
	if after := snapshot(); after != before {
		t.Fatal("late report mutated successor claim or queue state")
	}
	readReceipt := func() string {
		t.Helper()
		var value string
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT to_jsonb(r)::text FROM agent_job_receipts r WHERE tenant_id=$1 AND job_id=$2 AND attempt=$3 AND state='verified'`, h.tenant, first.JobID, first.Attempt).Scan(&value)
		}); err != nil {
			t.Fatal(err)
		}
		return value
	}
	originalReceipt := readReceipt()
	conflict := h.report(t, first.JobID, first.Attempt, outcome, "different observation for the same completed executor", "different-evidence")
	if result, err := h.client.ReportJobResult(ctx, conflict); err != nil || result.Accepted || result.ReceiptRecorded {
		t.Errorf("conflicting late observation was accepted: %+v %v", result, err)
	}
	if after := readReceipt(); after != originalReceipt {
		t.Error("conflicting late observation replaced original verified receipt")
	}

	var audited int
	if err := h.log.Replay(ctx, 0, func(e events.Event) error {
		if e.TenantID != h.tenant || e.Type != "agent.job.receipt.reconciled" {
			return nil
		}
		var record struct {
			JobID             int64  `json:"job_id"`
			Attempt           int    `json:"attempt"`
			Outcome           string `json:"outcome"`
			CurrentState      *bool  `json:"current_state_applied"`
			Statement         string `json:"receipt_statement"`
			Signature         string `json:"receipt_signature"`
			SignerFingerprint string `json:"receipt_signer_fingerprint"`
		}
		if err := json.Unmarshal(e.Data, &record); err != nil {
			return err
		}
		if record.JobID != first.JobID || record.Attempt != first.Attempt || record.Outcome != outcome || record.CurrentState == nil || *record.CurrentState || record.Statement == "" || record.Signature == "" || record.SignerFingerprint == "" {
			t.Error("late completion audit lost its original binding, signed proof, or observation-only status")
		}
		audited++
		return nil
	}); err != nil || audited != 1 {
		t.Fatalf("late completion was not auditable: records=%d err=%v", audited, err)
	}
	if err := h.store.RequireTenantAgentWorkQuiescent(ctx, h.tenant); !errors.Is(err, store.ErrTenantServiceBusy) {
		t.Fatalf("original receipt prematurely resolved the current executor: %v", err)
	}
	current := h.report(t, second.JobID, second.Attempt, transport.JobOutcomeFailed, "current executor has stopped", "")
	if result, err := h.client.ReportJobResult(ctx, current); err != nil || !result.Accepted {
		t.Fatalf("current completion refused: %+v %v", result, err)
	}
	if err := h.store.RequireTenantAgentWorkQuiescent(context.Background(), h.tenant); err != nil {
		t.Fatalf("both terminal reports did not release lifecycle hold: %v", err)
	}
}
