// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
)

func TestLateReceiptRecoversRetainedFactsAfterLedgerRollback(t *testing.T) {
	testLateReceiptHistoryRecovery(t, false)
}

func TestLateReceiptRecoveryWithProductionPrivacyGuard(t *testing.T) {
	testLateReceiptHistoryRecovery(t, true)
}

func testLateReceiptHistoryRecovery(t *testing.T, requiredPolicies bool) {
	t.Helper()
	const dedup = 100 * time.Millisecond
	options := []events.OpenOption{events.WithDuplicateWindowForTesting(dedup)}
	if requiredPolicies {
		options = append(options, events.WithRequiredPrivacyEventPolicies())
	}
	h := newRoleHarnessWithEventOptions(t, []string{mtls.AgentRoleNetwork}, []string{"endpoint.verify"}, options)
	ctx := t.Context()
	seedRoleJob(t, ctx, h, "endpoint.verify", "receipt-history-gap")
	claims, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"endpoint.verify"}, Limit: 1, LeaseSeconds: 60})
	if err != nil || len(claims.Jobs) != 1 {
		t.Fatalf("claim: %+v %v", claims, err)
	}
	job := claims.Jobs[0]
	// End the mutable claim, retaining the original executor binding. Its
	// observation now enters only the late-receipt path.
	if ok, err := h.store.ReleaseAgentJob(ctx, h.tenant, agentRowID(h.tenant, h.agent), job.JobID, job.Attempt, "owned released claim", time.Now()); err != nil || !ok {
		t.Fatalf("release: %v %v", ok, err)
	}
	// Model the durable crash cut: NATS append succeeds; the following SQL write
	// rolls back. No committed row is deleted to manufacture this state.
	if _, err := h.store.SystemPool().Exec(ctx, `CREATE FUNCTION qa_late_receipt_gap() RETURNS trigger LANGUAGE plpgsql AS $$
	BEGIN RAISE EXCEPTION 'owned receipt projection gap'; END $$;
	CREATE TRIGGER qa_late_receipt_gap BEFORE INSERT OR UPDATE ON agent_job_receipts
	FOR EACH ROW EXECUTE FUNCTION qa_late_receipt_gap()`); err != nil {
		t.Fatal(err)
	}
	remove := func() {
		t.Helper()
		if _, err := h.store.SystemPool().Exec(context.Background(), `DROP TRIGGER IF EXISTS qa_late_receipt_gap ON agent_job_receipts; DROP FUNCTION IF EXISTS qa_late_receipt_gap()`); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(remove)
	original := h.report(t, job.JobID, job.Attempt, transport.JobOutcomeFailed, "original terminal observation", "original-evidence")
	if response, err := h.client.ReportJobResult(ctx, original); status.Code(err) != codes.Unavailable {
		t.Fatalf("SQL failure acknowledged: %+v %v", response, err)
	}
	var ledgerRows int
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM agent_job_receipts WHERE tenant_id=$1 AND job_id=$2 AND attempt=$3`, h.tenant, job.JobID, job.Attempt).Scan(&ledgerRows)
	}); err != nil || ledgerRows != 0 {
		t.Fatalf("expected rolled-back ledger: %d %v", ledgerRows, err)
	}
	count := func() int {
		t.Helper()
		n := 0
		if err := h.log.Replay(ctx, 0, func(e events.Event) error {
			if e.TenantID == h.tenant && e.Type == "agent.job.receipt.reconciled" {
				n++
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if got := count(); got != 1 {
		t.Fatalf("crash cut lacks one durable observation: %d", got)
	}
	remove()
	// Crossing the real JetStream duplicate window ensures broker deduplication
	// cannot substitute for reading the retained source of truth.
	time.Sleep(3 * dedup)
	changed := h.report(t, job.JobID, job.Attempt, transport.JobOutcomeFailed, "conflicting later observation", "changed-evidence")
	if response, err := h.client.ReportJobResult(ctx, changed); err != nil || response.Accepted || response.ReceiptRecorded {
		t.Errorf("conflict replaced retained facts: %+v %v", response, err)
	}
	id := h.identity.Identity()
	fresh, err := transport.SignedReport(id, id.TenantID(), id.CommonName(), job.JobID, job.Attempt, original.Outcome, original.Detail, original.EvidenceDigest, original.IssuedAtUnix+1)
	if err != nil {
		t.Fatal(err)
	}
	if response, err := h.client.ReportJobResult(ctx, fresh); err != nil || response.Accepted || !response.ReceiptRecorded {
		t.Errorf("same facts did not recover: %+v %v", response, err)
	}
	if got := count(); got != 1 {
		t.Errorf("recovery duplicated/contradicted retained evidence: %d", got)
	}
	var conflicts int
	if err := h.log.Replay(ctx, 0, func(e events.Event) error {
		if e.TenantID == h.tenant && e.Type == "agent.job.receipt.conflict" {
			conflicts++
		}
		return nil
	}); err != nil || conflicts != 1 {
		t.Errorf("conflict lacks one durable refusal: %d %v", conflicts, err)
	}

	var statement string
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT statement FROM agent_job_receipts WHERE tenant_id=$1 AND job_id=$2 AND attempt=$3 AND state='verified'`, h.tenant, job.JobID, job.Attempt).Scan(&statement)
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.log.Replay(ctx, 0, func(e events.Event) error {
		if e.TenantID != h.tenant || e.Type != "agent.job.receipt.reconciled" {
			return nil
		}
		var payload struct {
			Statement string `json:"receipt_statement"`
		}
		if err := json.Unmarshal(e.Data, &payload); err != nil {
			return err
		}
		if statement != payload.Statement {
			t.Error("recovered ledger is not the original retained signed receipt")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
