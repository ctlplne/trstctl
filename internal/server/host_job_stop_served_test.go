// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/store"

	"github.com/jackc/pgx/v5"
)

// A public revocation must finish idle issuance work rather than leave an
// unclaimable pending job in the operator's queue indefinitely.
func TestServedTerminalIdentityCancelsIdleHostWork(t *testing.T) {
	h, token, identityID := servedHostRevocationFixture(t)
	ctx := t.Context()
	var id int64
	var before []byte
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id, payload FROM outbox
		 WHERE tenant_id=$1 AND destination='endpoint.renew'
		 AND convert_from(payload,'UTF8')::jsonb->>'identity_id'=$2`, h.tenant, identityID).Scan(&id, &before)
	}); err != nil {
		t.Fatal(err)
	}
	servedHostLifecycleTransition(t, h, token, identityID, "revoked", "stop-idle-host", http.StatusOK)
	assertStoppedHostWork(t, ctx, h, id, before)
	servedHostLifecycleTransition(t, h, token, identityID, "retired", "retire-idle-host", http.StatusOK)
	assertStoppedHostWork(t, ctx, h, id, before)
}

func assertStoppedHostWork(t *testing.T, ctx context.Context, h *roleHarness, id int64, original []byte) {
	t.Helper()
	row, err := h.srv.outbox.Get(ctx, h.tenant, id)
	if err != nil {
		t.Fatal(err)
	}
	if row.Status != "cancelled" {
		t.Fatalf("stopped identity's idle issuance job status=%q, want cancelled", row.Status)
	}
	if string(row.Payload) != string(original) || row.Attempts != 0 {
		t.Fatal("cancellation rewrote the original command or retry history")
	}
}

func TestServedTerminalIdentityPreservesLiveClaimUntilRelease(t *testing.T) {
	h, token, identityID := servedHostRevocationFixture(t)
	ctx := t.Context()
	job := claimOneRenewal(t, ctx, h)
	before, err := h.srv.outbox.Get(ctx, h.tenant, job.JobID)
	if err != nil {
		t.Fatal(err)
	}
	servedHostLifecycleTransition(t, h, token, identityID, "revoked", "stop-held-host", http.StatusOK)
	held, err := h.srv.outbox.Get(ctx, h.tenant, job.JobID)
	if err != nil || held.Status != "pending" {
		t.Fatalf("live claim was changed: status=%s err=%v", held.Status, err)
	}
	result, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeFailed, "signing refused", ""))
	if err != nil || !result.Accepted {
		t.Fatalf("live failure report: result=%v err=%v", result, err)
	}
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{agentJobKindEndpointRenew}, Limit: 5})
	if err != nil || len(claimed.Jobs) != 0 {
		t.Fatalf("stopped work was reclaimed: result=%v err=%v", claimed, err)
	}
	after, err := h.srv.outbox.Get(ctx, h.tenant, job.JobID)
	if err != nil || after.Status != "cancelled" || after.Attempts != 1 || string(after.Payload) != string(before.Payload) || after.LastError != store.AgentFailureReported {
		t.Fatalf("cancelled job lost failure history: status=%s attempts=%d reason=%s err=%v", after.Status, after.Attempts, after.LastError, err)
	}
	late, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeFailed, "late replay", ""))
	if err != nil || late.Accepted {
		t.Fatalf("late report was accepted: result=%v err=%v", late, err)
	}
}

func TestServedTerminalIdentityCancelsExpiredClaimWithRenewalDisabled(t *testing.T) {
	h, token, identityID := servedHostRevocationFixture(t)
	ctx := t.Context()
	job := claimOneRenewal(t, ctx, h)
	before, err := h.srv.outbox.Get(ctx, h.tenant, job.JobID)
	if err != nil {
		t.Fatal(err)
	}
	servedHostLifecycleTransition(t, h, token, identityID, "revoked", "stop-expired-host", http.StatusOK)
	h.srv.lifecycleRenewBefore = 0
	h.srv.lifecycleAlertBefore = 0
	h.srv.ownershipAttestationCadence = 0
	if _, err := h.srv.runLifecycleOnceAt(ctx, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	assertStoppedHostWork(t, ctx, h, job.JobID, before.Payload)
	late, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeFailed, "late expired result", ""))
	if err != nil || late.Accepted {
		t.Fatalf("expired generation was accepted: result=%v err=%v", late, err)
	}
}
