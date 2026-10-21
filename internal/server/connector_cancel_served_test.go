// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/store"
)

// A48: an operator cancels a target's in-flight connector work. A queued
// command is withdrawn, a command the enrolled host agent holds is recalled so
// its lease extension, credential redemption and result are refused (a late
// signed result is retained, not applied), a command the control-plane worker
// is executing is reported and left alone, and every withdrawn or recalled
// command gets a cancelled receipt. A second cancel finds nothing.
func TestServedOperatorCancelsQueuedAndLeasedTargetWork(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, "connector.deploy")
	token := seedScopedToken(t, h.store, h.tenant, "connectors:write", "connectors:read")
	agentID := agentRowID(h.tenant, h.agent)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}

	status, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets", token, map[string]any{
		"name": "a48-nginx", "connector": "nginx", "enabled": true,
		"config": map[string]any{
			"executor": "agent", "profile": "default", "cert_path": "/etc/nginx/a48.crt", "key_path": "/etc/nginx/a48.key",
			"required_agent_id": agentID, "required_agent_role": mtls.AgentRoleHost,
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create target = %d %s", status, body)
	}
	var target struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &target); err != nil || target.ID == "" {
		t.Fatalf("decode target: %v %s", err, body)
	}
	lane := store.ConnectorTargetLanePrefix + target.ID
	seed := func(idemKey, fingerprint string) int64 {
		t.Helper()
		payload := fmt.Sprintf(`{"connector":"nginx","target":"a48-nginx","target_id":%q,"fingerprint":%q}`, target.ID, fingerprint)
		var id int64
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, effect_lane, required_agent_role, required_agent_id)
				 VALUES ($1, 'connector.deploy', $2, $3, $4, 'host', $5::uuid) RETURNING id`,
				h.tenant, []byte(payload), idemKey, lane, agentID).Scan(&id)
		}); err != nil {
			t.Fatalf("seed host deploy job: %v", err)
		}
		return id
	}
	leased := seed("a48:deploy:1", "aa11")
	queued := seed("a48:deploy:2", "bb22")
	var executing int64
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, effect_lane, required_agent_role, status, worker_id, lease_until)
			 VALUES ($1, 'connector.deploy', $2, 'a48:deploy:cp', $3, 'control_plane', 'processing', 'worker-a48', $4) RETURNING id`,
			h.tenant, []byte(`{"connector":"f5","target":"a48-nginx","target_id":"`+target.ID+`","fingerprint":"cc33"}`),
			lane, time.Now().Add(time.Hour)).Scan(&executing)
	}); err != nil {
		t.Fatalf("seed executing worker job: %v", err)
	}

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 5, LeaseSeconds: 120})
	if err != nil || len(claimed.Jobs) != 1 || claimed.Jobs[0].JobID != leased {
		t.Fatalf("host agent claim = %+v err=%v; want exactly the first lane job %d", claimed, err, leased)
	}
	job := claimed.Jobs[0]

	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/connectors/targets/"+target.ID+"/cancel", token, "a48-cancel-1", map[string]any{"reason": "wrong certificate chosen"})
	if status != http.StatusOK {
		t.Fatalf("cancel = %d %s", status, body)
	}
	var cancelled struct {
		Withdrawn []int64 `json:"withdrawn_job_ids"`
		Recalled  []int64 `json:"recalled_job_ids"`
		Executing []int64 `json:"executing_job_ids"`
		Receipts  []struct {
			OutboxID int64  `json:"outbox_id"`
			Status   string `json:"status"`
			Detail   string `json:"detail"`
		} `json:"receipts"`
	}
	if err := json.Unmarshal(body, &cancelled); err != nil {
		t.Fatalf("decode cancel: %v %s", err, body)
	}
	if len(cancelled.Recalled) != 1 || cancelled.Recalled[0] != leased ||
		len(cancelled.Withdrawn) != 1 || cancelled.Withdrawn[0] != queued ||
		len(cancelled.Executing) != 1 || cancelled.Executing[0] != executing {
		t.Fatalf("dispositions = %s; want recalled %d, withdrawn %d, executing %d", body, leased, queued, executing)
	}
	if len(cancelled.Receipts) != 2 {
		t.Fatalf("receipts = %d, want one per withdrawn/recalled row: %s", len(cancelled.Receipts), body)
	}
	for _, receipt := range cancelled.Receipts {
		if receipt.Status != "cancelled" || receipt.Detail == "" {
			t.Fatalf("receipt %+v, want cancelled with a detail", receipt)
		}
	}

	// The recalled lease is dead for every agent operation that could change
	// the target or hand out material.
	if extended, err := h.client.ReportJobResult(ctx, &transport.ReportJobResultRequest{
		JobID: job.JobID, Attempt: job.Attempt, Outcome: transport.JobOutcomeExtend,
	}); err != nil || extended.Accepted {
		t.Fatalf("recalled job must refuse the lease extension: accepted=%v err=%v", extended != nil && extended.Accepted, err)
	}
	if redeemed, err := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: job.JobID, Attempt: job.Attempt}); err == nil && redeemed != nil && len(redeemed.Items) > 0 {
		t.Fatalf("recalled job must not redeem credential material: %+v", redeemed)
	}
	if again, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 5, LeaseSeconds: 60}); err != nil || len(again.Jobs) != 0 {
		t.Fatalf("cancelled lane must offer nothing: jobs=%d err=%v", len(again.Jobs), err)
	}

	// Rows: the two cancelled ones carry the closed class; the executing one is untouched.
	for _, tc := range []struct {
		id         int64
		wantStatus string
		wantError  string
	}{{leased, "cancelled", "operator_cancelled"}, {queued, "cancelled", "operator_cancelled"}, {executing, "processing", ""}} {
		var gotStatus, gotError string
		var recalled bool
		if err := h.store.SystemPool().QueryRow(ctx,
			`SELECT status, COALESCE(last_error, ''), agent_recalled_at IS NOT NULL FROM outbox WHERE tenant_id = $1 AND id = $2`,
			h.tenant, tc.id).Scan(&gotStatus, &gotError, &recalled); err != nil {
			t.Fatal(err)
		}
		if gotStatus != tc.wantStatus || gotError != tc.wantError || recalled != (tc.wantStatus == "cancelled") {
			t.Fatalf("row %d = %s/%s recalled=%v; want %s/%s", tc.id, gotStatus, gotError, recalled, tc.wantStatus, tc.wantError)
		}
	}

	// A late signed result from the recalled agent is retained, never applied:
	// the receipt stays cancelled.
	late, err := h.client.ReportJobResult(ctx, signedJobReport(t, h.identity, job.JobID, job.Attempt, transport.JobOutcomeVerified, "late", ""))
	if err != nil || late.Accepted || !late.ReceiptRecorded {
		t.Fatalf("late result = %+v err=%v; want retained (receipt_recorded) and not accepted", late, err)
	}
	receipt, err := h.store.GetConnectorDeliveryReceiptForOutbox(ctx, h.tenant, leased)
	if err != nil || receipt.Status != "cancelled" {
		t.Fatalf("receipt after late result = %+v err=%v; want cancelled", receipt, err)
	}

	// Nothing left on the lane: a second cancel is empty and the executing row
	// is still the only one in flight.
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/connectors/targets/"+target.ID+"/cancel", token, "a48-cancel-2", map[string]any{"reason": "again"})
	if status != http.StatusOK {
		t.Fatalf("second cancel = %d %s", status, body)
	}
	if err := json.Unmarshal(body, &cancelled); err != nil || len(cancelled.Withdrawn) != 0 || len(cancelled.Recalled) != 0 ||
		len(cancelled.Executing) != 1 || len(cancelled.Receipts) != 0 {
		t.Fatalf("second cancel = %s; want nothing cancelled and the executing row still reported", body)
	}

	// A reason is required, and connectors:read alone cannot cancel.
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/connectors/targets/"+target.ID+"/cancel", token, "a48-cancel-3", map[string]any{})
	if status != http.StatusBadRequest {
		t.Fatalf("cancel without reason = %d %s, want 400", status, body)
	}
	readOnly := seedScopedToken(t, h.store, h.tenant, "connectors:read")
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/connectors/targets/"+target.ID+"/cancel", readOnly, "a48-cancel-4", map[string]any{"reason": "x"})
	if status != http.StatusForbidden {
		t.Fatalf("cancel with connectors:read = %d %s, want 403", status, body)
	}
}
