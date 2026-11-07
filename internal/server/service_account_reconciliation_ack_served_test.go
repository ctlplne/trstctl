// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"io"
	"net/http"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

func TestServedReconciliationKeepsFirstCommandAfterProjectionLossA267(t *testing.T) {
	servedDependentRotationScenario(t, nil, false, dependentRotationOptions{Reconcile: true, LoseQueueProjection: true})
}

// Hold only the owned parent's existing advisory key. The request appends its
// immutable command and then waits at projection. Canceling the HTTP context
// forces the database transaction to roll back without touching other tenants.
func interruptDependentQueueProjection(t *testing.T, h *roleHarness, root, token, planID string, request map[string]any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	held, release, holderDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		holderDone <- h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "service-dependent-parent:"+h.tenant+":"+planID); err != nil {
				return err
			}
			close(held)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-held:
	case err := <-holderDone:
		t.Fatal("owned parent lock unavailable", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	requestCtx, cancelRequest := context.WithCancel(ctx)
	defer cancelRequest()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, h.ts.URL+root+"/rotations", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "owned-interrupted-queue-projection")
	type result struct {
		status int
		err    error
	}
	done := make(chan result, 1)
	go func() {
		response, err := h.ts.Client().Do(req)
		value := result{err: err}
		if response != nil {
			value.status = response.StatusCode
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
			_ = response.Body.Close()
		}
		done <- value
	}()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		_, found, err := h.log.EventByID(ctx, planID)
		if err != nil {
			t.Fatal(err)
		}
		if found {
			break
		}
		select {
		case value := <-done:
			t.Fatalf("queue returned before its source/projection gap: status=%d err=%v", value.status, value.err)
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	cancelRequest()
	select {
	case value := <-done:
		if value.status == http.StatusAccepted {
			t.Fatal("blocked projection falsely reported queued")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// Wait for the canceled projection's approval row lock to be released before
	// inspecting its durable pre-append claim. Do not release the parent gate yet.
	for {
		err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			var id string
			return tx.QueryRow(ctx, `SELECT id::text FROM operation_approval_requests WHERE tenant_id=$1 AND id=$2 FOR UPDATE NOWAIT`, h.tenant, request["approval_request_id"].(string)).Scan(&id)
		})
		if err == nil {
			break
		}
		var busy *pgconn.PgError
		if !errors.As(err, &busy) || busy.Code != "55P03" {
			t.Fatal(err)
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if _, err := h.store.GetServiceDependentRotation(ctx, h.tenant, planID); !errors.Is(err, store.ErrServiceDependentRotationNotFound) {
		t.Fatal("projection gap did not leave parent absent", err)
	}
	approval, err := h.store.GetOperationApproval(ctx, h.tenant, request["approval_request_id"].(string))
	if err != nil || approval.Status != store.ApprovalStatusConsumed || approval.ConsumedEventID != planID {
		t.Fatal("durably appended first command lost its independent one-shot claim", err)
	}
	fences, err := h.store.ListApprovedTargetFences(ctx, h.tenant)
	matched := false
	for _, fence := range fences {
		if fence.TargetKind == "service_reconcile_rotation" && fence.EventID == planID && fence.RequestBinding == request["intent_digest"].(string) {
			matched = true
		}
	}
	if err != nil || !matched {
		t.Fatal("exact first reconciliation command has no independent recovery fence", err)
	}
	close(release)
	select {
	case err := <-holderDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPut, root+"/"+agentRowID(h.tenant, h.agent), token, "refuse-claimed-host-edit", map[string]any{"enabled": false}); status != http.StatusConflict {
		t.Fatalf("claimed native account allowed host membership edit: %d", status)
	}
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/rotations/approval", token, "cannot-replace-first-queue-consent", map[string]any{"intent": request["intent"], "intent_digest": request["intent_digest"], "reason": "A later reason must not replace the first queued command"})
	if status != http.StatusConflict {
		t.Fatalf("queued first consent was replaced after projection loss: %d %s", status, body)
	}
	status, body = secretsReq(t, h.servedHarness, http.MethodGet, root+"/rotations/reviews/"+planID+"?approval_request_id="+approval.ID, token, nil)
	var pending struct {
		QueuePending bool   `json:"queue_pending"`
		RotationID   string `json:"rotation_id"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &pending) != nil || !pending.QueuePending || pending.RotationID != "" {
		t.Fatalf("claimed command did not expose exact queue recovery without inventing a projected operation: %d %s", status, body)
	}
}

func TestServedReconciliationRecoversErasedClaimWithoutRevivingConsentA267(t *testing.T) {
	servedDependentRotationScenario(t, nil, false, dependentRotationOptions{Reconcile: true, LoseQueueProjection: true, EraseClaim: true})
}
func eraseAndRecoverDependentClaim(t *testing.T, h *roleHarness, planID string) {
	t.Helper()
	ctx := t.Context()
	const subject = "owned-rotation-operator"
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "owned-privacy-operator", "privacy:read", "privacy:write", "access:read", "secrets:read")
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/privacy/subject-erasures", admin, "erase-owned-claimed-command", map[string]string{"subject": subject, "reason": "owned claimed command recovery proof"})
	if status != http.StatusCreated || bytes.Contains(body, []byte(subject)) {
		t.Fatalf("claimed source erasure failed: status=%d", status)
	}
	assertEventLogOmitsRawSubject(t, ctx, h.log, h.tenant, subject)
	fences, err := h.store.ListApprovedTargetFences(ctx, h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, fence := range fences {
		if fence.EventID == planID {
			found = true
			if bytes.Contains(fence.Payload, []byte(subject)) {
				t.Fatal("independent command retained erased requester")
			}
			if err := api.ProjectServiceReconciliationFence(ctx, h.store, h.log, fence); err != nil {
				t.Fatal("erased first command did not recover", err)
			}
			if err := api.ProjectServiceReconciliationFence(ctx, h.store, h.log, fence); err != nil {
				t.Fatal("completed first-command recovery was not idempotent", err)
			}

		}
	}
	if !found {
		t.Fatal("erased first command lost its recovery fence")
	}
	parent, err := h.store.GetServiceDependentRotation(ctx, h.tenant, planID)
	if err != nil || parent.Actor != privacy.Placeholder(privacy.SubjectRef(h.tenant, subject)) || parent.DirectoryApplyStarted {
		t.Fatal("claim recovery lost privacy or invented native effects", err)
	}
	command, err := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, planID)
	if err != nil || command.Phase != store.SecretStaticRotationQueued {
		t.Fatal("claim recovery did not queue original command", err)
	}
	remaining, err := h.store.ListApprovedTargetFences(ctx, h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range remaining {
		if f.EventID == planID {
			t.Fatal("projected claim retained fence")
		}
	}
}
