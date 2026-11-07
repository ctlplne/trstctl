// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

func TestServedDependentInverseRecoveryPreservesUncertainHistoryA267(t *testing.T) {
	servedDependentRotationScenario(t, nil, true, dependentRotationOptions{RecoverInverse: true})
}
func TestServedDependentInverseRecoveryExpiresLeaseAndRetainsLateReceiptA267(t *testing.T) {
	servedDependentRotationScenario(t, nil, true, dependentRotationOptions{RecoverInverse: true, ExpiredInverse: true})
}
func requestDependentInverseRecovery(t *testing.T, h *roleHarness, token string, step servicedependents.RotationStep) {
	t.Helper()
	parent, err := h.store.GetServiceDependentRotation(t.Context(), h.tenant, step.RotationID)
	if err != nil || parent.Direction != servicedependents.Inverse || !parent.DirectoryRestored {
		t.Fatal("recovery fixture lacks exact restored-directory authority", err)
	}
	original, err := h.store.GetServiceDependentStep(t.Context(), h.tenant, step.RotationID, step.ID)
	if err != nil || (original.Status != "uncertain" && original.Status != "queued") || (original.Status == "uncertain" && original.Report == nil) {
		t.Fatal("original uncertainty was not durably observed", err)
	}
	status, progress := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/discovery/dependent-rotations/"+step.RotationID, token, nil)
	var available struct {
		StepID string `json:"recovery_step_id"`
	}
	if status != http.StatusOK || json.Unmarshal(progress, &available) != nil || available.StepID != step.ID {
		t.Fatalf("progress omitted exact recovery effect: %d %s", status, progress)
	}
	root := "/api/v1/access/discovery/dependent-rotations/" + step.RotationID + "/recoveries"
	status, raw := secretsReq(t, h.servedHarness, http.MethodGet, root+"/preview?step_id="+step.ID, token, nil)
	var preview struct {
		Digest   string                         `json:"recovery_digest"`
		Previous servicedependents.RotationStep `json:"previous_step"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &preview) != nil || preview.Digest == "" || preview.Previous.ID != step.ID {
		t.Fatalf("exact inverse recovery review unavailable: %d %s", status, raw)
	}
	input := map[string]any{"step_id": step.ID, "intent_digest": parent.IntentDigest, "recovery_digest": preview.Digest, "reason": "Recover exact inverse work after observing the terminal task", "acknowledge_original_outcome": true}
	// Write permission and tenant isolation apply to both the full review and queue.
	reader := seedScopedToken(t, h.store, h.tenant, "access:read", "secrets:read")
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		path := root
		if method == http.MethodGet {
			path += "/preview?step_id=" + step.ID
		}
		if code, _ := secretsReqKey(t, h.servedHarness, method, path, reader, "refuse-recovery-readonly-"+method, input); code != http.StatusForbidden {
			t.Fatalf("readonly recovery authority: %s %d", method, code)
		}
	}
	other := uuid.NewString()
	registerServedTenantID(t, h.servedHarness, other, "Owned recovery tenant")
	foreign := seedScopedToken(t, h.store, other, "access:targets.write", "secrets:write")
	if code, _ := secretsReq(t, h.servedHarness, http.MethodGet, root+"/preview?step_id="+step.ID, foreign, nil); code != http.StatusNotFound {
		t.Fatalf("foreign recovery review: %d", code)
	}
	for _, change := range []string{"ack", "digest", "step"} {
		invalid := make(map[string]any, len(input))
		for k, v := range input {
			invalid[k] = v
		}
		switch change {
		case "ack":
			invalid["acknowledge_original_outcome"] = false
		case "digest":
			invalid["recovery_digest"] = strings.Repeat("0", 64)
		case "step":
			invalid["step_id"] = strings.Repeat("0", 32)
		}
		if code, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, root, token, "refuse-recovery-"+change, invalid); code != http.StatusConflict && code != http.StatusUnprocessableEntity {
			t.Fatalf("invalid recovery %s: %d", change, code)
		}
	}
	interruptDependentRecoveryProjection(t, h, root, token, step, input)
	status, raw = secretsReqKey(t, h.servedHarness, http.MethodPost, root, token, "owned-inverse-recovery", input)
	var queued struct {
		Step servicedependents.RotationStep `json:"step"`
	}
	if status != http.StatusAccepted || json.Unmarshal(raw, &queued) != nil || queued.Step.ID == step.ID || queued.Step.Recovery == nil || queued.Step.Recovery.PreviousStepID != step.ID {
		t.Fatalf("fresh explicit inverse recovery unavailable: %d %s", status, raw)
	}
	status, retry := secretsReqKey(t, h.servedHarness, http.MethodPost, root, token, "owned-inverse-recovery", input)
	var same struct {
		Step servicedependents.RotationStep `json:"step"`
	}
	if status != http.StatusAccepted || json.Unmarshal(retry, &same) != nil || same.Step.ID != queued.Step.ID {
		t.Fatal("lost recovery response created another native execution")
	}
	retained, err := h.store.GetServiceDependentStep(t.Context(), h.tenant, step.RotationID, step.ID)
	if err != nil || retained.Status != original.Status || projections.ServiceDependentReportDigest(retained.Report) != projections.ServiceDependentReportDigest(original.Report) {
		t.Fatal("replacement rewrote original uncertainty", err)
	}

	changed := make(map[string]any, len(input))
	for k, v := range input {
		changed[k] = v
	}
	changed["reason"] = "A different reason cannot replace the first recovery"
	if code, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, root, token, "changed-recovery-reason", changed); code != http.StatusConflict {
		t.Fatalf("first recovery reason replaced: %d", code)
	}
	// Canonical replacement still supersedes the old grant when every mutable
	// status and link is rewritten. Restore only these owned test rows afterwards.
	// A changed actor cannot take over the same retained first command either.
	outsider := seedScopedTokenSubject(t, h.store, h.tenant, "owned-other-recovery-operator", "access:targets.write", "secrets:write")
	if code, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, root, outsider, "changed-recovery-actor", input); code != http.StatusConflict {
		t.Fatalf("first recovery actor replaced: %d", code)
	}
	if original.OutboxID == nil {
		t.Fatal("original recovery step lacks host job")
	}
	var job store.AgentJob
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT id,tenant_id::text,idempotency_key,payload FROM outbox WHERE tenant_id=$1 AND id=$2`, h.tenant, *original.OutboxID).Scan(&job.ID, &job.TenantID, &job.IdempotencyKey, &job.Payload)
	}); err != nil {
		t.Fatal(err)
	}
	agent := &agentService{store: h.store, log: h.log}
	if _, err := agent.boundServiceDependentStep(t.Context(), h.tenant, step.Ref.AgentID, job.IdempotencyKey, job.Payload); err == nil {
		t.Fatal("superseded grant survived immutable replacement")
	}
	nextRow, err := h.store.GetServiceDependentStep(t.Context(), h.tenant, step.RotationID, queued.Step.ID)
	if err != nil {
		t.Fatal(err)
	}
	var replacementJob store.AgentJob
	if nextRow.OutboxID == nil {
		t.Fatal("replacement lacks bounded host job")
	}
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT id,tenant_id::text,idempotency_key,payload FROM outbox WHERE tenant_id=$1 AND id=$2`, h.tenant, *nextRow.OutboxID).Scan(&replacementJob.ID, &replacementJob.TenantID, &replacementJob.IdempotencyKey, &replacementJob.Payload)
	}); err != nil {
		t.Fatal(err)
	}
	altered := queued.Step
	altered.Challenge = uuid.NewString()
	alteredRaw, err := json.Marshal(altered)
	if err != nil {
		t.Fatal(err)
	}
	originalRaw, err := json.Marshal(queued.Step)
	if err != nil {
		t.Fatal(err)
	}
	setIntent := func(raw []byte) {
		t.Helper()
		if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(t.Context(), `UPDATE service_account_rotation_steps SET intent=$4::jsonb WHERE tenant_id=$1 AND rotation_id=$2 AND step_id=$3`, h.tenant, step.RotationID, queued.Step.ID, raw)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	setIntent(alteredRaw)
	if _, err := agent.projectServiceDependentRotationClaim(t.Context(), replacementJob, step.Ref.AgentID); err == nil {
		t.Fatal("changed projected recovery challenge acquired host authority")
	}
	setIntent(originalRaw)
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `DELETE FROM service_account_rotation_steps WHERE tenant_id=$1 AND rotation_id=$2 AND step_id=$3`, h.tenant, step.RotationID, queued.Step.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.boundServiceDependentStep(t.Context(), h.tenant, step.Ref.AgentID, job.IdempotencyKey, job.Payload); err == nil {
		t.Fatal("deleted SQL lineage revived old native grant")
	}
	if err := h.srv.api.AdvanceStaticSecretRotation(t.Context(), h.tenant, parent.CommandID, 1); err == nil {
		t.Fatal("missing projected recovery head authorized coordinator progress")
	}
	source, found, err := h.log.EventByID(t.Context(), servicedependents.StepSourceID(step.RotationID, queued.Step.ID))
	if err != nil || !found {
		t.Fatal("missing exact recovery source", err)
	}
	if err := projections.New(h.store).Apply(t.Context(), source); err != nil {
		t.Fatal("recovery source did not repair absent own projection", err)
	}
	repaired, err := h.store.GetServiceDependentStep(t.Context(), h.tenant, step.RotationID, queued.Step.ID)
	if err != nil || repaired.Status != "queued" || repaired.OutboxID == nil || nextRow.OutboxID == nil || *repaired.OutboxID != *nextRow.OutboxID {
		t.Fatal("recovery repair changed original job", err)
	}
}

func waitForExpiredDependentLease(t *testing.T, step servicedependents.RotationStep) {
	t.Helper()
	wait := time.Until(step.Deadline.Add(time.Minute).Add(25 * time.Millisecond))
	if wait < 0 || wait > 181*time.Second {
		t.Fatalf("unexpected native lease bound: %s", wait)
	}
	t.Logf("waiting %s for the actual immutable native lease and receipt grace", wait)
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
}
func assertLateDependentReceipt(t *testing.T, h *roleHarness, jobID int64, attempt int, report servicedependents.StepReport) {
	t.Helper()
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	result, err := h.client.ReportJobResult(t.Context(), h.report(t, jobID, attempt, transport.JobOutcomeExecuted, string(raw), crypto.SHA256Hex(raw)))
	if err != nil || result.Accepted || !result.ReceiptRecorded {
		t.Fatal("late predecessor report was not retained without current application", err, result)
	}
	if _, found, err := h.log.EventByID(t.Context(), servicedependents.StepObservedSourceID(report.RotationID, report.StepID)); err != nil || found {
		t.Fatal("late predecessor rewrote current step evidence", err)
	}
}

// A real row lock holds only this owned sealed child's projection transaction.
// Cancel after JetStream append; the retry must project the original command.
func interruptDependentRecoveryProjection(t *testing.T, h *roleHarness, root, token string, step servicedependents.RotationStep, input map[string]any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	held, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			var id string
			if err := tx.QueryRow(ctx, `SELECT id::text FROM secret_static_rotation_commands WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, h.tenant, step.RotationID).Scan(&id); err != nil {
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
	case err := <-done:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	requestCtx, cancelRequest := context.WithCancel(ctx)
	defer cancelRequest()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, h.ts.URL+root, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "owned-recovery-append-gap")
	returned := make(chan int, 1)
	go func() {
		res, err := h.ts.Client().Do(req)
		code := 0
		if err == nil {
			code = res.StatusCode
			_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
			_ = res.Body.Close()
		}
		returned <- code
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		_, found, err := h.log.EventByID(ctx, servicedependents.RecoverySourceID(step.RotationID, step.ID))
		if err != nil {
			t.Fatal(err)
		}
		if found {
			break
		}
		select {
		case code := <-returned:
			t.Fatalf("recovery returned before held SQL projection: %d", code)
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	cancelRequest()
	select {
	case code := <-returned:
		if code == http.StatusAccepted {
			t.Fatal("unprojected recovery reported queued")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// The canonical head takes effect even before its SQL row exists.
	if _, err := h.store.GetServiceDependentStep(ctx, h.tenant, step.RotationID, servicedependents.RecoveryStepID(step.RotationID, step.ID)); err != store.ErrServiceDependentStepNotFound {
		t.Fatal("projection gap did not leave recovery absent", err)
	}
	canonical, err := projections.ResolveServiceDependentStepHead(ctx, h.log, h.tenant, step.RotationID, step.ID)
	if err != nil || canonical.ID == step.ID {
		t.Fatal("appended recovery did not fence original native authority", err)
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
