// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// An operator must be able to stop future scheduled work without erasing the
// schedule or its run history. This is the served regression for the observed
// console/CLI stop-path failure.
func TestServedDiscoveryScheduleCanPauseResumeAndRetire(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", tok,
		"lifecycle-source", map[string]any{
			"name": "lifecycle-source", "kind": "manual", "config": map[string]any{
				"findings": []any{map[string]any{"kind": "x509_certificate", "ref": "qa-public-cert"}},
			},
		})
	if status != http.StatusCreated {
		t.Fatalf("create source: status %d body %s", status, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/schedules", tok,
		"lifecycle-schedule", map[string]any{
			"source_id": source.ID, "name": "lifecycle-schedule", "interval_seconds": 300, "enabled": true,
		})
	if status != http.StatusCreated {
		t.Fatalf("create schedule: status %d body %s", status, body)
	}
	var schedule struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &schedule); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/discovery/schedules/" + schedule.ID
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/schedules/not-a-uuid", tok, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("malformed schedule read: status %d body %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/schedules/not-a-uuid/pause", tok, "lifecycle-invalid-id", nil)
	if status != http.StatusBadRequest {
		t.Fatalf("malformed schedule control: status %d body %s", status, body)
	}
	readOnly := seedScopedToken(t, h.store, h.tenant, "discovery:read")
	status, body = secretsReqKey(t, h, http.MethodPost, path+"/pause", readOnly, "lifecycle-readonly-pause", nil)
	if status != http.StatusForbidden {
		t.Fatalf("read-only token changed schedule: status %d body %s", status, body)
	}
	const otherTenant = "22222222-2222-4222-8222-222222222222"
	registerServedTenantID(t, h, otherTenant, "discovery lifecycle isolation tenant")
	otherToken := seedScopedToken(t, h.store, otherTenant, "discovery:read", "discovery:write")
	status, body = secretsReq(t, h, http.MethodGet, path, otherToken, nil)
	if status != http.StatusNotFound {
		t.Fatalf("other tenant read schedule: status %d body %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, path+"/pause", otherToken, "lifecycle-cross-tenant-pause", nil)
	if status != http.StatusNotFound {
		t.Fatalf("other tenant paused schedule: status %d body %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, path+"/pause", tok, "lifecycle-pause", nil)
	if status != http.StatusOK {
		t.Fatalf("pause enabled schedule: status %d body %s, want 200", status, body)
	}
	var paused struct {
		Enabled   bool    `json:"enabled"`
		RetiredAt *string `json:"retired_at"`
	}
	if err := json.Unmarshal(body, &paused); err != nil || paused.Enabled || paused.RetiredAt != nil {
		t.Fatalf("paused schedule: %+v err=%v body=%s", paused, err, body)
	}
	cut, err := h.log.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var attributedPause bool
	if err := h.log.ReplayTenantTypesThrough(t.Context(), h.tenant, 1, cut.LastSequence,
		[]string{projections.EventDiscoverySchedulePaused}, func(event events.Event) error {
			if event.Actor != nil && event.Actor.Subject == "secrets-test" {
				attributedPause = true
			}
			return nil
		}); err != nil || !attributedPause {
		t.Fatalf("retained pause lacks authenticated audit actor: observed=%v err=%v", attributedPause, err)
	}
	pausedBody := append([]byte(nil), body...)
	before, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, path+"/pause", tok, "lifecycle-pause", nil)
	if status != http.StatusOK || !bytes.Equal(body, pausedBody) {
		t.Fatalf("lost pause response recovery: status %d body %s, want %s", status, body, pausedBody)
	}
	if after, err := h.log.LastSequence(t.Context()); err != nil || after != before {
		t.Fatalf("same-key pause retry appended event: before=%d after=%d err=%v", before, after, err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, path+"/pause", tok, "lifecycle-pause-noop", nil)
	if status != http.StatusOK || !bytes.Equal(body, pausedBody) {
		t.Fatalf("fresh-key pause no-op: status %d body %s, want %s", status, body, pausedBody)
	}
	if after, err := h.log.LastSequence(t.Context()); err != nil || after != before+1 {
		t.Fatalf("fresh-key pause no-op receipt event: before=%d after=%d err=%v", before, after, err)
	}
	before++
	if _, err := h.srv.orch.UpsertDiscoverySchedule(t.Context(), h.tenant, store.DiscoverySchedule{
		ID: schedule.ID, SourceID: source.ID, Name: "lifecycle-schedule", IntervalSeconds: 300, Enabled: true,
	}); !errors.Is(err, orchestrator.ErrDiscoveryScheduleInactive) {
		t.Fatalf("configuration update bypassed retained pause: %v", err)
	}
	if after, err := h.log.LastSequence(t.Context()); err != nil || after != before {
		t.Fatalf("refused configuration bypass appended event: before=%d after=%d err=%v", before, after, err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, path+"/resume", tok, "lifecycle-resume", nil)
	if status != http.StatusOK {
		t.Fatalf("resume paused schedule: status %d body %s, want 200", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, path+"/retire", tok, "lifecycle-retire", nil)
	if status != http.StatusOK {
		t.Fatalf("retire schedule: status %d body %s, want 200", status, body)
	}
	var retired struct {
		Enabled   bool    `json:"enabled"`
		RetiredAt *string `json:"retired_at"`
	}
	if err := json.Unmarshal(body, &retired); err != nil || retired.Enabled || retired.RetiredAt == nil {
		t.Fatalf("retired schedule: %+v err=%v body=%s", retired, err, body)
	}
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("cold rebuild retirement: %v", err)
	}
	status, body = secretsReq(t, h, http.MethodGet, path, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("read cold retired schedule: status %d body %s", status, body)
	}
	if err := json.Unmarshal(body, &retired); err != nil || retired.Enabled || retired.RetiredAt == nil {
		t.Fatalf("cold retired schedule: %+v err=%v body=%s", retired, err, body)
	}
	if count, err := h.store.WriteReadModelSnapshots(t.Context()); err != nil || count < 1 {
		t.Fatalf("snapshot retired schedule: count=%d err=%v", count, err)
	}
	if err := h.store.RestoreReadModelTx(t.Context(), func(tx pgx.Tx) error {
		_, err := h.store.RestoreSnapshotsTx(t.Context(), tx)
		return err
	}); err != nil {
		t.Fatalf("restore retired schedule snapshot: %v", err)
	}
	status, body = secretsReq(t, h, http.MethodGet, path, tok, nil)
	if status != http.StatusOK || json.Unmarshal(body, &retired) != nil || retired.Enabled || retired.RetiredAt == nil {
		t.Fatalf("snapshot-restored retired schedule: status=%d state=%+v body=%s", status, retired, body)
	}
	if n, err := h.srv.RunDiscoverySchedulerOnce(t.Context()); err != nil || n != 0 {
		t.Fatalf("retired schedule queued after rebuild: n=%d err=%v", n, err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, path+"/resume", tok, "lifecycle-resume-retired", nil)
	if status != http.StatusConflict {
		t.Fatalf("resume retired schedule: status %d body %s, want 409", status, body)
	}
	if _, err := h.store.GetDiscoverySchedule(t.Context(), "22222222-2222-4222-8222-222222222222", schedule.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("cross-tenant schedule read = %v, want no row", err)
	}
}

// A durable HTTP claim can remain bound after the event and projection commit.
// Retrying that exact key must return its first response, even if another key
// subsequently changed the schedule. The result cache is deliberately removed
// here to reproduce the receiver-commit / outer-result crash boundary.
func TestServedDiscoveryScheduleBoundRetryAfterOppositeControlReturnsOriginalReceipt(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")
	_, scheduleID := createLifecycleSchedule(t, h, tok, "bound-retry")
	path := "/api/v1/discovery/schedules/" + scheduleID

	status, original := secretsReqKey(t, h, http.MethodPost, path+"/pause", tok, "bound-retry-pause", nil)
	if status != http.StatusOK {
		t.Fatalf("first pause: status=%d body=%s", status, original)
	}
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(t.Context(), `UPDATE idempotency_keys
		   SET status = 'bound', result = NULL, completed_at = NULL
		 WHERE tenant_id = $1 AND key = $2`, h.tenant, "bound-retry-pause")
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("pause response-cache crash fixture did not find the claim")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	status, resumed := secretsReqKey(t, h, http.MethodPost, path+"/resume", tok, "bound-retry-resume", nil)
	if status != http.StatusOK || !bytes.Contains(resumed, []byte(`"enabled":true`)) {
		t.Fatalf("opposite resume: status=%d body=%s", status, resumed)
	}
	status, changed := secretsReqKey(t, h, http.MethodPost, path+"/resume", tok, "bound-retry-pause", nil)
	if status != http.StatusConflict {
		t.Fatalf("bound pause key reused for resume = (%d, %s), want 409", status, changed)
	}
	before, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	status, replay := secretsReqKey(t, h, http.MethodPost, path+"/pause", tok, "bound-retry-pause", nil)
	if status != http.StatusOK || !bytes.Equal(replay, original) {
		t.Fatalf("bound pause retry after opposite control = (%d, %s), want original (200, %s)", status, replay, original)
	}
	if after, err := h.log.LastSequence(t.Context()); err != nil || after != before {
		t.Fatalf("bound pause retry appended a second event: before=%d after=%d err=%v", before, after, err)
	}
	status, current := secretsReq(t, h, http.MethodGet, path, tok, nil)
	if status != http.StatusOK || !bytes.Contains(current, []byte(`"enabled":true`)) {
		t.Fatalf("bound pause retry changed the later state: status=%d body=%s", status, current)
	}
	// A command that was a no-op also needs its own immutable receipt. Without
	// it, a retry after an opposite control would become a new effect.
	status, noop := secretsReqKey(t, h, http.MethodPost, path+"/resume", tok, "bound-retry-noop", nil)
	if status != http.StatusOK || !bytes.Contains(noop, []byte(`"enabled":true`)) {
		t.Fatalf("first resume no-op: status=%d body=%s", status, noop)
	}
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `UPDATE idempotency_keys
		   SET status = 'bound', result = NULL, completed_at = NULL
		 WHERE tenant_id = $1 AND key = $2`, h.tenant, "bound-retry-noop")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	status, laterPause := secretsReqKey(t, h, http.MethodPost, path+"/pause", tok, "bound-retry-later-pause", nil)
	if status != http.StatusOK || !bytes.Contains(laterPause, []byte(`"enabled":false`)) {
		t.Fatalf("later pause: status=%d body=%s", status, laterPause)
	}
	before, err = h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	status, replay = secretsReqKey(t, h, http.MethodPost, path+"/resume", tok, "bound-retry-noop", nil)
	if status != http.StatusOK || !bytes.Equal(replay, noop) {
		t.Fatalf("bound no-op retry = (%d, %s), want original (200, %s)", status, replay, noop)
	}
	if after, err := h.log.LastSequence(t.Context()); err != nil || after != before {
		t.Fatalf("bound no-op retry appended another event: before=%d after=%d err=%v", before, after, err)
	}
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("cold rebuild after bound retries: %v", err)
	}
	status, current = secretsReq(t, h, http.MethodGet, path, tok, nil)
	if status != http.StatusOK || !bytes.Contains(current, []byte(`"enabled":false`)) {
		t.Fatalf("cold replay reversed later pause: status=%d body=%s", status, current)
	}
	if count, err := h.store.WriteReadModelSnapshots(t.Context()); err != nil || count < 1 {
		t.Fatalf("snapshot bound retry state: count=%d err=%v", count, err)
	}
	if err := h.store.RestoreReadModelTx(t.Context(), func(tx pgx.Tx) error {
		_, err := h.store.RestoreSnapshotsTx(t.Context(), tx)
		return err
	}); err != nil {
		t.Fatalf("restore bound retry snapshot: %v", err)
	}
	status, current = secretsReq(t, h, http.MethodGet, path, tok, nil)
	if status != http.StatusOK || !bytes.Contains(current, []byte(`"enabled":false`)) {
		t.Fatalf("snapshot restore reversed later pause: status=%d body=%s", status, current)
	}
}

func TestServedDiscoverySchedulePauseClosesStaleDueDecision(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")
	sourceID, scheduleID := createLifecycleSchedule(t, h, tok, "stale-due")
	due, err := h.store.DiscoverySchedulesDue(t.Context(), h.tenant, time.Now(), 10)
	if err != nil || len(due) != 1 || due[0].ID != scheduleID {
		t.Fatalf("pre-pause due list = %+v err=%v", due, err)
	}
	path := "/api/v1/discovery/schedules/" + scheduleID
	status, body := secretsReqKey(t, h, http.MethodPost, path+"/pause", tok, "stale-due-pause", nil)
	if status != http.StatusOK {
		t.Fatalf("pause: status %d body %s", status, body)
	}
	before, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.srv.orch.QueueDiscoveryRun(t.Context(), h.tenant, store.DiscoveryRun{
		SourceID: sourceID, ScheduleID: &scheduleID, OnlyIfDue: true,
	})
	if !errors.Is(err, orchestrator.ErrDiscoveryScheduleInactive) {
		t.Fatalf("stale due-list queued after pause: %v", err)
	}
	if after, err := h.log.LastSequence(t.Context()); err != nil || after != before {
		t.Fatalf("stale due-list appended run: before=%d after=%d err=%v", before, after, err)
	}
	if n, err := h.srv.RunDiscoverySchedulerOnce(t.Context()); err != nil || n != 0 {
		t.Fatalf("scheduler after pause queued=%d err=%v", n, err)
	}
}

func TestServedDiscoveryScheduleRetainedPauseBlocksQueueUntilCatchUp(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")
	sourceID, scheduleID := createLifecycleSchedule(t, h, tok, "lost-pause")
	_, err := h.store.SystemPool().Exec(t.Context(), `CREATE FUNCTION discovery_lifecycle_projection_fail() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.tenant_id='11111111-1111-1111-1111-111111111111'::uuid THEN RAISE EXCEPTION 'owned pause projection rollback'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER discovery_lifecycle_projection_fail BEFORE UPDATE ON discovery_schedules FOR EACH ROW EXECUTE FUNCTION discovery_lifecycle_projection_fail()`)
	if err != nil {
		t.Fatal(err)
	}
	drop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := h.store.SystemPool().Exec(ctx, `DROP TRIGGER IF EXISTS discovery_lifecycle_projection_fail ON discovery_schedules;
			DROP FUNCTION IF EXISTS discovery_lifecycle_projection_fail()`); err != nil {
			t.Errorf("drop owned trigger: %v", err)
		}
	}
	t.Cleanup(drop)
	before, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.ControlDiscoverySchedule(t.Context(), h.tenant, scheduleID, "pause", "lost-pause-recovery", "lost-pause-recovery-binding"); err == nil {
		t.Fatal("owned SQL fault did not interrupt pause projection")
	}
	retained, err := h.log.LastSequence(t.Context())
	if err != nil || retained != before+1 {
		t.Fatalf("pause event head=%d err=%v want=%d", retained, err, before+1)
	}
	if row, err := h.store.GetDiscoverySchedule(t.Context(), h.tenant, scheduleID); err != nil || !row.Enabled {
		t.Fatalf("expected stale SQL enabled row: %+v err=%v", row, err)
	}
	_, err = h.srv.orch.QueueDiscoveryRun(t.Context(), h.tenant, store.DiscoveryRun{
		SourceID: sourceID, ScheduleID: &scheduleID, OnlyIfDue: true,
	})
	if !errors.Is(err, store.ErrResourceAdmissionBusy) {
		t.Fatalf("unprojected pause allowed run admission: %v", err)
	}
	if after, err := h.log.LastSequence(t.Context()); err != nil || after != retained {
		t.Fatalf("refused run changed event head: after=%d err=%v", after, err)
	}
	drop()
	recovered, err := h.srv.orch.ControlDiscoverySchedule(t.Context(), h.tenant, scheduleID,
		"pause", "lost-pause-recovery", "lost-pause-recovery-binding")
	if err != nil || recovered.Enabled {
		t.Fatalf("same-key retry after append-before-SQL fault: schedule=%+v err=%v", recovered, err)
	}
	if after, err := h.log.LastSequence(t.Context()); err != nil || after != retained {
		t.Fatalf("append-before-SQL retry made a second event: before=%d after=%d err=%v", retained, after, err)
	}
	if err := h.srv.proj.ProjectCatchUp(t.Context(), h.log); err != nil {
		t.Fatalf("catch up retained pause: %v", err)
	}
	if row, err := h.store.GetDiscoverySchedule(t.Context(), h.tenant, scheduleID); err != nil || row.Enabled {
		t.Fatalf("retained pause did not project: %+v err=%v", row, err)
	}
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("cold rebuild retained pause: %v", err)
	}
	if row, err := h.store.GetDiscoverySchedule(t.Context(), h.tenant, scheduleID); err != nil || row.Enabled {
		t.Fatalf("cold rebuilt pause changed: %+v err=%v", row, err)
	}
}

func createLifecycleSchedule(t *testing.T, h *servedHarness, tok, name string) (sourceID, scheduleID string) {
	t.Helper()
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", tok,
		name+"-source", map[string]any{
			"name": name + "-source", "kind": "manual", "config": map[string]any{
				"findings": []any{map[string]any{"kind": "x509_certificate", "ref": "qa-public-cert"}},
			},
		})
	if status != http.StatusCreated {
		t.Fatalf("create source: status %d body %s", status, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/schedules", tok,
		name+"-schedule", map[string]any{
			"source_id": source.ID, "name": name + "-schedule", "interval_seconds": 300, "enabled": true,
		})
	if status != http.StatusCreated {
		t.Fatalf("create schedule: status %d body %s", status, body)
	}
	var schedule struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &schedule); err != nil {
		t.Fatal(err)
	}
	return source.ID, schedule.ID
}
