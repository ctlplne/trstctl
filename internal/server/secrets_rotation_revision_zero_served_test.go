// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secretsync"
)

func TestServedScheduledRotationDefersUnanchoredConfigurationWithoutChildEffect(t *testing.T) {
	connector := newRotationCapturePusher()
	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.SecretSyncTargets = map[string]*secretsync.Target{
				"ci": secretsync.NewCITarget(connector),
			}
		},
	)
	registerServedTenant(t, h, "served unanchored rotation configuration tenant")
	runner := seedScopedTokenSubject(t, h.store, h.tenant,
		"schedule-unanchored-runner", "secrets:read", "secrets:write")
	const (
		scheduleID = "15500000-0000-4000-8000-000000000159"
		secretName = "rotation/unanchored-configuration"
		tickKey    = "run-due-unanchored-configuration"
	)
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", runner,
		map[string]any{"name": secretName, "value": "unanchored-v1"})
	if status != http.StatusCreated {
		t.Fatalf("seed unanchored source: status=%d body=%s", status, body)
	}
	connector.put(secretName, []byte("unanchored-v1"))

	ctx := context.Background()
	dueAt := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	createdAt := dueAt.Add(-time.Hour)
	// This is the exact N-1 row shape after migration 0155 adds the revision
	// column: PostgreSQL can retain the schedule, but cannot invent the event
	// sequence that authored it. The served scheduler must surface that fact.
	if err := h.store.WithTenantProjection(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO secret_rotation_schedules
			        (id, tenant_id, name, provider, secret_key, old_ref,
			         interval_seconds, config_event_sequence, enabled, next_run_at,
			         created_at, updated_at)
			 VALUES ($1, $2, 'unanchored-configuration', 'connector:ci', $3,
			         'version:1', 3600, 0, true, $4, $5, $5)`,
			scheduleID, h.tenant, secretName, dueAt, createdAt)
		return err
	}); err != nil {
		t.Fatalf("seed unanchored schedule projection: %v", err)
	}

	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/secrets/rotation-schedules/run-due", runner, tickKey, nil)
	if status != http.StatusOK {
		t.Fatalf("run unanchored schedule: status=%d body=%s", status, body)
	}
	var receipt secretRotationDueRunValue
	if err := json.Unmarshal(body, &receipt); err != nil || receipt.Ran != 0 || receipt.Scanned != 1 ||
		len(receipt.Runs) != 0 || len(receipt.Deferred) != 1 || !receipt.Complete ||
		receipt.RunLimitReached || receipt.ScanLimitReached || receipt.Partial {
		t.Fatalf("unanchored scheduler receipt=%+v err=%v", receipt, err)
	}
	deferred := receipt.Deferred[0]
	if deferred.ScheduleID != scheduleID || deferred.Reason != "config_revision_unanchored" ||
		!deferred.DueAt.Equal(dueAt) || deferred.Error == "" {
		t.Fatalf("unanchored deferral=%+v, want exact due edge and diagnostic", deferred)
	}

	var commandCount, syncJobCount int
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM secret_rotation_schedule_commands
			  WHERE tenant_id = $1 AND schedule_id = $2`,
			h.tenant, scheduleID).Scan(&commandCount); err != nil {
			return err
		}
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM secret_sync_jobs
			  WHERE tenant_id = $1 AND secret_name = $2`,
			h.tenant, secretName).Scan(&syncJobCount)
	}); err != nil {
		t.Fatalf("load unanchored child/effect rows: %v", err)
	}
	if commandCount != 0 || syncJobCount != 0 || connector.successfulPushes(secretName) != 0 {
		t.Fatalf("unanchored schedule created command/effect: commands=%d sync_jobs=%d pushes=%d",
			commandCount, syncJobCount, connector.successfulPushes(secretName))
	}
	schedule, err := h.store.GetSecretRotationSchedule(ctx, h.tenant, scheduleID)
	if err != nil || schedule.LastRunID != nil || schedule.LastRunStatus != "" ||
		schedule.OldRef != "version:1" || !schedule.NextRunAt.Equal(dueAt) {
		t.Fatalf("unanchored schedule cadence changed: schedule=%+v err=%v", schedule, err)
	}
	secret, err := h.store.GetSecret(ctx, h.tenant, secretName)
	if err != nil || secret.Version != 1 || connector.value(secretName) != "unanchored-v1" {
		t.Fatalf("unanchored schedule changed source/target: secret=%+v target=%q err=%v",
			secret, connector.value(secretName), err)
	}
	terminalEvents := 0
	if err := h.log.Replay(ctx, 1, func(event events.Event) error {
		if event.Type != projections.EventSecretRotationScheduleRan {
			return nil
		}
		var payload projections.SecretRotationScheduleRan
		if err := json.Unmarshal(event.Data, &payload); err != nil {
			return err
		}
		if payload.ScheduleID == scheduleID {
			terminalEvents++
		}
		return nil
	}); err != nil {
		t.Fatalf("replay unanchored scheduler evidence: %v", err)
	}
	if terminalEvents != 0 {
		t.Fatalf("unanchored schedule emitted %d terminal events, want zero", terminalEvents)
	}
}
