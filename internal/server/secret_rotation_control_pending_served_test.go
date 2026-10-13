// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestServedSecretRotationDueClaimRefusesUnprojectedPauseOrRetire(t *testing.T) {
	for _, tc := range []struct {
		action    string
		eventType string
	}{
		{"pause", projections.EventSecretRotationSchedulePaused},
		{"retire", projections.EventSecretRotationScheduleRetired},
	} {
		t.Run(tc.action, func(t *testing.T) {
			h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
			registerServedTenant(t, h, "served unprojected secret rotation "+tc.action+" tenant")
			runner := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
			const scheduleID = "dae27b65-5eda-4ca9-a655-fd6153570301"
			if _, err := h.srv.orch.UpsertSecretRotationSchedule(t.Context(), h.tenant, store.SecretRotationSchedule{
				ID: scheduleID, Name: "pause-before-claim", Provider: "historical-static",
				Key: "rotation/pause-before-claim", OldRef: "static-v1", IntervalSeconds: 3600,
				Enabled: true, NextRunAt: time.Now().UTC().Add(-time.Minute),
			}); err != nil {
				t.Fatal(err)
			}
			current, err := h.store.GetSecretRotationSchedule(t.Context(), h.tenant, scheduleID)
			if err != nil {
				t.Fatal(err)
			}
			at := time.Now().UTC().Truncate(time.Microsecond)
			var retiredAt *time.Time
			if tc.action == "retire" {
				retiredAt = &at
			}
			payload, err := json.Marshal(projections.SecretRotationScheduleControlledV2{
				ID: scheduleID, Action: tc.action, ReasonCode: "operator_request", Binding: tc.action + "-before-claim-crash",
				Applied: true, Result: projections.SecretRotationScheduleControlResult{
					ID: scheduleID, TenantID: h.tenant, Name: current.Name, Provider: current.Provider,
					Key: current.Key, OldRef: current.OldRef, IntervalSeconds: current.IntervalSeconds,
					Enabled: false, NextRunAt: current.NextRunAt, RetiredAt: retiredAt,
					CreatedAt: current.CreatedAt, UpdatedAt: at,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.log.Append(t.Context(), events.Event{
				ID: uuid.NewString(), Type: tc.eventType,
				TenantID: h.tenant, SchemaVersion: 2, Time: at, Data: payload,
			}); err != nil {
				t.Fatal(err)
			}
			status, body := secretsReqKey(t, h, http.MethodPost,
				"/api/v1/secrets/rotation-schedules/run-due", runner, "pause-before-claim-tick", nil)
			if status != http.StatusServiceUnavailable {
				t.Fatalf("run due after unprojected durable %s did not fail closed: status=%d body=%s", tc.action, status, body)
			}
			var due secretRotationDueRunValue
			if err := json.Unmarshal(body, &due); err != nil {
				t.Fatal(err)
			}
			var commands int
			if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
				return tx.QueryRow(t.Context(), `SELECT count(*) FROM secret_rotation_schedule_commands
			WHERE tenant_id = $1 AND schedule_id = $2::uuid`, h.tenant, scheduleID).Scan(&commands)
			}); err != nil {
				t.Fatal(err)
			}
			if due.Ran != 0 || commands != 0 {
				t.Fatalf("unprojected %s admitted new due work: receipt=%+v commands=%d", tc.action, due, commands)
			}
			if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
				t.Fatalf("cold rebuild pending %s: %v", tc.action, err)
			}
			status, body = secretsReqKey(t, h, http.MethodPost,
				"/api/v1/secrets/rotation-schedules/run-due", runner, "pause-before-claim-after-replay", nil)
			if status != http.StatusOK {
				t.Fatalf("new tick after %s replay: status=%d body=%s", tc.action, status, body)
			}
			if err := json.Unmarshal(body, &due); err != nil || due.Ran != 0 {
				t.Fatalf("%s replay started due work: receipt=%+v err=%v", tc.action, due, err)
			}
		})
	}
}
