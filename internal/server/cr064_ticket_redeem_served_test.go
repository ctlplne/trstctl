// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/credref"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/ticketintake"
)

func TestCR064TicketRelayStopsAfterConfigurerLosesSecretRead(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "ticket-admin", "access:write", "certs:write", "secrets:read", "secrets:write")
	leaver := seedScopedTokenSubject(t, h.store, h.tenant, "ticket-leaver", "certs:write", "secrets:read", "secrets:write")
	call := func(tok, method, path, key string, body any, want int) {
		t.Helper()
		status, raw := secretsReqKey(t, h, method, path, tok, key, body)
		if status != want {
			t.Fatalf("%s %s: HTTP %d %s, want %d", method, path, status, raw, want)
		}
	}
	call(admin, http.MethodPost, "/api/v1/secrets/projects", "cr064-ticket-project", map[string]any{
		"slug": "ticketvault", "environments": []any{map[string]any{"slug": "prod", "restricted": true}},
	}, http.StatusCreated)
	call(admin, http.MethodPut, "/api/v1/secrets/projects/ticketvault/members/ticket-leaver", "cr064-ticket-member",
		map[string]any{"role": "developer", "environments": []string{"prod"}}, http.StatusOK)
	call(admin, http.MethodPut, "/api/v1/secrets/projects/ticketvault/members/ticket-admin", "cr064-ticket-admin-member",
		map[string]any{"role": "admin", "environments": []string{"prod"}}, http.StatusOK)
	call(leaver, http.MethodPost, "/api/v1/secrets/store", "cr064-ticket-secret", map[string]any{
		"name": "ticketvault/prod/token", "value": "ticket-canary-v1",
	}, http.StatusCreated)
	call(leaver, http.MethodPut, "/api/v1/issuance-requests/intake-schedule", "cr064-ticket-schedule", map[string]any{
		"system": "servicenow", "instance_url": "https://tickets.example.test", "token_ref": "secret://ticketvault/prod/token",
		"sn_table": "change_request", "subject_field": "u_subject", "profile_field": "u_profile",
		"interval_seconds": 3600, "enabled": true,
	}, http.StatusOK)
	schedule, found, err := h.store.GetTicketIntakeSchedule(t.Context(), h.tenant, ticketintake.SystemServiceNow)
	if err != nil || !found {
		t.Fatalf("configured ticket schedule: found=%t err=%v", found, err)
	}
	payload, err := json.Marshal(ticketSyncIntent(schedule))
	if err != nil {
		t.Fatal(err)
	}
	relay := relayCredentialResolver{store: h.store, kek: h.kek, tenantCrypto: h.srv.tenantCrypto}
	redeem := func() error {
		t.Helper()
		material, err := relay.resolveJobCredential(t.Context(), h.tenant, store.AgentJobForRedemption{
			Destination: "ticket.sync", Payload: payload,
		})
		if err == nil {
			material.wipe()
		}
		return err
	}
	if err := redeem(); err != nil {
		t.Fatalf("authorized ticket schedule could not redeem: %v", err)
	}
	statusJob, err := json.Marshal(map[string]any{"schedule": schedule.Name, "status_id": uuid.NewString(),
		"instance_url": schedule.InstanceURL, "token_ref": schedule.TokenRef,
		"sn_table": schedule.SNTable, "source_refs": []string{"abc"}, "config_revision": schedule.ConfigRevision})
	if err != nil {
		t.Fatal(err)
	}
	noteJob, err := json.Marshal(map[string]any{"schedule": schedule.Name, "note_id": uuid.NewString(),
		"instance_url": schedule.InstanceURL, "token_ref": schedule.TokenRef,
		"sn_table": schedule.SNTable, "source_ref": "abc", "text": "fixture note", "config_revision": schedule.ConfigRevision})
	if err != nil {
		t.Fatal(err)
	}
	redeemOther := func(kind string, payload []byte) error {
		t.Helper()
		material, err := relay.resolveJobCredential(t.Context(), h.tenant, store.AgentJobForRedemption{
			Destination: kind, Payload: payload,
		})
		if err == nil {
			material.wipe()
		}
		return err
	}
	for _, job := range []struct {
		kind string
		body []byte
	}{{"ticket.status", statusJob}, {"ticket.note", noteJob}} {
		if err := redeemOther(job.kind, job.body); err != nil {
			t.Fatalf("authorized %s could not redeem: %v", job.kind, err)
		}
	}
	call(admin, http.MethodDelete, "/api/v1/secrets/projects/ticketvault/members/ticket-leaver",
		"cr064-ticket-remove", nil, http.StatusOK)
	call(admin, http.MethodPut, "/api/v1/secrets/store/ticketvault/prod/token", "cr064-ticket-rotate",
		map[string]any{"value": "ticket-canary-v2"}, http.StatusOK)
	if err := redeem(); !errors.Is(err, credref.ErrReadAuthorityRevoked) {
		t.Fatalf("ticket relay redeemed a rotated secret after configurer lost read: %v", err)
	}
	for _, job := range []struct {
		kind string
		body []byte
	}{{"ticket.status", statusJob}, {"ticket.note", noteJob}} {
		if err := redeemOther(job.kind, job.body); !errors.Is(err, credref.ErrReadAuthorityRevoked) {
			t.Fatalf("%s redeemed a rotated secret after configurer lost read: %v", job.kind, err)
		}
	}
	call(admin, http.MethodPut, "/api/v1/issuance-requests/intake-schedule", "cr064-ticket-reauthorize", map[string]any{
		"system": "servicenow", "instance_url": "https://tickets.example.test", "token_ref": "secret://ticketvault/prod/token",
		"sn_table": "change_request", "subject_field": "u_subject", "profile_field": "u_profile",
		"interval_seconds": 3600, "enabled": true,
	}, http.StatusOK)
	if err := redeem(); !errors.Is(err, credref.ErrReadAuthorityRevoked) {
		t.Fatalf("old ticket job borrowed the new configurer's authority: %v", err)
	}
	for _, job := range []struct {
		kind string
		body []byte
	}{{"ticket.status", statusJob}, {"ticket.note", noteJob}} {
		if err := redeemOther(job.kind, job.body); !errors.Is(err, credref.ErrReadAuthorityRevoked) {
			t.Fatalf("old %s borrowed the new configurer's authority: %v", job.kind, err)
		}
	}
	newSchedule, found, err := h.store.GetTicketIntakeSchedule(t.Context(), h.tenant, ticketintake.SystemServiceNow)
	if err != nil || !found || newSchedule.ConfigRevision == schedule.ConfigRevision {
		t.Fatalf("reauthorized ticket schedule has no new revision: found=%t err=%v", found, err)
	}
	payload, err = json.Marshal(ticketSyncIntent(newSchedule))
	if err != nil {
		t.Fatal(err)
	}
	if err := redeem(); err != nil {
		t.Fatalf("new configurer's schedule could not redeem: %v", err)
	}
	withRevision := func(raw []byte) []byte {
		t.Helper()
		var values map[string]any
		if err := json.Unmarshal(raw, &values); err != nil {
			t.Fatal(err)
		}
		values["config_revision"] = newSchedule.ConfigRevision
		updated, err := json.Marshal(values)
		if err != nil {
			t.Fatal(err)
		}
		return updated
	}
	statusJob, noteJob = withRevision(statusJob), withRevision(noteJob)
	for _, job := range []struct {
		kind string
		body []byte
	}{{"ticket.status", statusJob}, {"ticket.note", noteJob}} {
		if err := redeemOther(job.kind, job.body); err != nil {
			t.Fatalf("new configurer's %s could not redeem: %v", job.kind, err)
		}
	}
	var changed ticketintake.SyncIntent
	if err := json.Unmarshal(payload, &changed); err != nil {
		t.Fatal(err)
	}
	changed.InstanceURL = "https://another.example.test"
	payload, err = json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if err := redeem(); !errors.Is(err, credref.ErrReadAuthorityRevoked) {
		t.Fatalf("ticket job changed destination under an authorized revision: %v", err)
	}
	payload, err = json.Marshal(ticketSyncIntent(newSchedule))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `UPDATE ticket_intake_schedules SET configured_by='', config_revision=''
			WHERE tenant_id=$1 AND system=$2 AND name=$3`, h.tenant, newSchedule.System, newSchedule.Name)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := redeem(); !errors.Is(err, credref.ErrReadAuthorityRevoked) {
		t.Fatalf("historical unattributed ticket schedule redeemed a secret: %v", err)
	}
	for _, job := range []struct {
		kind string
		body []byte
	}{{"ticket.status", statusJob}, {"ticket.note", noteJob}} {
		if err := redeemOther(job.kind, job.body); !errors.Is(err, credref.ErrReadAuthorityRevoked) {
			t.Fatalf("historical unattributed %s redeemed a secret: %v", job.kind, err)
		}
	}
}

func TestCR064TicketReauthorizationResumesAnIncompleteSweep(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	first := seedScopedTokenSubject(t, h.store, h.tenant, "ticket-first", "certs:write", "secrets:read", "secrets:write")
	second := seedScopedTokenSubject(t, h.store, h.tenant, "ticket-second", "certs:write", "secrets:read")
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", first, "cr064-recovery-secret",
		map[string]any{"name": "ticket/recovery-token", "value": "fixture-token"})
	if status != http.StatusCreated {
		t.Fatalf("seed ticket credential: HTTP %d %s", status, raw)
	}
	configBody := map[string]any{
		"system": "servicenow", "instance_url": "https://tickets.example.test", "token_ref": "secret://ticket/recovery-token",
		"sn_table": "incident", "subject_field": "u_subject", "profile_field": "u_profile",
		"interval_seconds": 3600, "enabled": true,
	}
	configure := func(token, key string) int {
		t.Helper()
		status, _ := secretsReqKey(t, h, http.MethodPut, "/api/v1/issuance-requests/intake-schedule", token, key, configBody)
		return status
	}
	if status := configure(first, "cr064-recovery-first"); status != http.StatusOK {
		t.Fatalf("first ticket configuration: HTTP %d", status)
	}
	before, found, err := h.store.GetTicketIntakeSchedule(t.Context(), h.tenant, ticketintake.SystemServiceNow)
	if err != nil || !found {
		t.Fatalf("first schedule: found=%t err=%v", found, err)
	}
	h.srv.dispatchTicketSyncJob(t.Context(), h.tenant, before)
	held, found, err := h.store.GetTicketIntakeSchedule(t.Context(), h.tenant, ticketintake.SystemServiceNow)
	if err != nil || !found || held.CurrentSweepID == "" {
		t.Fatalf("incomplete sweep was not queued: found=%t err=%v", found, err)
	}
	if status := configure(second, "cr064-recovery-second"); status != http.StatusOK {
		t.Fatalf("authorized reconfiguration could not recover incomplete sweep: HTTP %d", status)
	}
	current, found, err := h.store.GetTicketIntakeSchedule(t.Context(), h.tenant, ticketintake.SystemServiceNow)
	if err != nil || !found || current.CurrentSweepID != held.CurrentSweepID ||
		current.ConfigRevision == held.ConfigRevision || current.ConfiguredBy != "ticket-second" {
		t.Fatalf("reauthorization lost cursor or actor: found=%t err=%v", found, err)
	}
	pending, err := h.store.HasPendingTicketSyncJob(t.Context(), h.tenant, current.System, current.Name)
	if err != nil || pending {
		t.Fatalf("old revision still blocks a new sweep page: pending=%t err=%v", pending, err)
	}
	relay := relayCredentialResolver{store: h.store, kek: h.kek, tenantCrypto: h.srv.tenantCrypto}
	for _, candidate := range []struct {
		schedule store.TicketIntakeSchedule
		allowed  bool
	}{{held, false}, {current, true}} {
		payload, err := json.Marshal(ticketSyncIntent(candidate.schedule))
		if err != nil {
			t.Fatal(err)
		}
		material, err := relay.resolveJobCredential(t.Context(), h.tenant, store.AgentJobForRedemption{
			Destination: "ticket.sync", Payload: payload,
		})
		if err == nil {
			material.wipe()
		}
		if candidate.allowed && err != nil || !candidate.allowed && !errors.Is(err, credref.ErrReadAuthorityRevoked) {
			t.Fatalf("revision %s: allowed=%t err=%v", candidate.schedule.ConfigRevision, candidate.allowed, err)
		}
	}
	h.srv.dispatchTicketSyncJob(t.Context(), h.tenant, current)
	var newJobs int
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT count(*) FROM outbox
			WHERE tenant_id=$1 AND destination='ticket.sync'
			AND convert_from(payload,'UTF8')::jsonb->>'config_revision'=$2`,
			h.tenant, current.ConfigRevision).Scan(&newJobs)
	}); err != nil || newJobs != 1 {
		t.Fatalf("reauthorized sweep did not queue a new revision: jobs=%d err=%v", newJobs, err)
	}
}
