// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/ownership"
)

// A87: POST /api/v1/owners/cmdb-schedule/run starts a CMDB sweep now instead
// of waiting for the interval. It is the same durable relay job the scheduler
// dispatches (one cmdb.sweep.dispatched event, one network-stamped outbox
// row), so it never stacks a second read behind an incomplete sweep, refuses
// a paused or unconfigured schedule by name, and starts a fresh sweep after a
// terminal page even when the interval has not elapsed.
func TestServedCMDBScheduleRunNowA87(t *testing.T) {
	// A network relay is enrolled so the sweep can be claimed and reported
	// the way production settles it: the job ledger, not a direct call.
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{"cmdb.sync"}, func(d *Deps) {
		d.ServiceNowBindings = []api.ServiceNowBinding{{InstanceURL: "https://cmdb.internal.example", TokenRef: servedCMDBSecretRef, RelayOnly: true}}
	})
	if _, err := h.client.Heartbeat(t.Context(), &transport.HeartbeatRequest{AgentID: h.agent, Version: "relay-test", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	tok := seedScopedToken(t, h.store, h.tenant, "owners:write", "owners:read")
	reader := seedScopedToken(t, h.store, h.tenant, "owners:read")
	run := func(token, key string) (int, []byte) {
		return secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/owners/cmdb-schedule/run", token, key, nil)
	}
	jobs := func() int {
		var n int
		if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(t.Context(), `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = 'cmdb.sync'`, h.tenant).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Nothing configured: there is no schedule to run.
	if status, body := run(tok, "a87-none"); status != http.StatusNotFound || !strings.Contains(string(body), "cmdb-schedule") {
		t.Fatalf("run-now without a schedule = %d %s, want 404 naming the schedule route", status, body)
	}
	// A paused schedule is not run behind the operator's back.
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/owners/cmdb-schedule", tok, "a87-paused", map[string]any{
		"instance_url": "https://cmdb.internal.example", "token_ref": servedCMDBSecretRef, "interval_seconds": 3600, "enabled": false, "execution": "relay",
	}); status != http.StatusOK {
		t.Fatalf("configure paused schedule: %d %s", status, body)
	}
	if status, body := run(tok, "a87-while-paused"); status != http.StatusConflict || !strings.Contains(string(body), "paused") {
		t.Fatalf("run-now on a paused schedule = %d %s, want 409 saying it is paused", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/owners/cmdb-schedule", tok, "a87-enabled", map[string]any{
		"instance_url": "https://cmdb.internal.example", "token_ref": servedCMDBSecretRef, "interval_seconds": 3600, "enabled": true, "execution": "relay",
	}); status != http.StatusOK {
		t.Fatalf("enable schedule: %d %s", status, body)
	}
	// Reading is not running.
	if status, _ := run(reader, "a87-reader"); status != http.StatusForbidden {
		t.Fatalf("run-now with owners:read = %d, want 403", status)
	}

	status, body := run(tok, "a87-run-1")
	if status != http.StatusAccepted {
		t.Fatalf("run-now = %d %s, want 202", status, body)
	}
	var started struct {
		SweepID  string `json:"sweep_id"`
		Started  bool   `json:"started"`
		Schedule struct {
			CoverageStatus string `json:"coverage_status"`
		} `json:"schedule"`
	}
	if err := json.Unmarshal(body, &started); err != nil {
		t.Fatal(err)
	}
	if !started.Started || started.SweepID == "" || started.Schedule.CoverageStatus != "in_progress" {
		t.Fatalf("run-now response = %s, want started with a sweep id and in_progress coverage", body)
	}
	if jobs() != 1 {
		t.Fatalf("run-now queued %d cmdb.sync jobs, want exactly one network-relay job", jobs())
	}
	// The same key replays; a new request while the sweep is incomplete does
	// not stack a second read, and says what is in flight.
	if status, again := run(tok, "a87-run-1"); status != http.StatusAccepted || string(again) != string(body) {
		t.Fatalf("replay = %d %s, want the identical 202", status, again)
	}
	if status, body := run(tok, "a87-run-2"); status != http.StatusConflict || !strings.Contains(string(body), started.SweepID) {
		t.Fatalf("run-now during an incomplete sweep = %d %s, want 409 naming the sweep in flight", status, body)
	}
	if jobs() != 1 {
		t.Fatalf("a refused run-now still queued: %d jobs", jobs())
	}
	// The scheduler's own tick sees the same in-flight sweep and stacks nothing.
	sched, _, err := h.store.GetCMDBReconcileSchedule(t.Context(), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	h.srv.dispatchCMDBSyncJob(t.Context(), h.tenant, sched)
	if jobs() != 1 {
		t.Fatalf("the scheduler stacked a job behind the run-now sweep: %d", jobs())
	}

	// The relay claims the job and reports a terminal page through the
	// signed job ledger; a run-now straight after starts a fresh sweep
	// although the interval has not elapsed. That is the point.
	claimed, err := h.client.ClaimJobs(t.Context(), &transport.ClaimJobsRequest{Kinds: []string{"cmdb.sync"}, Limit: 1, LeaseSeconds: 120})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("relay claim = %+v %v, want the one cmdb.sync job", claimed, err)
	}
	job := claimed.Jobs[0]
	var intent ownership.CMDBSyncIntent
	if err := json.Unmarshal(job.Payload, &intent); err != nil || intent.SweepID != started.SweepID {
		t.Fatalf("claimed intent = %+v %v, want the run-now sweep", intent, err)
	}
	// Claimed but unreported is still in flight.
	if status, body := run(tok, "a87-run-2b"); status != http.StatusConflict {
		t.Fatalf("run-now while the relay holds the job = %d %s, want 409", status, body)
	}
	terminal := mustJSON(t, CMDBSyncReport{
		SweepID: intent.SweepID, ObservedAt: time.Now().UTC(), SourceRefs: []string{"ci-1"}, ReadCount: 1, Complete: true,
		Records: []ownership.Record{{SourceRef: "ci-1", OwnerName: "payments", ApplicationID: "APP-CMDB"}},
	})
	if _, err := h.client.ReportJobResult(t.Context(), h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, terminal, "")); err != nil {
		t.Fatalf("report terminal page: %v", err)
	}
	status, body = run(tok, "a87-run-3")
	if status != http.StatusAccepted {
		t.Fatalf("run-now after a terminal page = %d %s, want 202", status, body)
	}
	var second struct {
		SweepID string `json:"sweep_id"`
	}
	_ = json.Unmarshal(body, &second)
	if second.SweepID == "" || second.SweepID == started.SweepID {
		t.Fatalf("second run-now sweep id = %q (first %q), want a fresh sweep", second.SweepID, started.SweepID)
	}
	// The run is on the record as the scheduler's would be.
	if !h.hasEvent(t, "cmdb.sweep.dispatched") {
		t.Fatal("run-now left no cmdb.sweep.dispatched event")
	}
}
