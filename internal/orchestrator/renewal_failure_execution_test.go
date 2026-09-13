// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestRenewalFailureRetainsExactExecutionAcrossSQLRecovery(t *testing.T) {
	s, log := newStore(t), openLog(t)
	ctx := t.Context()
	const identityID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	const runID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	const agentID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	seedLifecycleIdentity(t, s, tenantA, identityID, orchestrator.StateRenewing)
	seedLifecycleIdentity(t, s, tenantB, identityID, orchestrator.StateRenewing)
	outbox := orchestrator.NewOutbox(s)
	orch := orchestrator.NewOrchestrator(log, s, outbox)
	cert, err := s.UpsertCertificate(ctx, store.Certificate{TenantID: tenantA, Fingerprint: "retained-predecessor", Subject: "svc.example.test", Source: "issued"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	run := store.RotationRun{ID: runID, TenantID: tenantA, IdentityID: identityID, Status: "running", Trigger: "scheduled", PredecessorFingerprint: cert.Fingerprint, IdempotencyKey: "exact-renewal", CreatedAt: now, UpdatedAt: now}
	payload, _ := json.Marshal(map[string]string{"identity_id": identityID, "rotation_run_id": runID, "predecessor_certificate_id": cert.ID})
	var jobID int64
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := s.ApplyRotationRunRecordedTx(ctx, tx, run); err != nil {
			return err
		}
		var err error
		jobID, err = outbox.Enqueue(ctx, tx, orchestrator.Entry{TenantID: tenantA, Destination: "endpoint.renew", IdempotencyKey: "host-renew:renew:exact-renewal", Payload: payload, RequiredAgentRole: "host", RequiredAgentID: agentID})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	jobs, err := s.ClaimAgentJobs(ctx, tenantA, agentID, []string{"endpoint.renew"}, []string{"host"}, 1, time.Minute, now.Add(time.Second))
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim: jobs=%d err=%v", len(jobs), err)
	}
	attempt := store.RenewalAttempt{JobID: jobID, Attempt: jobs[0].ClaimAttempts}
	for _, tc := range []struct {
		name, tenant string
		attempt      store.RenewalAttempt
	}{
		{"other tenant", tenantB, attempt}, {"stale attempt", tenantA, store.RenewalAttempt{JobID: jobID, Attempt: attempt.Attempt + 1}},
		{"missing job", tenantA, store.RenewalAttempt{JobID: jobID + 100, Attempt: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := orch.FailRenewalAttempt(ctx, tc.tenant, identityID, "attempt failed", tc.attempt); err == nil {
				t.Fatal("unbound failure accepted")
			}
			mustStatus(t, s, tc.tenant, identityID, "renewing")
		})
	}
	for _, field := range []string{"identity_id", "rotation_run_id", "predecessor_certificate_id"} {
		t.Run("mismatched "+field, func(t *testing.T) {
			var changed map[string]string
			if err := json.Unmarshal(payload, &changed); err != nil {
				t.Fatal(err)
			}
			changed[field] = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
			changedBytes, _ := json.Marshal(changed)
			// This alteration is confined to the disposable test database; the command
			// receiver must reject inconsistent retained data before appending an alert.
			if _, err := s.SystemPool().Exec(ctx, `UPDATE outbox SET payload=$3 WHERE tenant_id=$1 AND id=$2`, tenantA, jobID, changedBytes); err != nil {
				t.Fatal(err)
			}
			if err := orch.FailRenewalAttempt(ctx, tenantA, identityID, "attempt failed", attempt); err == nil {
				t.Fatal("mismatched command accepted")
			}
			if _, err := s.SystemPool().Exec(ctx, `UPDATE outbox SET payload=$3 WHERE tenant_id=$1 AND id=$2`, tenantA, jobID, payload); err != nil {
				t.Fatal(err)
			}
			mustStatus(t, s, tenantA, identityID, "renewing")
		})
	}
	// Fail the SQL projection after the immutable event append in this disposable
	// database. Recovery must retain the first execution binding and owner snapshot.
	if _, err = s.SystemPool().Exec(ctx, `CREATE FUNCTION qa_reject_execution_alert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.destination='notification.renewal_failure' THEN RAISE EXCEPTION 'injected enqueue failure'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER qa_reject_execution_alert BEFORE INSERT ON outbox FOR EACH ROW EXECUTE FUNCTION qa_reject_execution_alert()`); err != nil {
		t.Fatal(err)
	}
	if err := orch.FailRenewalAttempt(ctx, tenantA, identityID, "attempt failed", attempt); err == nil {
		t.Fatal("failure committed without notification")
	}
	mustStatus(t, s, tenantA, identityID, "renewing")
	if _, err = s.SystemPool().Exec(ctx, `DROP TRIGGER qa_reject_execution_alert ON outbox; DROP FUNCTION qa_reject_execution_alert()`); err != nil {
		t.Fatal(err)
	}
	// Removing the binding through the legacy API is a different command, even
	// though its identity, transition, and reason are unchanged.
	if err := orch.Transition(ctx, tenantA, identityID, orchestrator.StateRenewalFailed, "attempt failed"); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("binding downgrade: %v", err)
	}
	// A later claim must not replace the historical failed attempt either.
	next, err := s.ClaimAgentJobs(ctx, tenantA, agentID, []string{"endpoint.renew"}, []string{"host"}, 1, time.Minute, now.Add(2*time.Minute))
	if err != nil || len(next) != 1 {
		t.Fatalf("reclaim: count=%d err=%v", len(next), err)
	}
	if err := orch.FailRenewalAttempt(ctx, tenantA, identityID, "attempt failed", store.RenewalAttempt{JobID: jobID, Attempt: next[0].ClaimAttempts}); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed attempt reused first event: %v", err)
	}
	// Recover from the retained event, without requiring an expired claim to be
	// currently held or re-observing mutable execution state.
	if count, err := orch.ReconcileOutbox(ctx, log); err != nil || count != 1 {
		t.Fatalf("recover: count=%d err=%v", count, err)
	}
	var body []byte
	if err := s.SystemPool().QueryRow(ctx, `SELECT payload FROM outbox WHERE tenant_id=$1 AND destination=$2`, tenantA, notify.DestinationRenewalFailure).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var alert notify.Alert
	if err := json.Unmarshal(body, &alert); err != nil {
		t.Fatal(err)
	}
	if alert.RotationRunID != runID || alert.RenewalJobID != jobID || alert.RenewalAttempt != attempt.Attempt || !strings.Contains(alert.Detail, "/operations?run="+runID) {
		t.Fatalf("wrong retained execution: %+v", alert)
	}
	current, err := s.RotationRunHostJob(ctx, tenantA, run)
	if err != nil || current == nil || current.ID != jobID || current.Attempt != next[0].ClaimAttempts {
		t.Fatalf("current job: %+v err=%v", current, err)
	}
	if _, err := s.RotationRunHostJob(ctx, tenantB, run); err == nil {
		t.Fatal("cross-tenant run accepted")
	}
	handler := api.New(s, nil, orch, api.WithInsecureHeaderResolver())
	for _, tenant := range []string{tenantA, tenantB, ""} {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/lifecycle/rotation-runs/"+runID, nil)
		request.Header.Set("X-Tenant-ID", tenant)
		request.Header.Set("X-Roles", "admin")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if tenant == tenantA {
			if response.Code != http.StatusOK {
				t.Fatalf("run detail: %d %s", response.Code, response.Body.String())
			}
			var got struct {
				HostJob struct {
					ID       int64 `json:"id"`
					Attempts int   `json:"attempts"`
				} `json:"host_job"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.HostJob.ID != jobID || got.HostJob.Attempts != next[0].ClaimAttempts {
				t.Fatalf("run did not expose current exact child: %+v", got)
			}
			if strings.Contains(response.Body.String(), "predecessor_certificate_id") || strings.Contains(response.Body.String(), "payload") {
				t.Fatal("run detail exposed raw command payload")
			}
		} else if response.Code == http.StatusOK || strings.Contains(response.Body.String(), "retained-predecessor") {
			t.Fatalf("run detail crossed tenant/auth boundary: %d %s", response.Code, response.Body.String())
		}
	}
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type != projections.EventIdentityRenewalFailed {
			return nil
		}
		data, changed, err := events.PseudonymizeEventDataForSubject(event.Data, tenantA, "svc.example.test", event.Type, event.SchemaVersion)
		if err != nil || !changed {
			return fmt.Errorf("privacy: changed=%v err=%v", changed, err)
		}
		var retained struct {
			SideEffect struct {
				Payload []byte `json:"payload"`
			} `json:"side_effect"`
		}
		if err = json.Unmarshal(data, &retained); err != nil {
			return err
		}
		var rewritten notify.Alert
		if err = json.Unmarshal(retained.SideEffect.Payload, &rewritten); err != nil {
			return err
		}
		if rewritten.RotationRunID != runID || rewritten.RenewalJobID != jobID || rewritten.RenewalAttempt != attempt.Attempt {
			return errors.New("privacy rewrite changed execution")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
