// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/app"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/outboxgc"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Real served mTLS reports, real PostgreSQL and NATS exercise the receiver.
// The separate Vault/NGINX walk supplies listener deployment proof; a signed
// test report alone makes no claim about a real listener.
func TestHostRotationResultRecordsTheReportedOutcome(t *testing.T) {
	for _, outcome := range []string{transport.JobOutcomeVerified, transport.JobOutcomeExecuted, transport.JobOutcomeVerifyFailed, transport.JobOutcomeFailed} {
		t.Run(outcome, func(t *testing.T) {
			f := newHostRotationResultFixture(t)
			req := f.report(t, outcome)
			before := eventCount(t, f.h.log, f.h.tenant, projections.EventLifecycleRotationRecorded)
			result, err := f.h.client.ReportJobResult(t.Context(), req)
			if err != nil || !result.Accepted {
				t.Fatalf("served report: %+v %v", result, err)
			}
			run := f.run(t)
			if outcome == transport.JobOutcomeFailed {
				if run.Status != "running" || run.CompletedAt != nil || run.SuccessorFingerprint != "" {
					t.Fatalf("released failure falsely completed the run: %+v", run)
				}
				jobs, err := f.h.client.ClaimJobs(t.Context(), &transport.ClaimJobsRequest{Kinds: []string{agentJobKindEndpointRenew}, Limit: 1})
				if err != nil || len(jobs.Jobs) != 0 {
					t.Fatalf("failed attempt did not enter backoff: %+v %v", jobs, err)
				}
				var retryAt time.Time
				if err := f.h.store.WithTenant(t.Context(), f.h.tenant, func(tx pgx.Tx) error {
					return tx.QueryRow(t.Context(), `SELECT agent_next_attempt_at FROM outbox WHERE tenant_id=$1 AND id=$2`, f.h.tenant, f.job.JobID).Scan(&retryAt)
				}); err != nil {
					t.Fatal(err)
				}
				if wait := time.Until(retryAt); wait < 0 || wait > 5*time.Second {
					t.Fatalf("unexpected first failure retry deadline: %s", wait)
				}
				timer := time.NewTimer(time.Until(retryAt) + 10*time.Millisecond)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-t.Context().Done():
					t.Fatal(t.Context().Err())
				}
				jobs, err = f.h.client.ClaimJobs(t.Context(), &transport.ClaimJobsRequest{Kinds: []string{agentJobKindEndpointRenew}, Limit: 1})
				if err != nil || len(jobs.Jobs) != 1 || jobs.Jobs[0].Attempt != f.job.Attempt+1 {
					t.Fatalf("released attempt was not retryable: %+v %v", jobs, err)
				}
				f.job = jobs.Jobs[0]
				f.fingerprint = signHostRotationFixtureJob(t, f.h, f.job)
				result, err := f.h.client.ReportJobResult(t.Context(), f.report(t, transport.JobOutcomeVerified))
				if err != nil || !result.Accepted {
					t.Fatalf("reclaimed report: %+v %v", result, err)
				}
				if run := f.run(t); run.Status != "succeeded" || run.SuccessorFingerprint != f.fingerprint {
					t.Fatalf("reclaimed generation did not finish: %+v", run)
				}
				return
			}
			want := "succeeded"
			if outcome != transport.JobOutcomeVerified {
				want = "failed"
			}
			if run.Status != want || run.CompletedAt == nil || run.SuccessorFingerprint != f.fingerprint || !strings.Contains(run.RollbackRef, f.predecessor) {
				t.Fatalf("terminal run=%+v, want %s with exact successor/predecessor", run, want)
			}
			// Replaying/recovering cannot append another immutable outcome.
			if err := f.receiver().recordHostRotationResult(t.Context(), f.h.tenant, f.job.JobID); err != nil {
				t.Fatal(err)
			}
			if got := eventCount(t, f.h.log, f.h.tenant, projections.EventLifecycleRotationRecorded); got != before+1 {
				t.Fatalf("terminal events=%d, want one", got-before)
			}
			jobs, err := f.h.client.ClaimJobs(t.Context(), &transport.ClaimJobsRequest{Kinds: []string{agentJobKindEndpointRenew}, Limit: 1})
			if err != nil || len(jobs.Jobs) != 0 {
				t.Fatalf("retired work was offered again: %+v %v", jobs, err)
			}
		})
	}
}

func TestHostRotationRecoversAfterRetirementBeforeProjection(t *testing.T) {
	f := newHostRotationResultFixture(t, events.WithDuplicateWindowForTesting(100*time.Millisecond))
	// A real database failure after event append interrupts the terminal run
	// projection. Exact claim retirement must already have committed.
	stop := rejectHostRotationUpdate(t, f.h.store, "lifecycle_rotation_runs", "NEW.status = 'succeeded'")
	result, err := f.h.client.ReportJobResult(t.Context(), f.report(t, transport.JobOutcomeVerified))
	if err == nil {
		t.Fatalf("injected projection failure was hidden: %+v", result)
	}
	job, err := f.h.store.GetHostRotationJob(t.Context(), f.h.tenant, f.job.JobID)
	if err != nil || job.Status != "delivered" || job.CompletedAt == nil {
		t.Fatalf("claim was not retired before result projection: %+v %v", job, err)
	}
	if run := f.run(t); run.Status != "running" || run.CompletedAt != nil {
		t.Fatalf("failed projection falsely finished run: %+v", run)
	}
	// Even an aggressively short retention cannot erase the recovery binding.
	swept, err := outboxgc.New(f.h.store, time.Nanosecond).Sweep(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.store.GetHostRotationJob(t.Context(), f.h.tenant, f.job.JobID); err != nil {
		t.Fatalf("GC erased pending rotation recovery (swept %d): %v", swept, err)
	}
	time.Sleep(150 * time.Millisecond) // Cross the real broker duplicate window without changing the host clock.
	terminalEvents := eventCount(t, f.h.log, f.h.tenant, projections.EventLifecycleRotationRecorded)
	stop()
	if err := f.h.srv.reconcileHostRotationResults(t.Context(), &hostRotationRecoveryCursor{}); err != nil {
		t.Fatal(err)
	}
	run := f.run(t)
	if run.Status != "succeeded" || run.CompletedAt == nil || !run.CompletedAt.Equal(*job.CompletedAt) || run.SuccessorFingerprint != f.fingerprint {
		t.Fatalf("recovered run=%+v", run)
	}
	if got := eventCount(t, f.h.log, f.h.tenant, projections.EventLifecycleRotationRecorded); got != terminalEvents {
		t.Fatalf("recovery appended another retained terminal event: %d -> %d", terminalEvents, got)
	}
	// A second sweep is an exact replay, and no CSR/deploy work is recreated.
	if err := f.h.srv.reconcileHostRotationResults(t.Context(), &hostRotationRecoveryCursor{}); err != nil {
		t.Fatal(err)
	}
	jobs, err := f.h.client.ClaimJobs(t.Context(), &transport.ClaimJobsRequest{Kinds: []string{agentJobKindEndpointRenew}, Limit: 1})
	if err != nil || len(jobs.Jobs) != 0 {
		t.Fatalf("recovery recreated work: %+v %v", jobs, err)
	}
}

func TestHostRotationDoesNotCompleteWhenClaimRetirementFails(t *testing.T) {
	f := newHostRotationResultFixture(t)
	stop := rejectHostRotationUpdate(t, f.h.store, "outbox", fmt.Sprintf("NEW.id = %d AND NEW.status = 'delivered'", f.job.JobID))
	req := f.report(t, transport.JobOutcomeVerified)
	if result, err := f.h.client.ReportJobResult(t.Context(), req); err == nil {
		t.Fatalf("injected retirement failure hidden: %+v", result)
	}
	if run := f.run(t); run.Status != "running" || run.CompletedAt != nil {
		t.Fatalf("unretired claim completed its run: %+v", run)
	}
	stop()
	// The same signed report may now retire the exact attempt and finish once.
	result, err := f.h.client.ReportJobResult(t.Context(), req)
	if err != nil || !result.Accepted {
		t.Fatalf("report retry failed: %+v %v", result, err)
	}
	if run := f.run(t); run.Status != "succeeded" || run.SuccessorFingerprint != f.fingerprint {
		t.Fatalf("retry run=%+v", run)
	}
}

func TestHostRotationRejectsUnrelatedTenantAndRetirementGeneration(t *testing.T) {
	f := newHostRotationResultFixture(t)
	if err := f.receiver().recordHostRotationResult(t.Context(), "22222222-2222-4222-8222-222222222222", f.job.JobID); err == nil {
		t.Fatal("cross-tenant job result was read")
	}
	id := f.h.identity.Identity()
	ok, err := f.h.store.FailAgentJobTerminally(t.Context(), f.h.tenant, agentRowID(f.h.tenant, id.CommonName()), f.job.JobID, f.job.Attempt+1, "wrong generation", time.Now())
	if err != nil || ok {
		t.Fatalf("wrong attempt retired current claim: %v %v", ok, err)
	}
	if run := f.run(t); run.Status != "running" {
		t.Fatalf("wrong generation changed run: %+v", run)
	}
}

func TestHostRotationReceiptLookupResumesAcrossBoundedPasses(t *testing.T) {
	f := newHostRotationResultFixture(t)
	// Real retained traffic between run creation and the signed host report.
	// A report has a fixed read budget even when unrelated tenants are busy.
	for i := 0; i < hostRotationLookupPage*3; i++ {
		if _, err := f.h.log.Append(t.Context(), events.Event{TenantID: f.h.tenant,
			Type: "test.host.rotation.padding", Data: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	response, err := f.h.client.ReportJobResult(t.Context(), f.report(t, transport.JobOutcomeVerified))
	if err != nil || !response.Accepted {
		t.Fatalf("durable report: %+v %v", response, err)
	}
	if f.run(t).Status != "running" {
		t.Fatal("bounded lookup falsely claimed completion")
	}
	lookup, err := f.h.store.HostRotationLookup(t.Context(), f.h.tenant, f.job.JobID, f.job.Attempt)
	if err != nil {
		t.Fatal(err)
	}
	firstSequence := f.run(t).FirstEventSequence
	if firstSequence > math.MaxInt64-hostRotationLookupPage {
		t.Fatal("fixture sequence and one lookup page exceed the database cursor range")
		return
	}
	if lookup.Next < 0 {
		t.Fatal("lookup returned a negative cursor")
		return
	}
	if uint64(lookup.Next) != firstSequence+hostRotationLookupPage {
		t.Fatalf("first page cursor: %+v", lookup)
	}
	for pass := 0; pass < 5 && f.run(t).Status == "running"; pass++ {
		// Recreate the receiver to prove progress lives in PostgreSQL, not memory.
		err := f.receiver().recordHostRotationResult(t.Context(), f.h.tenant, f.job.JobID)
		if err != nil && !errors.Is(err, errHostRotationLookupPending) {
			t.Fatal(err)
		}
		next, err := f.h.store.HostRotationLookup(t.Context(), f.h.tenant, f.job.JobID, f.job.Attempt)
		if err != nil {
			t.Fatal(err)
		}
		if next.Next <= lookup.Next || next.Next-lookup.Next > hostRotationLookupPage {
			t.Fatalf("unbounded or stalled cursor: %+v -> %+v", lookup, next)
		}
		lookup = next
	}
	if f.run(t).Status != "succeeded" {
		t.Fatal("persisted lookup did not converge")
	}
	// A stale generation's offsets are disposable; exact retained events recover
	// the same result and no duplicate terminal event is appended.
	before := eventCount(t, f.h.log, f.h.tenant, projections.EventLifecycleRotationRecorded)
	lookup.Generation = "retired-generation"
	lookup.Next = 1 << 62
	if err := f.h.store.SaveHostRotationLookup(t.Context(), f.h.tenant, f.job.JobID, f.job.Attempt, lookup); err != nil {
		t.Fatal(err)
	}
	for pass := 0; pass < 5; pass++ {
		err := f.receiver().recordHostRotationResult(t.Context(), f.h.tenant, f.job.JobID)
		if err == nil {
			break
		}
		if !errors.Is(err, errHostRotationLookupPending) || pass == 4 {
			t.Fatal(err)
		}
	}
	if got := eventCount(t, f.h.log, f.h.tenant, projections.EventLifecycleRotationRecorded); got != before {
		t.Fatalf("stale index republished result: %d -> %d", before, got)
	}
}

func TestHostRotationRecoveryContinuesPastFailedEarlierJob(t *testing.T) {
	f := newHostRotationResultFixture(t)
	stop := rejectHostRotationUpdate(t, f.h.store, "lifecycle_rotation_runs", "NEW.status = 'succeeded'")
	if _, err := f.h.client.ReportJobResult(t.Context(), f.report(t, transport.JobOutcomeVerified)); err == nil {
		t.Fatal("injected failure hidden")
	}
	stop()
	// A separate registered tenant sorts before the real receiver tenant. Its
	// terminal job deliberately lacks the required immutable custody receipt.
	const earlier = "00000000-0000-4000-8000-000000000001"
	registration := app.New(f.h.log, f.h.store, nil)
	t.Cleanup(registration.Close)
	if err := registration.RegisterTenant(t.Context(), earlier, "earlier-incomplete-host", "earlier-registration"); err != nil {
		t.Fatal(err)
	}
	// Missing run binding authority is injected as a broken read model, rather
	// than manufacturing a signed host observation that never happened.
	if err := f.h.store.WithTenant(t.Context(), earlier, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `INSERT INTO lifecycle_rotation_runs
		 (tenant_id,id,identity_id,status,trigger,reason,idempotency_key,predecessor_fingerprint,created_at,updated_at)
		 VALUES($1,'44444444-4444-4444-8444-444444444444','55555555-5555-4555-8555-555555555555','running','scheduler','controlled missing authority','earlier-broken','missing',now(),now())`, earlier)
		if err != nil {
			return err
		}
		_, err = tx.Exec(t.Context(), `INSERT INTO outbox (tenant_id,destination,idempotency_key,payload,status,claim_attempts,claim_completed_at)
		 VALUES($1,'endpoint.renew','host-renew:renew:earlier-broken',$2,'delivered',1,now())`, earlier, []byte(`{"rotation_run_id":"44444444-4444-4444-8444-444444444444","identity_id":"55555555-5555-4555-8555-555555555555"}`))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var cursor hostRotationRecoveryCursor
	if err := f.h.srv.reconcileHostRotationResults(t.Context(), &cursor); err == nil {
		t.Fatal("missing authority was not reported")
	}
	if run := f.run(t); run.Status != "succeeded" {
		t.Fatalf("earlier broken tenant starved valid result: %+v", run)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	start := time.Now()
	f.h.srv.RunHostRotationRecovery(cancelled)
	if time.Since(start) > time.Second {
		t.Fatal("cancelled recovery worker did not stop promptly")
	}
}

type hostRotationResultFixture struct {
	h                               *roleHarness
	job                             transport.ClaimedJob
	fingerprint, predecessor, runID string
}

func newHostRotationResultFixture(t *testing.T, eventOptions ...events.OpenOption) *hostRotationResultFixture {
	t.Helper()
	return newHostRotationResultFixtureWithVerify(t, "rotation.example.test:443", eventOptions...)
}

func newHostRotationResultFixtureWithVerify(t *testing.T, verifyAddress string, eventOptions ...events.OpenOption) *hostRotationResultFixture {
	t.Helper()
	ctx := t.Context()
	h := newRoleHarnessWithEventOptions(t, []string{mtls.AgentRoleHost}, []string{agentJobKindEndpointRenew}, eventOptions)
	registration := app.New(h.log, h.store, nil)
	t.Cleanup(registration.Close)
	if err := registration.RegisterTenant(ctx, h.tenant, "host-rotation-fixture", "host-rotation-registration"); err != nil {
		t.Fatal(err)
	}
	seedRenewalJob(t, ctx, h, "host-rotation-initial", []string{"rotation.example.test"})
	first := claimOneRenewal(t, ctx, h)
	predecessor := signHostRotationFixtureJob(t, h, first)
	f := &hostRotationResultFixture{h: h, job: first, fingerprint: predecessor}
	result, err := h.client.ReportJobResult(ctx, f.report(t, transport.JobOutcomeVerified))
	if err != nil || !result.Accepted {
		t.Fatalf("first host receipt: %+v %v", result, err)
	}
	cert, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, predecessor)
	if err != nil {
		t.Fatal(err)
	}
	var intent RelayDeployIntent
	if err := json.Unmarshal(first.Payload, &intent); err != nil {
		t.Fatal(err)
	}
	f.runID = "33333333-3333-4333-8333-333333333333"
	run := rotationRunEvidence{ID: f.runID, IdentityID: intent.IdentityID, Trigger: "scheduler", Reason: "served host receiver regression", IdempotencyKey: "canary-renewal", PredecessorFingerprint: predecessor}
	dispatcher := &issuanceDispatcher{store: h.store, log: h.log}
	if err := dispatcher.recordRotationRun(ctx, h.tenant, run, "running", ""); err != nil {
		t.Fatal(err)
	}
	intent.RotationRunID = f.runID
	intent.PredecessorCertificateID = cert.ID
	intent.VerifyAddress = verifyAddress
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := h.srv.outbox.Enqueue(ctx, tx, orchestrator.Entry{TenantID: h.tenant, Destination: agentJobKindEndpointRenew, IdempotencyKey: "host-renew:renew:" + run.IdempotencyKey, Payload: payload, RequiredAgentRole: mtls.AgentRoleHost})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f.job = claimOneRenewal(t, ctx, h)
	f.fingerprint = signHostRotationFixtureJob(t, h, f.job)
	f.predecessor = predecessor
	return f
}

func (f *hostRotationResultFixture) report(t *testing.T, outcome string) *transport.ReportJobResultRequest {
	t.Helper()
	if outcome == transport.JobOutcomeFailed {
		return f.h.report(t, f.job.JobID, f.job.Attempt, outcome, "controlled pre-deploy failure", "")
	}
	id := f.h.identity.Identity()
	record := custody.Record{Origin: custody.OriginHostAgent, Storage: custody.StorageFile, Exportable: custody.Exportable, GeneratedBy: id.CommonName()}
	req, err := transport.SignedReportWithCustody(id, id.TenantID(), id.CommonName(), f.job.JobID, f.job.Attempt, outcome, "", "sha256:controlled-receiver-test", f.fingerprint, record, time.Now().UTC().Unix())
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func signHostRotationFixtureJob(t *testing.T, h *roleHarness, job transport.ClaimedJob) string {
	t.Helper()
	key, err := crypto.GenerateHostSubjectKey("rotation.example.test", []string{"rotation.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	issued, err := h.client.SignJobCSR(t.Context(), &transport.SignJobCSRRequest{JobID: job.JobID, Attempt: job.Attempt, CSRDER: key.CSRDER})
	if err != nil {
		t.Fatal(err)
	}
	return issued.Fingerprint
}

func TestHostRotationExecutionWithoutConfiguredProbeCompletes(t *testing.T) {
	f := newHostRotationResultFixtureWithVerify(t, "")
	response, err := f.h.client.ReportJobResult(t.Context(), f.report(t, transport.JobOutcomeExecuted))
	if err != nil || !response.Accepted {
		t.Fatalf("unprobed execution: %+v %v", response, err)
	}
	if run := f.run(t); run.Status != "succeeded" || run.SuccessorFingerprint != f.fingerprint {
		t.Fatalf("run=%+v", run)
	}
}
func (f *hostRotationResultFixture) run(t *testing.T) store.RotationRun {
	t.Helper()
	run, err := f.h.store.GetRotationRun(t.Context(), f.h.tenant, f.runID)
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func rejectHostRotationUpdate(t *testing.T, s *store.Store, table, condition string) func() {
	t.Helper()
	// table and condition are static test-owned identifiers and numeric job IDs.
	query := fmt.Sprintf(`CREATE FUNCTION hv2_rotation_test_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF %s THEN RAISE EXCEPTION 'controlled host rotation crash window'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER hv2_rotation_test_failure BEFORE UPDATE ON %s FOR EACH ROW EXECUTE FUNCTION hv2_rotation_test_failure()`, condition, table)
	if _, err := s.SystemPool().Exec(t.Context(), query); err != nil {
		t.Fatal(err)
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		if _, err := s.SystemPool().Exec(context.Background(), fmt.Sprintf("DROP TRIGGER hv2_rotation_test_failure ON %s; DROP FUNCTION hv2_rotation_test_failure()", table)); err != nil {
			t.Errorf("remove injected failure: %v", err)
		}
	}
	t.Cleanup(stop)
	return stop
}

func (f *hostRotationResultFixture) receiver() *agentService {
	return &agentService{store: f.h.store, log: f.h.log, orch: f.h.srv.orch}
}
