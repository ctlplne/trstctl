// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

type reportWorkerSigner struct {
	key         crypto.DigestSigner
	calls       atomic.Int32
	fail        atomic.Bool
	unavailable atomic.Bool
}

func (s *reportWorkerSigner) ExportEvidencePack(context.Context, string, api.ComplianceFramework) (api.ComplianceEvidencePack, error) {
	return api.ComplianceEvidencePack{}, errors.New("unexpected evidence-pack export")
}

func (s *reportWorkerSigner) SignScheduledManifest(_ context.Context, manifest json.RawMessage) (json.RawMessage, error) {
	s.calls.Add(1)
	if s.unavailable.Load() {
		return nil, status.Error(codes.Unavailable, "test isolated signer unavailable")
	}
	if s.fail.Load() {
		return nil, errors.New("test signer unavailable")
	}
	signature, err := crypto.SignMessage(s.key, manifest)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Manifest     json.RawMessage `json:"manifest"`
		Signature    []byte          `json:"signature"`
		PublicKeyDER []byte          `json:"public_key_der"`
	}{manifest, signature, s.key.Public().DER})
}

func (s *reportWorkerSigner) ScheduledVerificationKeyDER() []byte { return s.key.Public().DER }

func TestComplianceReportWorkerSignsArchivesAndRecoversExactDueEdge(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	signer := &reportWorkerSigner{key: key}
	archiveRoot := t.TempDir()
	// #nosec G302 -- owner execute is required to traverse this private test directory.
	if err := os.Chmod(archiveRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AuditArchiveDir = archiveRoot
		d.APIOptions = append(d.APIOptions, api.WithComplianceEvidence(signer))
	})
	ctx := t.Context()
	auditWriter := seedScopedToken(t, h.store, h.tenant, "audit:write")
	definition := map[string]any{
		"framework": "soc2", "name": "operator daily audit summary",
		"report_type": "audit_summary", "interval_seconds": 3600,
	}
	status, body := secretsReq(t, h, http.MethodPost,
		"/api/v1/compliance/report-schedules/preview", auditWriter, definition)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"ready":true`)) {
		t.Fatalf("configured operator preview = %d %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost,
		"/api/v1/compliance/report-schedules", auditWriter, definition)
	if status != http.StatusCreated {
		t.Fatalf("configured operator schedule create = %d %s", status, body)
	}
	const scheduleID = "27d819ea-0057-4ddb-9551-836d0e32128a"
	due := time.Now().UTC().Add(-time.Hour)
	seedEvent, err := h.log.Append(ctx, events.Event{
		TenantID: h.tenant, Type: projections.EventComplianceReportScheduleUpserted,
		Time: due.Add(-time.Hour), SchemaVersion: 1,
		Data: []byte(`{"id":"` + scheduleID + `","framework":"soc2","name":"daily audit summary","report_type":"audit_summary","interval_seconds":3600,"enabled":true,"delivery":"audit_export"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(h.store).Apply(ctx, seedEvent); err != nil {
		t.Fatal(err)
	}
	selected, err := h.store.GetComplianceReportSchedule(ctx, h.tenant, scheduleID)
	if err != nil || !selected.NextRunAt.Equal(due) {
		t.Fatalf("seeded due schedule = %+v, %v", selected, err)
	}
	if _, _, _, err := h.srv.reportArchive.FindRun(h.tenant,
		orchestrator.ComplianceReportRunID(h.tenant, scheduleID, due)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty private archive should have no signed run: %v", err)
	}
	// The first attempt fails while the signer is unavailable. The retry is
	// event-backed and exposes a bounded reason rather than a secret/error body.
	signer.unavailable.Store(true)
	processed, err := h.srv.RunComplianceReportsOnce(ctx)
	if err != nil || processed != 1 {
		t.Fatalf("first due sweep = %d, %v", processed, err)
	}
	run, err := h.store.GetComplianceReportRunByDue(ctx, h.tenant, scheduleID, due)
	if err != nil || run.Status != "retrying" || run.Attempt != 1 || run.ErrorCode != "signer_unavailable" {
		t.Fatalf("failed signer receipt = %+v, %v", run, err)
	}
	signer.unavailable.Store(false)
	didProcess, err := h.srv.runComplianceReportDue(ctx, selected, time.Now().UTC().Add(2*time.Minute))
	if err != nil || !didProcess {
		t.Fatalf("retry due edge = %t, %v", didProcess, err)
	}
	completed, err := h.store.GetComplianceReportRun(ctx, h.tenant, run.ID)
	if err != nil || completed.Status != "completed" || completed.Attempt != 2 || completed.ArtifactDigest == "" {
		t.Fatalf("completed report receipt = %+v, %v", completed, err)
	}
	artifact, err := h.srv.reportArchive.Read(h.tenant, run.ID, completed.ArtifactDigest)
	if err != nil || h.srv.api.VerifyScheduledComplianceArtifact(artifact, completed) != nil {
		t.Fatalf("independent archived signed readback = %v, artifact bytes %d", err, len(artifact))
	}
	if err := api.New(h.store, nil, nil).VerifyScheduledComplianceArtifact(artifact, completed); err != nil {
		t.Fatalf("core auditor lost completed report verification after license detachment: %v", err)
	}
	auditor := seedScopedToken(t, h.store, h.tenant, "audit:read")
	path := "/api/v1/compliance/report-runs/" + run.ID
	status, body = secretsReq(t, h, http.MethodGet, path, auditor, nil)
	if status != http.StatusOK {
		t.Fatalf("served run receipt = %d %s", status, body)
	}
	var servedRun struct {
		Status         string `json:"status"`
		ArtifactDigest string `json:"artifact_digest"`
	}
	if err := json.Unmarshal(body, &servedRun); err != nil || servedRun.Status != "completed" ||
		servedRun.ArtifactDigest != completed.ArtifactDigest {
		t.Fatalf("served run receipt = %+v, %v", servedRun, err)
	}
	status, body = secretsReq(t, h, http.MethodGet, path+"/artifact", auditor, nil)
	if status != http.StatusOK || !bytes.Equal(body, artifact) {
		t.Fatalf("served artifact changed signed bytes: status %d, got %d bytes", status, len(body))
	}
	status, body = secretsReq(t, h, http.MethodGet,
		"/api/v1/compliance/report-schedules/"+scheduleID+"/runs", auditor, nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(run.ID)) {
		t.Fatalf("served report history = %d %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodGet,
		"/api/v1/compliance/report-schedules/"+scheduleID+"/runs?limit=1", auditor, nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"next_cursor":""`)) {
		t.Fatalf("last report-history page advertised a nonexistent successor: %d %s", status, body)
	}
	viewer := seedScopedToken(t, h.store, h.tenant, "owners:read")
	status, _ = secretsReq(t, h, http.MethodGet, path+"/artifact", viewer, nil)
	if status != http.StatusForbidden {
		t.Fatalf("non-auditor downloaded signed report: HTTP %d", status)
	}
	if signer.calls.Load() != 2 {
		t.Fatalf("signer calls = %d, want one outage and one successful signature", signer.calls.Load())
	}
	if _, err := h.store.GetComplianceReportRun(ctx, "22222222-2222-2222-2222-222222222222", run.ID); err == nil {
		t.Fatal("other tenant read signed report receipt")
	}
	advanced, err := h.store.GetComplianceReportSchedule(ctx, h.tenant, scheduleID)
	if err != nil || !advanced.NextRunAt.After(completed.CompletedAt) {
		t.Fatalf("completed report did not advance next due edge: %+v, %v", advanced, err)
	}
	// Repeating the old selected due edge cannot sign or complete again.
	didProcess, err = h.srv.runComplianceReportDue(ctx, selected, time.Now().UTC().Add(2*time.Minute))
	if err != nil || didProcess || signer.calls.Load() != 2 {
		t.Fatalf("old due edge repeated: processed %t calls %d err %v", didProcess, signer.calls.Load(), err)
	}
}

func TestComplianceReportScheduleRefusesUnconfiguredExecution(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	auditor := seedScopedToken(t, h.store, h.tenant, "audit:write")
	definition := map[string]any{
		"framework": "soc2", "name": "cannot run without signer and archive",
		"report_type": "audit_summary", "interval_seconds": 3600,
	}
	status, body := secretsReq(t, h, http.MethodPost,
		"/api/v1/compliance/report-schedules/preview", auditor, definition)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"ready":false`)) ||
		!bytes.Contains(body, []byte("audit.archive_dir")) {
		t.Fatalf("unconfigured preview hid blockers = %d %s", status, body)
	}
	status, _ = secretsReq(t, h, http.MethodPost,
		"/api/v1/compliance/report-schedules", auditor, definition)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured schedule creation = HTTP %d, want 503", status)
	}
	if h.hasEvent(t, projections.EventComplianceReportScheduleUpserted) {
		t.Fatal("unconfigured schedule appended an event")
	}
}

func TestComplianceReportWorkerDeadLetterRequeueAndRecover(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	signer := &reportWorkerSigner{key: key}
	signer.fail.Store(true)
	archiveRoot := t.TempDir()
	// #nosec G302 -- owner execute is required to traverse this private test directory.
	if err := os.Chmod(archiveRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AuditArchiveDir = archiveRoot
		d.APIOptions = append(d.APIOptions, api.WithComplianceEvidence(signer))
	})
	ctx := t.Context()
	const scheduleID = "8a82db2c-1eef-47ce-a146-58f727576a88"
	due := time.Now().UTC().Add(-time.Hour)
	ev, err := h.log.Append(ctx, events.Event{
		TenantID: h.tenant, Type: projections.EventComplianceReportScheduleUpserted,
		Time: due.Add(-time.Hour), SchemaVersion: 1,
		Data: []byte(`{"id":"` + scheduleID + `","framework":"soc2","name":"dead letter replay","report_type":"audit_summary","interval_seconds":3600,"enabled":true,"delivery":"audit_export"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(h.store).Apply(ctx, ev); err != nil {
		t.Fatal(err)
	}
	schedule, err := h.store.GetComplianceReportSchedule(ctx, h.tenant, scheduleID)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 5; attempt++ {
		processed, err := h.srv.runComplianceReportDue(ctx, schedule, time.Now().UTC().Add(time.Hour))
		if err != nil || !processed {
			t.Fatalf("failed report attempt %d = %t, %v", attempt, processed, err)
		}
	}
	run, err := h.store.GetComplianceReportRunByDue(ctx, h.tenant, scheduleID, due)
	if err != nil || run.Status != "failed" || run.Attempt != 5 || run.ErrorCode != "producer_failed" {
		t.Fatalf("dead-letter receipt = %+v, %v", run, err)
	}
	path := "/api/v1/compliance/report-runs/" + run.ID + "/requeue"
	viewer := seedScopedToken(t, h.store, h.tenant, "audit:read")
	status, _ := secretsReq(t, h, http.MethodPost, path, viewer, nil)
	if status != http.StatusForbidden {
		t.Fatalf("read-only auditor requeued failed report: HTTP %d", status)
	}
	writer := seedScopedToken(t, h.store, h.tenant, "audit:write")
	status, body := secretsReqKey(t, h, http.MethodPost, path, writer, "requeue-dead-letter-once", nil)
	if status != http.StatusOK {
		t.Fatalf("operator requeue = %d %s", status, body)
	}
	status, replay := secretsReqKey(t, h, http.MethodPost, path, writer, "requeue-dead-letter-once", nil)
	if status != http.StatusOK || !bytes.Equal(replay, body) {
		t.Fatalf("idempotent requeue replay = %d %s", status, replay)
	}
	requeued, err := h.store.GetComplianceReportRun(ctx, h.tenant, run.ID)
	if err != nil || requeued.Status != "retrying" || requeued.Attempt != 0 || requeued.RetryGeneration != 1 {
		t.Fatalf("requeued due edge = %+v, %v", requeued, err)
	}
	signer.fail.Store(false)
	processed, err := h.srv.runComplianceReportDue(ctx, schedule, time.Now().UTC().Add(time.Hour))
	if err != nil || !processed {
		t.Fatalf("recovery attempt = %t, %v", processed, err)
	}
	recovered, err := h.store.GetComplianceReportRun(ctx, h.tenant, run.ID)
	if err != nil || recovered.Status != "completed" || recovered.Attempt != 1 || recovered.RetryGeneration != 1 {
		t.Fatalf("recovered report = %+v, %v", recovered, err)
	}
	status, _ = secretsReq(t, h, http.MethodPost, path, writer, nil)
	if status != http.StatusConflict {
		t.Fatalf("completed report accepted another requeue: HTTP %d", status)
	}
}
