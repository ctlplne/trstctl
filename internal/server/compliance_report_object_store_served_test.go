// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/objectstore/s3test"
	"trstctl.com/trstctl/internal/projections"
)

// evidencePackReportSigner produces a complete signed evidence pack, so a
// framework_evidence_pack schedule can run end to end.
type evidencePackReportSigner struct{ *reportWorkerSigner }

func (s evidencePackReportSigner) ExportEvidencePack(_ context.Context, _ string, framework api.ComplianceFramework) (api.ComplianceEvidencePack, error) {
	return api.ComplianceEvidencePack{
		Format: api.ComplianceEvidencePackFormat, Framework: string(framework),
		SignedExport: json.RawMessage(`{"manifest":{"framework":"` + string(framework) + `"},"signature":"AQ=="}`),
		PublicKeyDER: s.key.Public().DER,
	}, nil
}

// A97 (owner 2026-10-24): with audit.archive_object_store, a scheduled
// evidence pack is kept in the object store under the tenant's prefix, the
// completion event records that object as the run's reference, the schedule
// preview is ready without an archive directory, and an auditor downloads the
// exact signed bytes the store holds.
func TestServedScheduledEvidencePackIsArchivedInTheObjectStore(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	signer := evidencePackReportSigner{&reportWorkerSigner{key: key}}
	srv := s3test.NewServer(t)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ArchiveObjectStore = srv.Open(t)
		d.APIOptions = append(d.APIOptions, api.WithComplianceEvidence(signer))
	})
	ctx := t.Context()
	auditWriter := seedScopedToken(t, h.store, h.tenant, "audit:write")
	definition := map[string]any{
		"framework": "soc2", "name": "weekly SOC 2 evidence pack",
		"report_type": "framework_evidence_pack", "interval_seconds": 7 * 24 * 3600,
	}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/compliance/report-schedules/preview", auditWriter, definition)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"ready":true`)) {
		t.Fatalf("preview with only an object store = %d %s", status, body)
	}
	const scheduleID = "5b0bcf7e-1d76-4f1c-9b0f-97a0c35e6f61"
	due := time.Now().UTC().Add(-time.Hour)
	seed, err := h.log.Append(ctx, events.Event{
		TenantID: h.tenant, Type: projections.EventComplianceReportScheduleUpserted,
		Time: due.Add(-7 * 24 * time.Hour), SchemaVersion: 1,
		Data: []byte(`{"id":"` + scheduleID + `","framework":"soc2","name":"weekly SOC 2 evidence pack","report_type":"framework_evidence_pack","interval_seconds":604800,"enabled":true,"delivery":"audit_export"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(h.store).Apply(ctx, seed); err != nil {
		t.Fatal(err)
	}
	if processed, err := h.srv.RunComplianceReportsOnce(ctx); err != nil || processed != 1 {
		t.Fatalf("due sweep = %d, %v", processed, err)
	}
	run, err := h.store.GetComplianceReportRunByDue(ctx, h.tenant, scheduleID, due)
	if err != nil || run.Status != "completed" {
		t.Fatalf("evidence-pack run = %+v, %v", run, err)
	}
	wantRef := "tenant/" + h.tenant + "/reports/" + run.ID + "/" + run.ArtifactDigest + ".json"
	if run.ArtifactRef != wantRef {
		t.Fatalf("recorded reference = %q, want the object %q", run.ArtifactRef, wantRef)
	}
	stored, found := srv.Object(wantRef)
	if !found {
		t.Fatalf("the store holds %v, not the run's object", srv.Keys())
	}
	if !strings.Contains(string(stored), `"framework_evidence_pack"`) {
		t.Fatalf("the stored artifact is not the evidence-pack report: %.120s", stored)
	}
	auditor := seedScopedToken(t, h.store, h.tenant, "audit:read")
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/compliance/report-runs/"+run.ID+"/artifact", auditor, nil)
	if status != http.StatusOK || !bytes.Equal(body, stored) {
		t.Fatalf("served artifact = %d, %d bytes; want the %d stored bytes", status, len(body), len(stored))
	}
	if err := h.srv.api.VerifyScheduledComplianceArtifact(body, run); err != nil {
		t.Fatalf("the downloaded artifact does not verify: %v", err)
	}
	if err := h.srv.proj.Rebuild(ctx, h.log); err != nil {
		t.Fatalf("a rebuild refused the object reference: %v", err)
	}
	if rebuilt, err := h.store.GetComplianceReportRun(ctx, h.tenant, run.ID); err != nil || rebuilt.ArtifactRef != wantRef {
		t.Fatalf("rebuilt run = %+v, %v", rebuilt, err)
	}
	srv.Replace(wantRef, []byte(`{"tampered":true}`))
	if status, _ := secretsReq(t, h, http.MethodGet, "/api/v1/compliance/report-runs/"+run.ID+"/artifact", auditor, nil); status != http.StatusServiceUnavailable {
		t.Fatalf("download of altered stored bytes = %d, want 503", status)
	}
}
