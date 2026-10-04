// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

type scheduledReportTestSigner struct{}

func (scheduledReportTestSigner) ExportEvidencePack(_ context.Context, _ string, framework api.ComplianceFramework) (api.ComplianceEvidencePack, error) {
	return api.ComplianceEvidencePack{
		Format: api.ComplianceEvidencePackFormat, Framework: string(framework),
		SignedExport: json.RawMessage(`{"manifest":{"control":"evidenced"},"signature":"AQ=="}`),
		PublicKeyDER: []byte{1},
	}, nil
}

func (scheduledReportTestSigner) SignScheduledManifest(_ context.Context, manifest json.RawMessage) (json.RawMessage, error) {
	return json.Marshal(struct {
		Manifest json.RawMessage `json:"manifest"`
	}{Manifest: manifest})
}

func TestScheduledReportProducerBindsAllAdvertisedTypesToTenantRunAndDue(t *testing.T) {
	if testing.Short() {
		t.Skip("scheduled-report producer uses real PostgreSQL and embedded NATS")
	}
	ctx := context.Background()
	dsn, stopPG := startMachineSessionPostgres(t)
	t.Cleanup(stopPG)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	const tenantID = "11111111-1111-1111-1111-111111111111"
	const otherTenantID = "22222222-2222-2222-2222-222222222222"
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "scheduled-test", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	due := time.Date(2026, 10, 4, 16, 0, 0, 0, time.UTC)
	if _, err := log.Append(ctx, events.Event{TenantID: tenantID, Type: "policy.decision", Time: due.Add(-time.Minute), Data: []byte(`{"result":"allow"}`)}); err != nil {
		t.Fatal(err)
	}
	a := api.New(st, nil, nil, api.WithComplianceEvidence(scheduledReportTestSigner{}), api.WithEventLog(log))
	for _, reportType := range []string{"framework_evidence_pack", "inventory_snapshot", "cbom_posture", "audit_summary", "nhi_compliance_mapping"} {
		schedule := store.ComplianceReportSchedule{
			ID: "33333333-3333-4333-8333-333333333333", TenantID: tenantID,
			Framework: "soc2", ReportType: reportType, Enabled: true,
			IntervalSeconds: 3600, Delivery: "audit_export", NextRunAt: due,
		}
		const runID = "44444444-4444-4444-8444-444444444444"
		wire, err := a.BuildScheduledComplianceArtifact(ctx, tenantID, schedule, runID, due.Add(time.Minute))
		if err != nil {
			t.Fatalf("%s: %v", reportType, err)
		}
		var envelope struct {
			Manifest api.ScheduledComplianceManifest `json:"manifest"`
		}
		if err := json.Unmarshal(wire, &envelope); err != nil {
			t.Fatal(err)
		}
		manifest := envelope.Manifest
		if manifest.Format != api.ScheduledComplianceReportFormat || manifest.TenantID != tenantID ||
			manifest.ScheduleID != schedule.ID || manifest.RunID != runID || !manifest.DueAt.Equal(due) ||
			manifest.Framework != "soc2" || manifest.ReportType != reportType || len(manifest.Payload) == 0 {
			t.Fatalf("%s manifest binding = %+v", reportType, manifest)
		}
		if reportType == "audit_summary" {
			var summary struct {
				RecordCount        int    `json:"record_count"`
				FirstEventID       string `json:"first_event_id"`
				SourceHeadSequence uint64 `json:"source_head_sequence"`
			}
			if err := json.Unmarshal(manifest.Payload, &summary); err != nil || summary.RecordCount != 1 ||
				summary.FirstEventID == "" || summary.SourceHeadSequence == 0 {
				t.Fatalf("audit summary = %s, %v", manifest.Payload, err)
			}
		}
		if _, err := a.BuildScheduledComplianceArtifact(ctx, otherTenantID, schedule, runID, due.Add(time.Minute)); err == nil {
			t.Fatalf("%s accepted a cross-tenant schedule", reportType)
		}
	}
}
