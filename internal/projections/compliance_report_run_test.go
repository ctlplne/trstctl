// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestComplianceReportRunRetainedThroughCatchUpAndFullRebuild(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	p := projections.New(s)
	const scheduleID = "19bdd6d9-c73e-4eb0-8f51-b0bed471ef22"
	const runID = "858fd1b2-995b-4a29-b803-c928e655164a"
	due := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	createdAt := due.Add(-time.Hour)
	schedulePayload, err := json.Marshal(projections.ComplianceReportScheduleUpserted{
		ID: scheduleID, Framework: "soc2", Name: "rebuild pack", ReportType: "framework_evidence_pack",
		IntervalSeconds: 3600, Enabled: true, Delivery: "audit_export",
	})
	if err != nil {
		t.Fatal(err)
	}
	mustAppend(t, log, events.Event{Type: projections.EventComplianceReportScheduleUpserted,
		TenantID: tenantA, Time: createdAt, Data: schedulePayload})
	digest := crypto.SHA256Hex([]byte(`{"signed_export":{"signature":"AQ=="}}`))
	artifactRef := "reports/" + tenantA + "/" + runID + "-" + digest + ".json"
	runPayload, err := json.Marshal(projections.ComplianceReportRunRecorded{
		ID: runID, ScheduleID: scheduleID, DueAt: due, Framework: "soc2",
		ReportType: "framework_evidence_pack", Status: "completed", Attempt: 1,
		ArtifactRef: artifactRef, ArtifactDigest: digest,
		CompletedAt: due.Add(time.Minute), CreatedAt: due,
	})
	if err != nil {
		t.Fatal(err)
	}
	mustAppend(t, log, events.Event{Type: projections.EventComplianceReportRunRecorded,
		TenantID: tenantA, Time: due.Add(time.Minute), Data: runPayload})
	check := func(stage string) {
		t.Helper()
		got, err := s.GetComplianceReportRun(ctx, tenantA, runID)
		if err != nil || got.Status != "completed" || got.ArtifactRef != artifactRef ||
			got.ArtifactDigest != digest {
			t.Fatalf("%s run = %+v, %v", stage, got, err)
		}
		if _, err := s.GetComplianceReportRun(ctx, tenantB, runID); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("%s cross-tenant read = %v", stage, err)
		}
	}
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	check("catch-up")
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	check("full rebuild")
}
