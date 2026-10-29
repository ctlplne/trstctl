// SPDX-License-Identifier: BUSL-1.1

package eventprivacy_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// Source-only tests. No SQL hold projection is supplied to this authority.
// Actual SQL deletion, external bucket readback and operator release/retry must
// also be exercised by the production receiver journey before qualification.
func TestRetainedArchiveHoldRequiresVerifiedReleaseInExactLifetimeCut(t *testing.T) {
	const hold = "6fcf3d63-8b3f-4397-9b7d-a270f7b81893"
	for _, test := range []struct {
		name     string
		kinds    []string
		wantHold bool
	}{
		{"empty", nil, false},
		{"placed", []string{"placed"}, true},
		{"applied", []string{"placed", "applied"}, true},
		{"release-pending", []string{"placed", "applied", "release_requested"}, true},
		{"failed-place-is-uncertain", []string{"placed", "failed"}, true},
		{"failed-release-is-uncertain", []string{"placed", "applied", "release_requested", "failed"}, true},
		{"late-release-after-failure-is-not-current-readback", []string{"placed", "applied", "release_requested", "failed", "released"}, true},
		{"fresh-release-after-failure", []string{"placed", "applied", "release_requested", "failed", "release_requested", "released"}, false},
		{"verified-release", []string{"placed", "applied", "release_requested", "released"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy, log, _, _ := sourceFixture(t, nil)
			for i, kind := range test.kinds {
				id := fmt.Sprintf("hold-source-%s-%d-%s", test.name, i, kind)
				at := time.Now().UTC().Add(time.Duration(i) * time.Nanosecond)
				switch kind {
				case "placed":
					appendSource(t, log, id, projections.EventArchiveLegalHoldPlaced, at, projections.ArchiveLegalHoldPlaced{ID: hold, Object: "s3://fixture-bucket/opaque-segment", Reason: "fixture-person@example.invalid"})
				case "release_requested":
					appendSource(t, log, id, projections.EventArchiveLegalHoldReleaseRequested, at, projections.ArchiveLegalHoldRelease{ID: hold})
				default:
					appendSource(t, log, id, projections.EventArchiveLegalHoldRecorded, at, projections.ArchiveLegalHoldRecorded{ID: hold, Status: kind, At: at})
				}
			}
			appendSource(t, log, "hold-source-offboard", "tenant.offboarded", time.Now().UTC(), struct {
				RowsDeleted int `json:"rows_deleted"`
			}{0})
			life, err := policy.LatestLifetime(t.Context(), sourceTenant)
			if err != nil {
				t.Fatal(err)
			}
			err = (eventprivacy.RetainedHoldPolicy{Policy: policy}).RequireClear(t.Context(), life)
			if test.wantHold {
				if !errors.Is(err, eventprivacy.ErrRetentionHold) {
					t.Fatalf("retained hold lost authority without verified release: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRetainedReportHoldAndNeighborStayBoundToOldOffboardCut(t *testing.T) {
	const run = "c8c90eb5-aa5a-491f-887f-e9c22a098f24"
	for _, released := range []bool{false, true} {
		t.Run(map[bool]string{false: "held", true: "released"}[released], func(t *testing.T) {
			policy, log, _, _ := sourceFixture(t, nil)
			appendSource(t, log, "report-hold-placed", projections.EventComplianceReportLegalHoldPlaced, time.Now().UTC(), projections.ComplianceReportLegalHold{RunID: run, Reason: "fixture hold reason"})
			if released {
				appendSource(t, log, "report-hold-released", projections.EventComplianceReportLegalHoldReleased, time.Now().UTC(), projections.ComplianceReportLegalHold{RunID: run})
			}
			if _, err := log.Append(t.Context(), events.Event{ID: "neighbor-hold", Type: projections.EventComplianceReportLegalHoldPlaced, TenantID: "22222222-2222-2222-2222-222222222222", Data: []byte(`{"run_id":"c8c90eb5-aa5a-491f-887f-e9c22a098f24","reason":"neighbor"}`)}); err != nil {
				t.Fatal(err)
			}
			appendSource(t, log, "report-hold-offboard", "tenant.offboarded", time.Now().UTC(), struct {
				RowsDeleted int `json:"rows_deleted"`
			}{0})
			life, err := policy.LatestLifetime(t.Context(), sourceTenant)
			if err != nil {
				t.Fatal(err)
			}
			appendSource(t, log, "report-hold-new-registration", "tenant.registered", time.Now().UTC(), struct {
				Name string `json:"name"`
			}{"new lifetime"})
			appendSource(t, log, "new-lifetime-report-hold", projections.EventComplianceReportLegalHoldPlaced, time.Now().UTC(), projections.ComplianceReportLegalHold{RunID: "2c14fe81-1956-4e9d-a174-e27a38e8e979", Reason: "new lifetime hold"})
			err = (eventprivacy.RetainedHoldPolicy{Policy: policy}).RequireClear(t.Context(), life)
			if released && err != nil {
				t.Fatalf("new/neighbor hold blocked unrelated historical lifetime: %v", err)
			}
			if !released && !errors.Is(err, eventprivacy.ErrRetentionHold) {
				t.Fatalf("old report hold disappeared at re-registration: %v", err)
			}
		})
	}
}
