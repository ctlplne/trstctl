// SPDX-License-Identifier: BUSL-1.1

package eventprivacy_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestHoldClearanceRefusesRetainedHold(t *testing.T) {
	policy, log, _, _ := sourceFixture(t, nil)
	const hold = "6fcf3d63-8b3f-4397-9b7d-a270f7b81893"
	appendSource(t, log, "clearance-place", projections.EventArchiveLegalHoldPlaced, time.Now().UTC(), projections.ArchiveLegalHoldPlaced{ID: hold, Object: "opaque-segment", Reason: "clearance proof"})
	appendSource(t, log, "clearance-offboard", "tenant.offboarded", time.Now().UTC(), struct {
		RowsDeleted int `json:"rows_deleted"`
	}{0})
	life, err := policy.LatestLifetime(t.Context(), sourceTenant)
	if err != nil {
		t.Fatal(err)
	}
	request, err := eventprivacy.NewDestructionRequest(life)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(eventprivacy.HoldClearance{Request: request})
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{ID: eventprivacy.HoldClearanceEventID(request), Type: eventprivacy.EventHoldClearance, TenantID: sourceTenant, SchemaVersion: 1, Time: time.Now().UTC(), Data: wire}
	admission := eventprivacy.SourceAdmission{Policy: policy, Holds: eventprivacy.RetainedHoldPolicy{Policy: policy}}
	if _, err := admission.EventProtectionFor(t.Context(), event); !errors.Is(err, eventprivacy.ErrRetentionHold) {
		t.Fatalf("a caller invented public hold clearance: %v", err)
	}
}

func TestHoldClearanceRemainsBoundToHistoricalOffboardAfterNewRegistration(t *testing.T) {
	policy, log, _, _ := sourceFixture(t, nil)
	appendSource(t, log, "clear-cut-offboard", "tenant.offboarded", time.Now().UTC(), struct {
		RowsDeleted int `json:"rows_deleted"`
	}{0})
	life, err := policy.LatestLifetime(t.Context(), sourceTenant)
	if err != nil {
		t.Fatal(err)
	}
	request, err := eventprivacy.NewDestructionRequest(life)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(eventprivacy.HoldClearance{Request: request})
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{ID: eventprivacy.HoldClearanceEventID(request), Type: eventprivacy.EventHoldClearance, TenantID: sourceTenant, SchemaVersion: 1, Time: time.Now().UTC(), Data: wire}
	admission := eventprivacy.SourceAdmission{Policy: policy, Holds: eventprivacy.RetainedHoldPolicy{Policy: policy}}
	if decision, err := admission.EventProtectionFor(t.Context(), event); err != nil || decision.Mode != events.EventProtectionPublicControl {
		t.Fatalf("independently clear cut refused: %v", err)
	}
	retained, err := log.Append(t.Context(), event)
	if err != nil {
		t.Fatal(err)
	}
	appendSource(t, log, "clear-cut-new-registration", "tenant.registered", time.Now().UTC(), struct {
		Name string `json:"name"`
	}{"new lifetime"})
	appendSource(t, log, "clear-cut-new-hold", projections.EventComplianceReportLegalHoldPlaced, time.Now().UTC(), projections.ComplianceReportLegalHold{RunID: "c8c90eb5-aa5a-491f-887f-e9c22a098f24", Reason: "new lifetime hold"})
	old, found, err := policy.LifetimeForKey(t.Context(), request.Ref)
	if err != nil || !found || old.HoldClearance == nil || old.HoldClearance.Meta.Sequence != retained.Sequence {
		t.Fatalf("clearance moved to the new lifetime: %v", err)
	}
	// A retained, admitted immutable cut needs no future reopening of encrypted
	// hold bodies. Removal still requires its separate committed effect grant.
	admission.Holds = nil
	if _, err := admission.EventProtectionFor(t.Context(), event); err != nil {
		t.Fatalf("durable clearance retry reopened private hold authority: %v", err)
	}
	changed := event
	changed.TenantID = "22222222-2222-2222-2222-222222222222"
	if _, err := admission.EventProtectionFor(t.Context(), changed); !errors.Is(err, eventprivacy.ErrSource) {
		t.Fatalf("cross-tenant clearance accepted: %v", err)
	}
}
