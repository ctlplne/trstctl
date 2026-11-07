// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"encoding/json"
	"strings"
	"testing"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/servicedependents"
)

func TestManifestPositionCannotWidenPublishedNativeStepSourcesA267(t *testing.T) {
	source, v, _, _ := recoverySourceFixture(t)
	position := &servicedependents.ManifestPosition{Stage: v.Step.Action, EntryOrdinal: 3, PageNumber: 1, EntryIndex: 1}
	v.Previous.ManifestPosition = position
	replacement, err := servicedependents.NewInverseRecoveryStep(v.Previous, v.Step.Challenge, v.At)
	if err != nil {
		t.Fatal(err)
	}
	v.Step = replacement
	v.ReviewDigest, err = ServiceDependentRecoveryReviewDigest(v.Previous, v.PreviousStatus, v.PreviousReportDigest, v.CurrentVersion)
	if err != nil {
		t.Fatal(err)
	}
	source.Data, err = json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if ValidateServiceDependentStepRecovery(source, v) == nil {
		t.Error("published recovery v1 accepted a new manifest position")
	}
	if _, _, _, err := DecodeServiceDependentStepSource(source); err == nil {
		t.Error("canonical recovery decoder accepted position under v1")
	}
	queued := events.Event{ID: servicedependents.StepSourceID(v.Previous.RotationID, v.Previous.ID), Type: EventServiceDependentStepQueued, SchemaVersion: 1, Time: v.Previous.NotBefore, TenantID: source.TenantID}
	queued.Data, err = json.Marshal(ServiceDependentStepQueued{Step: v.Previous, At: queued.Time})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := DecodeServiceDependentStepSource(queued); err == nil {
		t.Error("ordinary step v1 accepted manifest position")
	}
	for _, e := range []events.Event{source, queued} {
		if _, _, err := events.PseudonymizeEventDataForSubject(e.Data, e.TenantID, v.Previous.ProbeID, e.Type, e.SchemaVersion); err == nil || !strings.Contains(err.Error(), "pre-rewrite payload") {
			t.Errorf("legacy native shape widened: %s: %v", e.Type, err)
		}
	}
}
func TestManifestCannotWidenPublishedInlinePlanPrivacyShapesA267(t *testing.T) {
	for _, v := range []struct {
		kind    string
		version int
	}{
		{EventServiceDependentRotationQueued, 1}, {EventServiceDependentRotationQueued, 2}, {EventServiceReconciliationReviewProposed, 1},
	} {
		var value any = ServiceDependentRotationQueued{Actor: "owned-operator"}
		if v.kind == EventServiceReconciliationReviewProposed {
			value = ServiceReconciliationReview{Actor: "owned-operator"}
		}
		baseline, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := events.PseudonymizeEventDataForSubject(baseline, "owned-tenant", "owned-operator", v.kind, v.version); err != nil {
			t.Fatalf("valid old shape refused: %v", err)
		}
		var payload map[string]any
		if err := json.Unmarshal(baseline, &payload); err != nil {
			t.Fatal(err)
		}
		payload["intent"].(map[string]any)["plan"].(map[string]any)["manifest"] = nil
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := events.PseudonymizeEventDataForSubject(raw, "owned-tenant", "owned-operator", v.kind, v.version); err == nil || !strings.Contains(err.Error(), "pre-rewrite payload") {
			t.Fatalf("%s v%d accepted widened inline plan: %v", v.kind, v.version, err)
		}
	}
}

func TestManifestNullFieldCannotHideInPublishedStepSourceA267(t *testing.T) {
	source, v, _, _ := recoverySourceFixture(t)
	source.ID = servicedependents.StepSourceID(v.Previous.RotationID, v.Previous.ID)
	source.Type = EventServiceDependentStepQueued
	source.Time = v.Previous.NotBefore
	raw, err := json.Marshal(ServiceDependentStepQueued{Step: v.Previous, At: source.Time})
	if err != nil {
		t.Fatal(err)
	}
	source.Data = raw
	if _, _, _, err := DecodeServiceDependentStepSource(source); err != nil {
		t.Fatal("original source refused", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	payload["step"].(map[string]any)["manifest_position"] = nil
	source.Data, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := DecodeServiceDependentStepSource(source); err == nil {
		t.Fatal("an undeclared null manifest position widened step source v1")
	}
}
