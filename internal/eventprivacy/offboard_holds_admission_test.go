// SPDX-License-Identifier: BUSL-1.1

package eventprivacy_test

import (
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// Source/admission proof, not a served operator or external-bucket proof.
func TestProtectedOffboardKeepsHeldLifetimeManageableUntilVerifiedRelease(t *testing.T) {
	policy, log, _, _ := sourceFixture(t, nil)
	holds := eventprivacy.RetainedHoldPolicy{Policy: policy}
	admission := eventprivacy.SourceAdmission{Policy: policy, Holds: holds}
	offboard := events.Event{ID: "held-offboard", Type: "tenant.offboarded", TenantID: sourceTenant, SchemaVersion: 1, Time: time.Now().UTC(), Data: []byte(`{"rows_deleted":0}`)}
	const id = "6fcf3d63-8b3f-4397-9b7d-a270f7b81893"
	appendSource(t, log, "preflight-hold", projections.EventArchiveLegalHoldPlaced, time.Now().UTC(), projections.ArchiveLegalHoldPlaced{ID: id, Object: "tenant/" + sourceTenant + "/audit/held.jws", Reason: "retained legal hold"})
	appendSource(t, log, "preflight-applied", projections.EventArchiveLegalHoldRecorded, time.Now().UTC(), projections.ArchiveLegalHoldRecorded{ID: id, Status: "applied", At: time.Now().UTC()})
	if _, err := admission.EventProtectionFor(t.Context(), offboard); !errors.Is(err, eventprivacy.ErrRetentionHold) {
		t.Fatalf("held offboard admitted: %v", err)
	}
	life, err := policy.LatestLifetime(t.Context(), sourceTenant)
	if err != nil || life.Offboard != nil {
		t.Fatalf("refusal consumed the live lifetime: %v", err)
	}
	release := events.Event{ID: "preflight-release-request", Type: projections.EventArchiveLegalHoldReleaseRequested, TenantID: sourceTenant, SchemaVersion: 1, Time: time.Now().UTC(), Data: []byte(`{"id":"` + id + `"}`)}
	if decision, err := admission.EventProtectionFor(t.Context(), release); err != nil || decision.Mode != events.EventProtectionSensitive {
		t.Fatalf("hold prevented its own protected release: %v", err)
	}
	appendSource(t, log, release.ID, release.Type, release.Time, projections.ArchiveLegalHoldRelease{ID: id})
	if _, err := admission.EventProtectionFor(t.Context(), offboard); !errors.Is(err, eventprivacy.ErrRetentionHold) {
		t.Fatalf("release intent was mistaken for bucket readback: %v", err)
	}
	appendSource(t, log, "preflight-release-readback", projections.EventArchiveLegalHoldRecorded, time.Now().UTC(), projections.ArchiveLegalHoldRecorded{ID: id, Status: "released", At: time.Now().UTC()})
	if decision, err := admission.EventProtectionFor(t.Context(), offboard); err != nil || decision.Mode != events.EventProtectionSensitive {
		t.Fatalf("verified release did not unblock protected offboard: %v", err)
	}
}

func TestProtectedOffboardRequiresIndependentHoldPolicy(t *testing.T) {
	policy, _, _, _ := sourceFixture(t, nil)
	_, err := (eventprivacy.SourceAdmission{Policy: policy}).EventProtectionFor(t.Context(), events.Event{ID: "no-hold-policy", Type: "tenant.offboarded", TenantID: sourceTenant, SchemaVersion: 1, Time: time.Now().UTC(), Data: []byte(`{"rows_deleted":0}`)})
	if !errors.Is(err, eventprivacy.ErrSource) {
		t.Fatalf("missing hold authority admitted destructive offboard: %v", err)
	}
}
