// SPDX-License-Identifier: BUSL-1.1

package eventprivacy_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/events"
)

// Source/admission fixture only. The actual served authorization request must
// additionally prove omission of inherited actor and truthful audit status.
func TestMinimalAuthzAdmissionStaysClosedAndBoundToActualSourceState(t *testing.T) {
	for _, state := range []string{"active", "key_preparing", "tenant_offboarded"} {
		t.Run(state, func(t *testing.T) {
			policy, log, _, _ := sourceFixture(t, nil)
			if state != "active" {
				appendSource(t, log, "minimal-authz-offboard", "tenant.offboarded", time.Now().UTC(), struct {
					RowsDeleted int `json:"rows_deleted"`
				}{0})
			}
			if state == "key_preparing" {
				registered := appendSource(t, log, "minimal-authz-new-lifetime", "tenant.registered", time.Now().UTC(), struct {
					Name string `json:"name"`
				}{"new fixture"})
				request, err := eventprivacy.NewRequested(sourceTenant, registered.ID, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				appendSource(t, log, eventprivacy.RequestedEventID(request), eventprivacy.EventRequested, time.Now().UTC(), request)
			}
			admission := eventprivacy.SourceAdmission{Policy: policy}
			event, minimal, err := policy.MinimalAuthzEvent(t.Context(), sourceTenant, "privacy:read", "deny")
			if err != nil {
				t.Fatal(err)
			}
			if state == "active" {
				if minimal {
					t.Fatal("active tenant silently lost its encrypted detailed authorization audit")
				}
				decision, err := admission.EventProtectionFor(t.Context(), events.Event{Type: "authz.decision", TenantID: sourceTenant, SchemaVersion: 1, Data: []byte(`{"actor":"fixture-person@example.invalid","permission":"privacy:read","resource":"api_route","target":"fixture","decision":"deny"}`)})
				if err != nil || decision.Mode != events.EventProtectionSensitive {
					t.Fatalf("active detailed audit lost normal protection: %v", err)
				}
				return
			}
			if !minimal || event.Actor != nil || event.SchemaVersion != eventprivacy.MinimalAuthzSchemaVersion || bytes.Contains(event.Data, []byte("example.invalid")) {
				t.Fatal("minimal decision copied private context")
			}
			decision, err := admission.EventProtectionFor(t.Context(), event)
			if err != nil || decision.Mode != events.EventProtectionPublicControl {
				t.Fatalf("actual source state refused minimal audit: %v", err)
			}
			body, err := eventprivacy.ParseMinimalAuthzDecision(event)
			if err != nil || body.DetailsOmitted != state {
				t.Fatalf("audit omission state differs: %v", err)
			}
			if state == "key_preparing" {
				body.DetailsOmitted = "tenant_offboarded"
			} else {
				body.DetailsOmitted = "key_preparing"
			}
			event.Data, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := admission.EventProtectionFor(t.Context(), event); !errors.Is(err, eventprivacy.ErrSource) {
				t.Fatal("caller invented a different public audit state")
			}
			event.SchemaVersion = 1
			event.Data = []byte(`{"actor":"fixture-person@example.invalid","decision":"deny"}`)
			if _, err := admission.EventProtectionFor(t.Context(), event); err == nil {
				t.Fatal("preparing/offboarded state admitted detailed plaintext audit")
			}
		})
	}
}
