// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"testing"

	"trstctl.com/trstctl/internal/events"
)

// This is the audit-only parser/no-domain-write seam, not a datastore mock.
// Separate served matrix tests use actual PostgreSQL and NATS. A nil transaction
// here ensures a valid closed decision does not need a domain SQL mutation.
func TestMinimalAuthorizationProjectionRejectsNonClosedRecords(t *testing.T) {
	event := events.Event{Type: "authz.decision", TenantID: "d59b4292-1adc-4d43-a405-781f95b1779c", SchemaVersion: 2, Data: []byte(`{"permission":"owners:write","decision":"deny","details_omitted":"key_preparing"}`)}
	projector := &Projector{}
	if err := projector.applyCoreEventTx(t.Context(), nil, event); err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{
		`{"permission":"private-person@example.invalid","decision":"deny","details_omitted":"key_preparing"}`,
		`{"permission":"owners:write","decision":"deny","details_omitted":"private-reason"}`,
		`{"permission":"owners:write","decision":"deny","details_omitted":"key_preparing","target":"private-target"}`,
		`{"permission":"owners:write","decision":"deny","decision":"allow","details_omitted":"key_preparing"}`,
	} {
		changed := event
		changed.Data = []byte(data)
		if err := projector.applyCoreEventTx(t.Context(), nil, changed); err == nil {
			t.Fatal("replay accepted identity-bearing or ambiguous minimal audit data")
		}
	}
	changed := event
	changed.Actor = &events.Actor{Subject: "private-person@example.invalid"}
	if err := projector.applyCoreEventTx(t.Context(), nil, changed); err == nil {
		t.Fatal("replay accepted an actor on the closed audit schema")
	}
	changed = event
	changed.SchemaVersion = 3
	if err := projector.applyCoreEventTx(t.Context(), nil, changed); err == nil {
		t.Fatal("replay silently ignored an unknown audit schema")
	}
}
