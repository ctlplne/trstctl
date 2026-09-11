// SPDX-License-Identifier: MPL-2.0

package projections

import (
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

func TestOwnershipReadyRecoveryHasNoExternalEffect(t *testing.T) {
	event := events.Event{Type: EventIdentityRenewalRecovered, SchemaVersion: LifecycleOwnershipReadinessEventSchemaVersion}
	for _, tc := range []struct {
		name   string
		change func(*identityTransition)
	}{
		{"valid", func(*identityTransition) {}},
		{"wrong predecessor state", func(p *identityTransition) { p.From = "revoked" }},
		{"wrong next state", func(p *identityTransition) { p.To = "issued" }},
		{"missing owner authority", func(p *identityTransition) { p.OwnershipReadiness = nil }},
		{"other identity authority", func(p *identityTransition) { p.OwnershipReadiness.IdentityID = "other" }},
		{"invented connector effect", func(p *identityTransition) { p.SideEffect = &identityTransitionEffect{Destination: "connector.deploy"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := identityTransition{IdentityID: "owned", From: "renewal_failed", To: "deployed",
				OwnershipReadiness: &store.OwnershipReadinessEvidence{IdentityID: "owned"}}
			tc.change(&payload)
			err := validateLifecycleApprovalShape(event, payload)
			if (err == nil) != (tc.name == "valid") {
				t.Fatalf("recovery shape error=%v", err)
			}
		})
	}
}
