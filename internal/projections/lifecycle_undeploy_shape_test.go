// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"testing"

	"trstctl.com/trstctl/internal/events"
)

func TestVerifiedRollbackLifecycleRequiresCompletedExactEffect(t *testing.T) {
	event := events.Event{ID: "rollback-event", Type: EventIdentityUndeployed,
		SchemaVersion: LifecycleCompletedSideEffectEventSchemaVersion}
	valid := identityTransition{IdentityID: "identity-a", From: "deployed", To: "issued",
		SideEffect: &identityTransitionEffect{Destination: "connector.rollback", Completed: true,
			IdempotencyKey: lifecycleApprovalOutboxKey(event.ID, "")}}
	for _, tc := range []struct {
		name string
		edit func(*identityTransition)
	}{
		{"valid", func(*identityTransition) {}},
		{"wrong predecessor", func(p *identityTransition) { p.From = "renewing" }},
		{"wrong destination", func(p *identityTransition) { p.SideEffect.Destination = "connector.deploy" }},
		{"not completed", func(p *identityTransition) { p.SideEffect.Completed = false }},
		{"wrong event binding", func(p *identityTransition) { p.SideEffect.IdempotencyKey = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := valid
			effect := *valid.SideEffect
			payload.SideEffect = &effect
			tc.edit(&payload)
			err := validateLifecycleApprovalShape(event, payload)
			if (err == nil) != (tc.name == "valid") {
				t.Fatalf("rollback lifecycle shape error = %v", err)
			}
		})
	}
}
