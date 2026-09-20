// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"testing"

	"trstctl.com/trstctl/internal/events"
)

func TestAuthzDecisionPrivacyPolicyCoversEveryPersonalFieldAUD68(t *testing.T) {
	if !events.HasPrivacyEventPolicy(EventAuthzDecision, events.DefaultSchemaVersion) {
		t.Fatal("production authz.decision privacy policy is not registered")
	}
	count, err := events.ValidatePrivacyEventPolicySubjectFixtures(
		EventAuthzDecision,
		events.DefaultSchemaVersion,
	)
	if err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Fatalf("authz.decision subject-bearing paths=%d, want actor, target, reason, and role", count)
	}
}
