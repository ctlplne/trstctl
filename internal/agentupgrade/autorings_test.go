// SPDX-License-Identifier: BUSL-1.1

package agentupgrade_test

import (
	"errors"
	"testing"
	"time"

	fleet "trstctl.com/trstctl/internal/agentupgrade"
)

// A69: automatic ring placement is deterministic and never produces an empty
// ring. Fresh, long-enrolled agents become the canary; a silent agent is not a
// canary; too small a fleet is refused rather than planned into a halt.
func TestPlanAutoRingsPrefersFreshLongEnrolledCanariesAndFillsEveryRing(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	seen := func(ago time.Duration) *time.Time { ts := now.Add(-ago); return &ts }
	candidates := []fleet.RingCandidate{
		{AgentID: "a-silent", Name: "oldest-but-silent", EnrolledAt: now.Add(-400 * time.Hour), LastSeenAt: seen(48 * time.Hour)},
		{AgentID: "a-new", Name: "newest", EnrolledAt: now.Add(-1 * time.Hour), LastSeenAt: seen(10 * time.Second)},
		{AgentID: "a-old", Name: "old-and-fresh", EnrolledAt: now.Add(-300 * time.Hour), LastSeenAt: seen(20 * time.Second)},
		{AgentID: "a-mid", Name: "mid-and-fresh", EnrolledAt: now.Add(-100 * time.Hour), LastSeenAt: seen(30 * time.Second)},
		{AgentID: "a-never", Name: "never-seen", EnrolledAt: now.Add(-500 * time.Hour)},
	}
	plan, err := fleet.PlanAutoRings(candidates, 0, 0, now, 90*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Canary) != 1 || plan.Canary[0].AgentID != "a-old" {
		t.Fatalf("canary = %+v, want the longest-enrolled agent that is still heartbeating", plan.Canary)
	}
	if len(plan.Early) != 1 || plan.Early[0].AgentID != "a-mid" {
		t.Fatalf("early = %+v, want the next fresh agent by enrollment age", plan.Early)
	}
	if len(plan.Broad) != 3 || plan.Broad[0].AgentID != "a-new" || plan.Broad[1].AgentID != "a-silent" || plan.Broad[2].AgentID != "a-never" {
		t.Fatalf("broad = %+v, want the rest with silent agents last", plan.Broad)
	}
	// Deterministic: the same input plans the same rings.
	again, _ := fleet.PlanAutoRings(candidates, 0, 0, now, 90*time.Second)
	if again.Canary[0].AgentID != plan.Canary[0].AgentID || len(again.Broad) != len(plan.Broad) {
		t.Fatal("the same candidates planned different rings")
	}
	// Two canaries, a bigger early share.
	plan, err = fleet.PlanAutoRings(candidates, 2, 50, now, 90*time.Second)
	if err != nil || len(plan.Canary) != 2 || len(plan.Early) != 2 || len(plan.Broad) != 1 {
		t.Fatalf("canary 2 / early 50%% = %d/%d/%d %v, want 2/2/1", len(plan.Canary), len(plan.Early), len(plan.Broad), err)
	}
	// Refusals: too few agents, a canary that leaves no room, an early share
	// that leaves no broad ring.
	if _, err := fleet.PlanAutoRings(candidates[:2], 1, 10, now, time.Minute); !errors.Is(err, fleet.ErrAutoRingsTooFew) {
		t.Fatalf("two agents planned into three rings: %v", err)
	}
	if _, err := fleet.PlanAutoRings(candidates, 4, 10, now, time.Minute); err == nil {
		t.Fatal("a canary of four among five left no early and broad ring but was planned")
	}
	if _, err := fleet.PlanAutoRings(candidates, 1, 95, now, time.Minute); err == nil {
		t.Fatal("an early share of 95% was planned")
	}
}
