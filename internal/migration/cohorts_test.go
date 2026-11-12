// SPDX-License-Identifier: BUSL-1.1

package migration_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/migration"
)

// P3-L1: cohorts are cut canary first, in name order, each identity once,
// within the documented bounds.
func TestPlanCohortsCutsACanaryThenCohortsP3L1(t *testing.T) {
	t.Parallel()
	candidates := []migration.CohortCandidate{
		{IdentityID: "id-d", Name: "web-d"}, {IdentityID: "id-a", Name: "web-a", AgentID: "agent-1"},
		{IdentityID: "id-c", Name: "web-c"}, {IdentityID: "id-b", Name: "web-b"},
		{IdentityID: "id-a", Name: "web-a", AgentID: "agent-1"}, // a duplicate is placed once
		{IdentityID: "id-e2", Name: "web-e"}, {IdentityID: "id-e1", Name: "web-e"},
	}
	cohorts, err := migration.PlanCohorts(candidates, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range cohorts {
		var names []string
		for _, m := range c.Members {
			names = append(names, m.IdentityID)
		}
		got = append(got, c.ID+":"+strings.Join(names, ","))
		if c.Ordinal != len(got) {
			t.Fatalf("cohort %s has ordinal %d, want %d", c.ID, c.Ordinal, len(got))
		}
	}
	if want := "canary:id-a|cohort-2:id-b,id-c|cohort-3:id-d,id-e1|cohort-4:id-e2"; strings.Join(got, "|") != want {
		t.Fatalf("cohorts = %s, want %s", strings.Join(got, "|"), want)
	}
	if cohorts[0].Members[0].AgentID != "agent-1" || cohorts[0].Members[0].Name != "web-a" {
		t.Fatalf("canary member = %+v", cohorts[0].Members[0])
	}

	if cohorts, err := migration.PlanCohorts(nil, 1, 25); err != nil || len(cohorts) != 0 {
		t.Fatalf("no candidates: %v %v", cohorts, err)
	}
	for _, tc := range []struct {
		canary, cohort int
		want           string
	}{
		{0, 25, "canary_size"}, {migration.MaxCanarySize + 1, 25, "canary_size"},
		{1, 0, "cohort_size"}, {1, migration.MaxCohortSize + 1, "cohort_size"},
	} {
		if _, err := migration.PlanCohorts(candidates, tc.canary, tc.cohort); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("canary %d cohort %d: %v", tc.canary, tc.cohort, err)
		}
	}
	tooMany := make([]migration.CohortCandidate, migration.MaxCohortPlanMembers+1)
	for i := range tooMany {
		tooMany[i] = migration.CohortCandidate{IdentityID: "id-" + strings.Repeat("x", i%7) + string(rune('a'+i%26)), Name: "n"}
	}
	if _, err := migration.PlanCohorts(tooMany, 1, 25); err == nil {
		t.Fatal("a plan past MaxCohortPlanMembers was cut")
	}
	if _, err := migration.PlanCohorts([]migration.CohortCandidate{{Name: "no id"}}, 1, 25); err == nil {
		t.Fatal("a candidate with no identity id was placed")
	}
}
