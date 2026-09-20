// SPDX-License-Identifier: BUSL-1.1

package risk

import "testing"

func TestAUD67UrgentSummaryMergesEveryProjectionWithoutDoubleCounting(t *testing.T) {
	base := []CredentialRisk{
		{CredentialID: "shared", Subject: "shared.example", Score: 92},
		{CredentialID: "base-high", Subject: "base-high.example", Score: 74},
		{CredentialID: "base-low", Subject: "base-low.example", Score: 40},
	}
	contextual := []ContextualPriority{
		{CredentialID: "shared", Subject: "shared.example", Severity: "critical", ContextualScore: 100},
		{CredentialID: "context-critical", Subject: "shadow.example", Severity: "critical", ContextualScore: 96},
		{CredentialID: "context-high", Subject: "old-token", Severity: "high", ContextualScore: 78},
	}

	got := SummarizeUrgentRisk(base, contextual)
	if got.Status != UrgentSummaryComplete || got.Urgent != 4 || got.Critical != 2 || got.High != 2 {
		t.Fatalf("canonical urgent summary = %+v, want complete/4 urgent/2 critical/2 high", got)
	}
	if got.UniqueAnalyzed != 5 {
		t.Fatalf("unique analyzed = %d, want 5 after shared credential_id is deduplicated", got.UniqueAnalyzed)
	}
	if got.CredentialRisk.Analyzed != 3 || got.CredentialRisk.Critical != 1 || got.CredentialRisk.High != 1 {
		t.Fatalf("credential-risk projection = %+v, want 3/1/1", got.CredentialRisk)
	}
	if got.ContextualPriorities.Analyzed != 3 || got.ContextualPriorities.Critical != 2 || got.ContextualPriorities.High != 1 {
		t.Fatalf("contextual projection = %+v, want 3/2/1", got.ContextualPriorities)
	}
	if len(got.IncludedProjections) != 2 || got.Scope == "" {
		t.Fatalf("projection scope is not explicit: %+v", got)
	}
}

func TestAUD67UrgentSummaryIncludesContextualCriticalWhenBaseIsEmpty(t *testing.T) {
	got := SummarizeUrgentRisk(nil, []ContextualPriority{{
		CredentialID: "discovery:shadow", Subject: "shadow", Severity: "critical", ContextualScore: 100,
	}})
	if got.Urgent != 1 || got.Critical != 1 || got.CredentialRisk.Analyzed != 0 || got.ContextualPriorities.Critical != 1 {
		t.Fatalf("base-empty contextual-critical summary = %+v, want one visible critical", got)
	}
}

func TestAUD67DiscoveryAlertUsesContextualSeverityBands(t *testing.T) {
	for _, tc := range []struct {
		score int
		want  string
	}{
		{score: 85, want: "critical"},
		{score: 70, want: "high"},
		{score: 69, want: ""},
	} {
		if got := DiscoveryUrgency(tc.score); got != tc.want {
			t.Fatalf("DiscoveryUrgency(%d) = %q, want %q", tc.score, got, tc.want)
		}
	}
}
