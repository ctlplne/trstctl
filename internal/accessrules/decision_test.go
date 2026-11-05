// SPDX-License-Identifier: BUSL-1.1
package accessrules

import (
	"testing"
	"time"
)

func TestReviewCombinesQuorumAndDeadlineButBlockWins(t *testing.T) {
	rules := []Rule{
		{ID: "11111111-1111-4111-8111-111111111111", Name: "First", Enabled: true, Protocol: "postgres", Operations: []string{"DROP"}, Effect: EffectReview, RequiredApprovals: 1, ReviewTTLSeconds: 40},
		{ID: "22222222-2222-4222-8222-222222222222", Name: "Second", Enabled: true, Protocol: "postgres", Operations: []string{"DROP"}, Effect: EffectReview, RequiredApprovals: 3, ReviewTTLSeconds: 10},
	}
	canonical, err := CanonicalRules(rules)
	if err != nil {
		t.Fatal(err)
	}
	policy := ForTarget("33333333-3333-4333-8333-333333333333", 4, canonical, "postgres")
	if err := ValidatePolicy(policy, "postgres"); err != nil {
		t.Fatal(err)
	}
	observation := Observation{Phase: "query", RuleIDs: Match(policy, []string{"DROP"})}
	if q, ttl := ReviewRequirement(policy, observation); q != 3 || ttl != 10 {
		t.Fatalf("combined review = %d,%d", q, ttl)
	}
	policy.Rules[0].Effect = EffectBlock
	if q, _ := ReviewRequirement(policy, observation); q != 0 {
		t.Fatal("a matching block became human-authorizable")
	}
	policy.Rules[0].Effect = EffectReview
	for _, phase := range []string{"control", "uninspectable"} {
		observation.Phase = phase
		if q, _ := ReviewRequirement(policy, observation); q != 0 {
			t.Fatal("unsupported traffic became human-authorizable")
		}
	}
	for _, edit := range []func(*Rule){func(r *Rule) { r.RequiredApprovals = 0 }, func(r *Rule) { r.RequiredApprovals = 4 }, func(r *Rule) { r.ReviewTTLSeconds = 4 }, func(r *Rule) { r.ReviewTTLSeconds = 46 }, func(r *Rule) { r.Effect = EffectBlock }} {
		r := rules[0]
		edit(&r)
		if _, err := CanonicalRules([]Rule{r}); err == nil {
			t.Fatal("invalid review bounds accepted")
		}
	}
}

func TestDecisionCannotExtendAuthorityOrMixAnOccurrence(t *testing.T) {
	session, connection := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	deadline := at.Add(10 * time.Second)
	d := Decision{ID: ActionID(session, connection, 7, 2, 1), SessionID: session, JobID: 7, Attempt: 2, Protocol: "postgres", Observation: Observation{ConnectionID: connection, Ordinal: 1, Phase: "bind", Operations: []string{"DROP"}, RuleIDs: []string{"33333333-3333-4333-8333-333333333333"}, MessageDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, PolicyDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Status: StatusAuthorized, Reason: "review_approved", ObservedAt: at, DecidedAt: at.Add(time.Second), ReviewExpiresAt: &deadline}
	if err := ValidateDecision(d); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*Decision){func(d *Decision) { d.Attempt++ }, func(d *Decision) { d.Ordinal++ }, func(d *Decision) { d.DecidedAt = deadline }, func(d *Decision) { d.ReviewExpiresAt = nil }, func(d *Decision) { d.Status = StatusPending }, func(d *Decision) { d.Reason = "untrusted free-form input" }} {
		copy := d
		edit(&copy)
		if ValidateDecision(copy) == nil {
			t.Fatal("altered authorization accepted")
		}
	}
}
