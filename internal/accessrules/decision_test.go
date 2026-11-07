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

// TestAlertRulesLetACommandRunAndNameItsSeverityA275: an alert rule has a
// severity and no review; a command only alert rules matched is alerted —
// permitted, with the highest severity — while a block or review rule
// matched beside one takes precedence and uninspected traffic is never
// alerted through. An alerted decision has no review deadline.
func TestAlertRulesLetACommandRunAndNameItsSeverityA275(t *testing.T) {
	warn := Rule{ID: "11111111-1111-4111-8111-111111111111", Name: "Privilege change", Enabled: true, Protocol: "postgres", Operations: []string{"GRANT"}, Effect: EffectAlert, Severity: SeverityWarning}
	crit := Rule{ID: "22222222-2222-4222-8222-222222222222", Name: "Bulk delete", Enabled: true, Protocol: "postgres", Operations: []string{"GRANT", "TRUNCATE"}, Effect: EffectAlert, Severity: SeverityCritical}
	review := Rule{ID: "33333333-3333-4333-8333-333333333333", Name: "Review drops", Enabled: true, Protocol: "postgres", Operations: []string{"DROP"}, Effect: EffectReview, RequiredApprovals: 1, ReviewTTLSeconds: 30}
	block := Rule{ID: "44444444-4444-4444-8444-444444444444", Name: "Refuse revokes", Enabled: true, Protocol: "postgres", Operations: []string{"REVOKE"}, Effect: EffectBlock}
	canonical, err := CanonicalRules([]Rule{warn, crit, review, block})
	if err != nil {
		t.Fatal(err)
	}
	policy := ForTarget("55555555-5555-4555-8555-555555555555", 1, canonical, "postgres")
	if err := ValidatePolicy(policy, "postgres"); err != nil || policy.Rules[0].Severity != SeverityWarning || policy.Rules[1].Severity != SeverityCritical {
		t.Fatalf("the frozen policy keeps each alert rule's severity: %+v %v", policy, err)
	}
	observe := func(phase string, ops ...string) Observation {
		return Observation{Phase: phase, RuleIDs: Match(policy, ops), Operations: MatchedOperations(policy, ops)}
	}
	if ok, severity := Alerting(policy, observe("query", "GRANT")); !ok || severity != SeverityCritical {
		t.Fatalf("GRANT matched both alert rules: %v %q", ok, severity)
	}
	if q, _ := ReviewRequirement(policy, observe("query", "GRANT")); q != 0 {
		t.Fatal("an alert rule asked for review")
	}
	for _, o := range []Observation{observe("query", "GRANT", "DROP"), observe("query", "TRUNCATE", "REVOKE"), {Phase: "control", RuleIDs: Match(policy, []string{"GRANT"})}, observe("query", "SELECT")} {
		if ok, _ := Alerting(policy, o); ok {
			t.Fatalf("alerted through a stricter rule, uninspected traffic or nothing: %+v", o)
		}
	}
	if q, ttl := ReviewRequirement(policy, observe("query", "GRANT", "DROP")); q != 1 || ttl != 30 {
		t.Fatalf("review beside an alert rule = %d,%d", q, ttl)
	}
	for _, edit := range []func(*Rule){func(r *Rule) { r.Severity = "" }, func(r *Rule) { r.Severity = "info" }, func(r *Rule) { r.RequiredApprovals = 1 },
		func(r *Rule) { r.ReviewTTLSeconds = 10 }, func(r *Rule) { r.Effect = EffectBlock }} {
		r := warn
		edit(&r)
		if _, err := CanonicalRules([]Rule{r}); err == nil {
			t.Fatalf("invalid alert rule accepted: %+v", r)
		}
	}

	session, connection := "66666666-6666-4666-8666-666666666666", "77777777-7777-4777-8777-777777777777"
	at := time.Date(2026, 11, 7, 20, 0, 0, 0, time.UTC)
	d := Decision{ID: ActionID(session, connection, 3, 1, 1), SessionID: session, JobID: 3, Attempt: 1, Protocol: "postgres",
		Observation: Observation{ConnectionID: connection, Ordinal: 1, Phase: "query", Operations: []string{"GRANT"}, RuleIDs: []string{warn.ID},
			MessageDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		PolicyDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Status: StatusAlerted, Reason: "matched_alert_rule", ObservedAt: at, DecidedAt: at}
	if err := ValidateDecision(d); err != nil || !Permits(d.Status) {
		t.Fatalf("an alerted decision: %v", err)
	}
	deadline := at.Add(10 * time.Second)
	for _, edit := range []func(*Decision){func(d *Decision) { d.ReviewExpiresAt = &deadline }, func(d *Decision) { d.Reason = "matched_rule" }} {
		c := d
		edit(&c)
		if ValidateDecision(c) == nil {
			t.Fatalf("invalid alerted decision accepted: %+v", c)
		}
	}
	for _, status := range []string{StatusBlocked, StatusPending, StatusDenied, StatusExpired, StatusCanceled} {
		if Permits(status) {
			t.Fatalf("%s lets a command run", status)
		}
	}
}
