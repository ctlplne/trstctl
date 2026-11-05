// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/accessrules"
)

func TestCommandBudgetReservesBeforeAllocationAndPreservesAnotherTarget(t *testing.T) {
	var budget commandBudget
	release, ok := budget.reserve("postgres", "one", commandTargetBytes, true)
	if !ok {
		t.Fatal("first target reservation refused")
	}
	if _, ok := budget.reserve("postgres", "one", 1, false); ok {
		t.Fatal("target byte bound exceeded")
	}
	other, ok := budget.reserve("postgres", "two", commandTargetBytes, true)
	if !ok {
		t.Fatal("one target starved another target")
	}
	if _, ok := budget.reserve("postgres", "three", 1, false); ok {
		t.Fatal("protocol byte bound exceeded")
	}
	independent, ok := budget.reserve("ssh", "one", 1, true)
	if !ok {
		t.Fatal("one protocol starved another")
	}
	independent()
	release()
	release()
	other()
	if len(budget.targetBytes) != 0 || len(budget.targetCalls) != 0 {
		t.Fatal("released targets retained budget entries")
	}
	var releases []func()
	for range commandTargetCalls {
		r, ok := budget.reserve("postgres", "one", 0, true)
		if !ok {
			t.Fatal("valid call refused")
		}
		releases = append(releases, r)
	}
	if _, ok := budget.reserve("postgres", "one", 0, true); ok {
		t.Fatal("target call bound exceeded")
	}
	r, ok := budget.reserve("postgres", "two", 0, true)
	if !ok {
		t.Fatal("call saturation starved another target")
	}
	r()
	for _, release := range releases {
		release()
	}
}

func TestPolicyCannotRideTheOldSessionJobKind(t *testing.T) {
	policy := &accessrules.Policy{Version: 1, TemplateID: "11111111-1111-4111-8111-111111111111", TemplateRevision: 2, Rules: []accessrules.PolicyRule{{ID: "22222222-2222-4222-8222-222222222222", Protocol: "postgres", Operations: []string{"DROP"}, Effect: accessrules.EffectBlock}}}
	if err := accessrules.ValidatePolicy(policy, "postgres"); err != nil {
		t.Fatal(err)
	}
	intent := SessionIntent{CommandPolicy: policy}
	if MatchesSessionJob(KindSession, intent) || !MatchesSessionJob(KindSessionRules, intent) {
		t.Fatal("policy kind fence lost")
	}
	if MatchesSessionJob(KindSessionRules, SessionIntent{}) || !MatchesSessionJob(KindSession, SessionIntent{}) {
		t.Fatal("ordinary sessions lost their old kind fence")
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	var older accessrules.Policy
	if err := json.Unmarshal(append(raw[:len(raw)-1], []byte(`,"future_authority":true}`)...), &older); err == nil {
		t.Fatal("unknown frozen authority was silently ignored")
	}
}
