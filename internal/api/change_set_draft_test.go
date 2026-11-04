// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"strings"
	"testing"
)

// A248: the model's answer is read strictly as a change set — the first JSON
// object in it, fenced or not; anything else, or an unknown field, is no
// change set at all.
func TestDraftedChangeSetIsReadStrictly(t *testing.T) {
	cs, err := draftedChangeSet("Here you go:\n```json\n{\"name\":\"onboard\",\"members\":[{\"subject\":\"dev@x.example\",\"roles\":[\"viewer\"]}]}\n```\nDone.")
	if err != nil || cs.Name != "onboard" || len(cs.Members) != 1 || cs.Members[0].Roles[0] != "viewer" {
		t.Fatalf("fenced draft = %+v, %v", cs, err)
	}
	for _, answer := range []string{
		"I cannot help with that.",
		`{"name":"x","secret_values":["nope"]}`,
		`{"name":"x","members":[{"subject":"a","roles":["viewer"],"password":"p"}]}`,
	} {
		if _, err := draftedChangeSet(answer); err == nil {
			t.Fatalf("%q was read as a change set", answer)
		}
	}
}

// A248: the prompt carries the instruction, the change set's shape, the
// catalog's names in a fixed order, and the request — nothing else.
func TestDraftPromptCarriesNamesAndTheRequestOnly(t *testing.T) {
	prompt := draftPrompt(map[string][]string{
		"roles":    {"auditor", "viewer"},
		"profiles": {"web"},
		"owners":   {"platform (team)"},
	}, "onboard the billing team")
	for _, want := range []string{"owners: platform (team)\nprofiles: web\nroles: auditor, viewer\n", "Request: onboard the billing team\n",
		"Never write a secret value", "never with a pattern"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("the prompt lacks %q:\n%s", want, prompt)
		}
	}
	if strings.Index(prompt, "owners:") > strings.Index(prompt, "roles:") {
		t.Fatal("the catalog's kinds are not in a fixed order")
	}
}
