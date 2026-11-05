// SPDX-License-Identifier: BUSL-1.1

package accessrules

import (
	"reflect"
	"testing"
)

func TestRulesAreBoundedPublicConfiguration(t *testing.T) {
	good := Rule{ID: "11111111-1111-4111-8111-111111111111", Name: "Refuse destructive SQL", Enabled: true, Protocol: "postgres", Operations: []string{"truncate", "DROP", "DROP"}, Effect: EffectBlock}
	got, err := CanonicalRules([]Rule{good})
	if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0].Operations, []string{"DROP", "TRUNCATE"}) {
		t.Fatalf("canonical rules = %+v, %v", got, err)
	}
	if !reflect.DeepEqual(good.Operations, []string{"truncate", "DROP", "DROP"}) {
		t.Fatal("validation mutated caller-owned configuration")
	}
	p := ForTarget("22222222-2222-4222-8222-222222222222", 3, got, "postgres")
	if err := ValidatePolicy(p, "postgres"); err != nil {
		t.Fatal(err)
	}
	if ids := Match(p, []string{"SELECT", "TRUNCATE"}); len(ids) != 1 || ids[0] != good.ID {
		t.Fatalf("matched identifiers = %v", ids)
	}
	if ids := Match(p, []string{"untrusted-word-must-not-be-evidence"}); len(ids) != 0 {
		t.Fatalf("unknown word matched = %v", ids)
	}
	if ForTarget(p.TemplateID, 3, got, "ssh") != nil {
		t.Fatal("other protocol received rules")
	}
	got[0].Operations[0] = "ALTER"
	if p.Rules[0].Operations[0] != "DROP" {
		t.Fatal("frozen policy aliases an editable rule")
	}
	for _, change := range []struct {
		name string
		edit func(*Rule)
	}{
		{"unknown protocol", func(r *Rule) { r.Protocol = "unimplemented" }},
		{"unimplemented effect", func(r *Rule) { r.Effect = "require_approval" }},
		{"unknown operation", func(r *Rule) { r.Operations = []string{"not-a-verb"} }},
		{"no operations", func(r *Rule) { r.Operations = nil }},
		{"invalid id", func(r *Rule) { r.ID = "" }},
		{"control name", func(r *Rule) { r.Name = "name\nnext" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			r := good
			change.edit(&r)
			if _, err := CanonicalRules([]Rule{r}); err == nil {
				t.Fatal("invalid rule accepted")
			}
		})
	}
	if _, err := CanonicalRules([]Rule{good, good}); err == nil {
		t.Fatal("duplicate UUID accepted")
	}
	if _, err := CanonicalRules(make([]Rule, MaxRules+1)); err == nil {
		t.Fatal("unbounded rules accepted")
	}
	p.Version++
	if ValidatePolicy(p, "postgres") == nil {
		t.Fatal("unknown policy version accepted")
	}
}
