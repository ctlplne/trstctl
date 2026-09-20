// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCustomConfigRuleCountIsMeasuredNotAssumed is the regression guard for
// scan evidence that reported a number nobody measured.
//
// rules_active is surfaced over the served API and documented as "an auditable
// floor for the real default scanner is active". When a custom config was in
// play the report still carried GitleaksDefaultRulesActive (213) — a count of the
// DEFAULT rule set, which a custom config replaces or extends. So a report could
// read custom_rules:true alongside rules_active:213 while five rules actually
// ran, and the 213 describes nothing that happened.
func TestCustomConfigRuleCountIsMeasuredNotAssumed(t *testing.T) {
	for _, tc := range []struct {
		name string
		toml string
		want int
	}{
		{
			name: "narrow custom config",
			toml: "title = \"narrow\"\n\n[[rules]]\nid = \"a\"\n\n[[rules]]\nid = \"b\"\n",
			want: 2,
		},
		{
			name: "config extending the defaults",
			toml: "[extend]\nuseDefault = true\n\n[[rules]]\nid = \"extra\"\n",
			want: GitleaksDefaultRulesActive + 1,
		},
		{
			name: "rules commented out do not count",
			toml: "[[rules]]\nid = \"real\"\n\n# [[rules]]\n# id = \"disabled\"\n",
			want: 1,
		},
		{
			name: "no rules at all",
			toml: "title = \"empty\"\n",
			want: 0,
		},
		{
			name: "useDefault false does not add the defaults",
			toml: "[extend]\nuseDefault = false\n\n[[rules]]\nid = \"only\"\n",
			want: 1,
		},
		{
			name: "indented rule headers still count",
			toml: "  [[rules]]\n  id = \"a\"\n\t[[rules]]\n\tid = \"b\"\n",
			want: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "gitleaks.toml")
			if err := os.WriteFile(path, []byte(tc.toml), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := countGitleaksRules(path)
			if err != nil {
				t.Fatalf("countGitleaksRules: %v", err)
			}
			if got != tc.want {
				t.Errorf("counted %d rules, want %d", got, tc.want)
			}
			if got == GitleaksDefaultRulesActive && tc.want != GitleaksDefaultRulesActive {
				t.Errorf("the count fell back to the default rule set (%d) instead of measuring the config",
					GitleaksDefaultRulesActive)
			}
		})
	}
}

// TestUnreadableConfigIsAnError keeps the counter from silently reporting zero —
// or worse, the default — for a config it could not read.
func TestUnreadableConfigIsAnError(t *testing.T) {
	if _, err := countGitleaksRules(filepath.Join(t.TempDir(), "does-not-exist.toml")); err == nil {
		t.Error("an unreadable config produced a rule count instead of an error")
	}
}
