// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// trstctlRuleFor names the trstctl rule each corpus format the pinned
// Gitleaks misses is caught by (P14-L4).
var trstctlRuleFor = map[string]string{ // #nosec G101 -- format and rule names, not credentials (CWE-798)
	"trstctl-api-token":                      "trstctl-api-token",
	"trstctl-opaque-access-token":            "trstctl-opaque-access-token",
	"trstctl-vault-wrapping-token":           "trstctl-vault-wrapping-token",
	"doppler-service-token":                  "trstctl-doppler-scoped-token",
	"doppler-service-account-token":          "trstctl-doppler-scoped-token",
	"doppler-cli-token":                      "trstctl-doppler-scoped-token",
	"doppler-scim-token":                     "trstctl-doppler-scoped-token",
	"doppler-audit-token":                    "trstctl-doppler-scoped-token",
	"infisical-service-token":                "trstctl-infisical-service-token",
	"bitwarden-secrets-manager-access-token": "trstctl-bitwarden-secrets-manager-access-token",
}

// TestTrstctlRulesMatchTheirFormatsAndNotTheirNeighborsP14L4: each trstctl
// rule compiles, matches its corpus samples, carries a keyword the sample
// holds (Gitleaks reads only text holding a keyword), and does not match
// near misses: a shorter value, the wrong alphabet, prose that starts the
// same way. Every rule covers some corpus format, and no rule ID is a
// Gitleaks one.
func TestTrstctlRulesMatchTheirFormatsAndNotTheirNeighborsP14L4(t *testing.T) {
	samples := map[string]string{}
	for _, c := range tokenCorpus() {
		samples[c.Name] = c.Sample
	}
	byID := map[string]trstctlRule{}
	for _, r := range trstctlRules {
		if !strings.HasPrefix(r.ID, "trstctl-") || r.Description == "" || len(r.Keywords) == 0 {
			t.Fatalf("rule %+v: a trstctl rule has a trstctl- ID, a description and keywords", r)
		}
		byID[r.ID] = r
	}
	covered := map[string]bool{}
	for format, id := range trstctlRuleFor {
		r, ok := byID[id]
		if !ok {
			t.Fatalf("%s: no rule %s", format, id)
		}
		covered[id] = true
		sample := samples[format]
		if sample == "" || !regexp.MustCompile(r.Regex).MatchString("value="+sample+"\n") {
			t.Fatalf("%s: rule %s does not match its sample", format, id)
		}
		if !slices.ContainsFunc(r.Keywords, func(k string) bool { return strings.Contains(strings.ToLower(sample), strings.ToLower(k)) }) {
			t.Fatalf("%s: the sample holds none of rule %s's keywords %v", format, id, r.Keywords)
		}
	}
	for id := range byID {
		if !covered[id] {
			t.Fatalf("rule %s covers no corpus format", id)
		}
	}
	for id, misses := range map[string][]string{
		"trstctl-api-token":                              {"trst_" + strings.Repeat("a", 20), "xtrst_" + strings.Repeat("Ab", 22)},
		"trstctl-vault-wrapping-token":                   {"trstw_" + strings.Repeat("0f", 31), "trstw_" + strings.Repeat("ZZ", 32)},
		"trstctl-opaque-access-token":                    {"trsto_" + strings.Repeat("a", 39)},
		"trstctl-doppler-scoped-token":                   {"dp.st." + strings.Repeat("a", 20), "dp.xx." + strings.Repeat("a", 43)},
		"trstctl-infisical-service-token":                {"st.louis.mo", "st." + strings.Repeat("a", 24) + "." + strings.Repeat("b", 32)},
		"trstctl-bitwarden-secrets-manager-access-token": {"0.5", "0." + strings.Repeat("a", 8) + "-0000-4000-8000-" + strings.Repeat("0", 12)},
	} {
		re := regexp.MustCompile(byID[id].Regex)
		for _, miss := range misses {
			if re.MatchString(miss) {
				t.Fatalf("rule %s matches the near miss %q", id, miss)
			}
		}
	}
	fragment := string(trstctlRulesFragment())
	if strings.Count(fragment, "[[rules]]") != TrstctlRulesActive || countCustomRuleTables([]byte(fragment)) != TrstctlRulesActive ||
		strings.Contains(fragment, "[extend]") || strings.Contains(strings.ToLower(fragment), "allowlist") {
		t.Fatalf("the fragment is not %d plain rule tables:\n%s", TrstctlRulesActive, fragment)
	}
}

// pinnedGitleaks is the pinned Gitleaks binary, or the test is skipped where
// none is installed (it fails where TRSTCTL_GITLEAKS_BIN names one that is not
// the pinned version).
func pinnedGitleaks(t *testing.T) string {
	t.Helper()
	bin, err := NewGitleaksRunner("").resolveBinary()
	if err == nil {
		out, verr := exec.Command(bin, "version").Output() // #nosec G204 -- the resolved gitleaks binary, asked only its version (CWE-78)
		if verr == nil && strings.TrimPrefix(strings.TrimSpace(string(out)), "v") == strings.TrimPrefix(GitleaksPinnedVersion, "v") {
			return bin
		}
		err = errorString("not the pinned version: " + strings.TrimSpace(string(out)))
	}
	if strings.TrimSpace(os.Getenv("TRSTCTL_GITLEAKS_BIN")) != "" {
		t.Fatalf("TRSTCTL_GITLEAKS_BIN does not name the pinned Gitleaks %s: %v", GitleaksPinnedVersion, err)
	}
	t.Skipf("P14-L4 runs the pinned Gitleaks %s; run tools/gitleaks/install.sh or set TRSTCTL_GITLEAKS_BIN (%v)", GitleaksPinnedVersion, err)
	return ""
}

type errorString string

func (e errorString) Error() string { return string(e) }

// TestPinnedGitleaksAloneAndWithTrstctlRulesOverTheTokenCorpusP14L4 is
// P14-L4's Done-when: the pinned Gitleaks alone, over a corpus of the token
// formats trstctl needs to catch, misses exactly the formats trstctl's own
// rules cover (if a later release catches one, or misses another, this says
// which); a scan through the runner, which carries those rules through the
// custom-rules path, catches every format, the missed ones by their trstctl
// rule, and reports the rules it ran; an operator's custom rules still add
// to them.
func TestPinnedGitleaksAloneAndWithTrstctlRulesOverTheTokenCorpusP14L4(t *testing.T) {
	bin := pinnedGitleaks(t)
	dir := t.TempDir()
	for _, c := range tokenCorpus() {
		if err := os.WriteFile(filepath.Join(dir, c.Name+".env"), []byte("value="+c.Sample+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// Alone: the pinned binary with its defaults and nothing else.
	report := filepath.Join(t.TempDir(), "alone.json")
	out, err := exec.Command(bin, "dir", "--no-banner", "--exit-code", "0", "--report-format", "json", // #nosec G204 -- the pinned gitleaks over this test's own temp corpus (CWE-78)
		"--report-path", report, dir).CombinedOutput()
	if err != nil {
		t.Fatalf("gitleaks alone: %v %s", err, out)
	}
	raw, err := os.ReadFile(report) // #nosec G304 -- the report this test asked gitleaks to write (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	var alone []struct{ RuleID, File string }
	if err := json.Unmarshal(raw, &alone); err != nil {
		t.Fatal(err)
	}
	caughtAlone := map[string]bool{}
	for _, f := range alone {
		caughtAlone[strings.TrimSuffix(filepath.Base(f.File), ".env")] = true
	}
	var missed []string
	for _, c := range tokenCorpus() {
		_, ours := trstctlRuleFor[c.Name]
		switch {
		case !caughtAlone[c.Name] && !ours:
			t.Fatalf("the pinned Gitleaks misses %s and no trstctl rule covers it", c.Name)
		case caughtAlone[c.Name] && ours:
			t.Fatalf("the pinned Gitleaks now catches %s by itself; its trstctl rule can go", c.Name)
		case !caughtAlone[c.Name]:
			missed = append(missed, c.Name)
		}
	}
	t.Logf("P14L4_ALONE gitleaks %s alone misses %d of %d formats: %v", GitleaksPinnedVersion, len(missed), len(tokenCorpus()), missed)

	// Through the runner: the defaults and trstctl's rules.
	runner := NewGitleaksRunner(bin)
	runner.AllowedRoots = []string{dir}
	got, err := runner.ScanWithOptions(context.Background(), dir, ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rules := map[string][]string{}
	for _, f := range got.Findings {
		name := strings.TrimSuffix(filepath.Base(f.File), ".env")
		rules[name] = append(rules[name], f.RuleID)
	}
	for _, c := range tokenCorpus() {
		if len(rules[c.Name]) == 0 {
			t.Fatalf("the scan misses %s", c.Name)
		}
		if id, ours := trstctlRuleFor[c.Name]; ours && !slices.Contains(rules[c.Name], id) {
			t.Fatalf("%s is caught by %v, not by %s", c.Name, rules[c.Name], id)
		}
	}
	if got.RulesActive != GitleaksDefaultRulesActive+TrstctlRulesActive || got.CustomRules {
		t.Fatalf("the scan reports %d rules (custom %v), want %d: the defaults and trstctl's %d", got.RulesActive, got.CustomRules,
			GitleaksDefaultRulesActive+TrstctlRulesActive, TrstctlRulesActive)
	}
	findingsJSON, err := json.Marshal(got.Findings)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range tokenCorpus() {
		if strings.Contains(string(findingsJSON), c.Sample) {
			t.Fatalf("a finding carries the %s value", c.Name)
		}
	}

	// An operator's custom rules still add to them.
	custom := filepath.Join(dir, "custom-rules.toml")
	if err := os.WriteFile(custom, []byte("[[rules]]\nid = \"operator-rule\"\nregex = '''operator-[0-9]{6}'''\nkeywords = [\"operator-\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "operator.env"), []byte("value=operator-123456\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = runner.ScanWithOptions(context.Background(), dir, ScanOptions{CustomRulesPath: custom})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, f := range got.Findings {
		ids[f.RuleID] = true
	}
	if !ids["operator-rule"] || !ids["trstctl-api-token"] || got.RulesActive != GitleaksDefaultRulesActive+TrstctlRulesActive+1 || !got.CustomRules {
		t.Fatalf("with custom rules: %d rules (custom %v), rule IDs %v", got.RulesActive, got.CustomRules, ids)
	}

	// A repository's own config, which Gitleaks reads by itself, is
	// extended, not replaced: its allowlist holds and trstctl's rules apply.
	repo := t.TempDir()
	for _, c := range tokenCorpus() {
		if err := os.WriteFile(filepath.Join(repo, c.Name+".env"), []byte("value="+c.Sample+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	repoConfig := "[extend]\nuseDefault = true\n\n[allowlist]\npaths = ['" + `trstctl-api-token\.env` + "']\n"
	if err := os.WriteFile(filepath.Join(repo, ".gitleaks.toml"), []byte(repoConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	runner.AllowedRoots = []string{repo}
	got, err = runner.ScanWithOptions(context.Background(), repo, ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]bool{}
	for _, f := range got.Findings {
		files[strings.TrimSuffix(filepath.Base(f.File), ".env")] = true
	}
	if files["trstctl-api-token"] || !files["trstctl-vault-wrapping-token"] || !files["infisical-service-token"] ||
		got.RulesActive != GitleaksDefaultRulesActive+TrstctlRulesActive {
		t.Fatalf("with the repository's own config: %d rules, files %v; want its allowlist kept and trstctl's rules applied", got.RulesActive, files)
	}
	t.Log("P14L4_OK")
}
