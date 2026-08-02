// SPDX-License-Identifier: MPL-2.0

package docs

// Intake guards (AH-2cfeb7f0). README.md and CONTRIBUTING.md both tell a reader to
// open an issue, and SECURITY.md tells them a vulnerability must NOT become one.
// Both instructions are only enforceable at the moment of filing, which is
// .github/ISSUE_TEMPLATE/. These guards lock that surface: the two forms stay
// parseable GitHub issue forms that require what a maintainer needs to reproduce or
// judge a report, blank issues stay disabled so nothing can be filed off-form, the
// security contact link keeps routing vulnerabilities at SECURITY.md, and
// CODE_OF_CONDUCT.md stays the Contributor Covenant with an enforcement address that
// has not drifted from the one SECURITY.md publishes.
//
// Helper `read` is defined in docs/docs_test.go and reused here.

import (
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// issueForm is the subset of GitHub's issue-form schema these guards assert on.
type issueForm struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Body        []struct {
		Type        string `yaml:"type"`
		ID          string `yaml:"id"`
		Validations struct {
			Required bool `yaml:"required"`
		} `yaml:"validations"`
	} `yaml:"body"`
}

// issueIntakeConfig is the subset of .github/ISSUE_TEMPLATE/config.yml asserted on.
type issueIntakeConfig struct {
	BlankIssuesEnabled bool `yaml:"blank_issues_enabled"`
	ContactLinks       []struct {
		Name  string `yaml:"name"`
		URL   string `yaml:"url"`
		About string `yaml:"about"`
	} `yaml:"contact_links"`
}

// securityContactPattern extracts the maintainer address SECURITY.md publishes, so
// the code of conduct's enforcement address can be compared against it rather than
// hard-coded twice.
var securityContactPattern = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)

// TestIssueIntakeFormsRequireWhatAMaintainerNeeds locks the two intake forms: each
// stays a parseable issue form with a name and description (GitHub renders both in
// the template chooser), every field carries an id, and the fields without which a
// report cannot be acted on stay REQUIRED. A form that has drifted into all-optional
// fields is the same unactionable free-text box it replaced.
func TestIssueIntakeFormsRequireWhatAMaintainerNeeds(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		file     string
		required []string
	}{
		{"../.github/ISSUE_TEMPLATE/bug_report.yml", []string{"version", "what-happened", "repro"}},
		{"../.github/ISSUE_TEMPLATE/feature_request.yml", []string{"problem", "proposal", "tree"}},
	} {
		var form issueForm
		if err := yaml.Unmarshal([]byte(read(t, tc.file)), &form); err != nil {
			t.Errorf("%s is not a parseable GitHub issue form: %v", tc.file, err)
			continue
		}
		if strings.TrimSpace(form.Name) == "" || strings.TrimSpace(form.Description) == "" {
			t.Errorf("%s must keep both a name and a description; GitHub shows them in the template chooser", tc.file)
		}
		required := map[string]bool{}
		for _, item := range form.Body {
			if item.Type == "markdown" {
				continue // static guidance, correctly has no id
			}
			if item.ID == "" {
				t.Errorf("%s has a %q field with no id; ids are what make a form answer addressable", tc.file, item.Type)
				continue
			}
			if item.Validations.Required {
				required[item.ID] = true
			}
		}
		for _, id := range tc.required {
			if !required[id] {
				t.Errorf("%s must keep field %q REQUIRED; without it a report arrives unactionable", tc.file, id)
			}
		}
	}
}

// TestIssueIntakeConfigRoutesVulnerabilitiesAwayFromPublicIssues locks the
// security-routing half of the intake surface: blank issues stay disabled, and a
// contact link keeps pointing a would-be vulnerability reporter at SECURITY.md
// before they can open a public issue. SECURITY.md's own instruction is asserted
// too, because the link only earns its keep while that sentence stands.
func TestIssueIntakeConfigRoutesVulnerabilitiesAwayFromPublicIssues(t *testing.T) {
	t.Parallel()

	raw := read(t, "../.github/ISSUE_TEMPLATE/config.yml")
	// Asserted literally as well as after parsing: an ABSENT key also unmarshals to
	// false, so the parsed check alone would pass on a file that never disabled them.
	if !strings.Contains(raw, "blank_issues_enabled: false") {
		t.Error("config.yml must keep `blank_issues_enabled: false`; a blank issue is the path around every routing decision below")
	}

	var cfg issueIntakeConfig
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("config.yml is not parseable YAML: %v", err)
	}
	if cfg.BlankIssuesEnabled {
		t.Error("config.yml re-enabled blank issues; a vulnerability could then be filed publicly on an empty form")
	}

	routed := false
	for _, link := range cfg.ContactLinks {
		if strings.TrimSpace(link.Name) == "" || strings.TrimSpace(link.About) == "" {
			t.Errorf("contact link %q must keep a name and an about; GitHub renders both", link.URL)
		}
		if strings.Contains(link.URL, "SECURITY.md") {
			routed = true
		}
	}
	if !routed {
		t.Error("config.yml must keep a contact_link whose url points at SECURITY.md; that link is what a reporter sees instead of the new-issue form")
	}

	if !strings.Contains(read(t, "../SECURITY.md"), "do not open a public GitHub issue") {
		t.Error("SECURITY.md no longer tells reporters not to open a public issue; the contact link this guard pins exists to enforce exactly that sentence")
	}
}

// TestCodeOfConductIsTheContributorCovenant locks CODE_OF_CONDUCT.md as the adopted
// Contributor Covenant 2.1 rather than a bespoke rewrite: the pledge, standards,
// responsibilities, scope, enforcement, the four-rung impact ladder, and the
// attribution the licence requires must all still be there, and the upstream
// placeholder must be gone.
func TestCodeOfConductIsTheContributorCovenant(t *testing.T) {
	t.Parallel()

	coc := read(t, "../CODE_OF_CONDUCT.md")
	for _, want := range []string{
		"# Contributor Covenant Code of Conduct",
		"## Our Pledge",
		"## Our Standards",
		"## Enforcement Responsibilities",
		"## Scope",
		"## Enforcement",
		"## Enforcement Guidelines",
		"### 1. Correction",
		"### 2. Warning",
		"### 3. Temporary Ban",
		"### 4. Permanent Ban",
		"## Attribution",
		"[Contributor Covenant][homepage]",
		"version 2.1",
		"https://www.contributor-covenant.org/version/2/1/code_of_conduct.html",
	} {
		if !strings.Contains(coc, want) {
			t.Errorf("CODE_OF_CONDUCT.md no longer contains %q; it is adopted verbatim, so a missing section means it was rewritten", want)
		}
	}
	if strings.Contains(coc, "INSERT CONTACT METHOD") {
		t.Error("CODE_OF_CONDUCT.md still carries the Contributor Covenant contact placeholder; an unreachable enforcement address is worse than none")
	}
}

// TestCodeOfConductEnforcementAddressMatchesSecurityPolicy is the anti-drift half:
// the code of conduct must reuse the address SECURITY.md already publishes. Two
// independently-maintained contact addresses is how a report reaches nobody.
func TestCodeOfConductEnforcementAddressMatchesSecurityPolicy(t *testing.T) {
	t.Parallel()

	contacts := securityContactPattern.FindAllString(read(t, "../SECURITY.md"), -1)
	if len(contacts) == 0 {
		t.Fatal("SECURITY.md no longer publishes a maintainer email address; revisit this guard")
	}
	coc := read(t, "../CODE_OF_CONDUCT.md")
	for _, contact := range contacts {
		if strings.Contains(coc, contact) {
			return
		}
	}
	t.Errorf("CODE_OF_CONDUCT.md must name an address SECURITY.md already publishes (%v); a second, separately-maintained contact drifts silently", contacts)
}
