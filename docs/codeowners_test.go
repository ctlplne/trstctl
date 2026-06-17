package docs

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// criticalCodeownerPaths are the security-critical trees that MUST have an explicit
// owner in CODEOWNERS (TEST-006): the AN-3 crypto boundary, the AN-4 isolated
// signer (logic + binary + proto contract), the AN-1 multi-tenant store, and the
// architecture linter that enforces the guardrails in CI. A compromise or silent
// weakening of any of these is, per AGENTS.md, "the company is over," so a change to
// them must require a code-owner review (with require_code_owner_reviews enabled —
// see docs/branch-protection.md). The pattern in CODEOWNERS may be broader than the
// path (e.g. `/internal/crypto/` covers `internal/crypto/seal/`), so we match by
// pattern-prefix, not string equality.
var criticalCodeownerPaths = []string{
	"internal/crypto/",
	"internal/signing/",
	"internal/signing/proto/",
	"cmd/trstctl-signer/",
	"internal/store/",
	"tools/trstctllint/",
}

// codeownerRule is one parsed CODEOWNERS line: a path pattern and its owners.
type codeownerRule struct {
	pattern string
	owners  []string
}

// parseCodeowners reads .github/CODEOWNERS into rules, skipping blanks/comments.
func parseCodeowners(t *testing.T) []codeownerRule {
	t.Helper()
	f, err := os.Open(filepath.FromSlash("../.github/CODEOWNERS"))
	if err != nil {
		t.Fatalf("a CODEOWNERS file must exist at .github/CODEOWNERS (TEST-006): %v", err)
	}
	defer func() { _ = f.Close() }()

	var rules []codeownerRule
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			// A pattern with no owner is meaningless (and unsets ownership in GitHub);
			// reject it so the file cannot silently leave a path unowned.
			t.Errorf("CODEOWNERS line %q has a pattern but no owner", line)
			continue
		}
		var owners []string
		for _, o := range fields[1:] {
			if !strings.HasPrefix(o, "@") && !strings.Contains(o, "@") {
				t.Errorf("CODEOWNERS owner %q on line %q is not a @handle or email", o, line)
			}
			owners = append(owners, o)
		}
		rules = append(rules, codeownerRule{pattern: fields[0], owners: owners})
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return rules
}

// ownerFor returns the owners of the LAST CODEOWNERS rule whose pattern matches the
// given path (last-match-wins, like GitHub). A leading-slash, dir-style pattern
// `/p/` matches any path under `p/`.
func ownerFor(rules []codeownerRule, path string) []string {
	var owners []string
	for _, r := range rules {
		pat := strings.TrimPrefix(r.pattern, "/")
		switch {
		case pat == "*":
			owners = r.owners // catch-all
		case strings.HasSuffix(pat, "/"):
			if strings.HasPrefix(path, pat) || path == strings.TrimSuffix(pat, "/") {
				owners = r.owners
			}
		default:
			if path == pat || strings.HasPrefix(path, pat) {
				owners = r.owners
			}
		}
	}
	return owners
}

// TestCodeownersCoversSecurityCriticalPaths is the TEST-006 reality-test: a
// CODEOWNERS file exists and assigns a non-empty owner to every security-critical
// path, with an explicit (non-catch-all) rule for each — so the root of trust
// cannot merge without a code-owner review and the ownership is provable from the
// repository. The referenced trees must also still exist (the rule is anchored in
// real code, not stale).
func TestCodeownersCoversSecurityCriticalPaths(t *testing.T) {
	rules := parseCodeowners(t)
	if len(rules) == 0 {
		t.Fatal("CODEOWNERS parsed to zero rules")
	}

	// A catch-all (`*`) owner must exist so nothing is unowned by default.
	if owners := ownerFor(rules, "some/random/path.go"); len(owners) == 0 {
		t.Error("CODEOWNERS should have a catch-all `*` owner so no path is unowned")
	}

	explicit := map[string]bool{}
	for _, r := range rules {
		if r.pattern != "*" {
			explicit[strings.TrimPrefix(r.pattern, "/")] = true
		}
	}

	for _, p := range criticalCodeownerPaths {
		// The path must resolve to a non-empty owner.
		if owners := ownerFor(rules, p); len(owners) == 0 {
			t.Errorf("CODEOWNERS leaves the security-critical path %q unowned (TEST-006)", p)
		}
		// And it must be covered by an EXPLICIT rule, not just the catch-all — the
		// root of trust gets named ownership, not a default.
		if !explicit[p] {
			t.Errorf("CODEOWNERS must have an explicit (non-catch-all) owner rule for %q (TEST-006)", p)
		}
		// The tree it owns must exist, anchoring the rule in real code.
		clean := strings.TrimSuffix(p, "/")
		if _, err := os.Stat(filepath.FromSlash("../" + clean)); err != nil {
			t.Errorf("CODEOWNERS owns %q but the path does not exist; revisit this rule: %v", p, err)
		}
	}
}
