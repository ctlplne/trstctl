// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"fmt"
	"strings"
)

// trstctlRule is a trstctl-owned scanning rule (P14-L4): a credential format
// trstctl needs a scan to catch that the pinned Gitleaks' default rules miss.
// Every scan carries these rules through the custom-rules path, extending
// the defaults; their IDs start with "trstctl-", so they never collide with a
// Gitleaks rule.
type trstctlRule struct {
	ID          string
	Description string
	Regex       string
	Keywords    []string
}

// trstctlRules are the formats the pinned Gitleaks (v8.27.2) misses in the
// token corpus (token_corpus_test.go): trstctl's own credentials and the
// tokens of the secret stores it integrates with.
var trstctlRules = []trstctlRule{
	{ID: "trstctl-api-token", Description: "trstctl API token",
		Regex: `\btrst_[A-Za-z0-9_-]{43}`, Keywords: []string{"trst_"}},
	{ID: "trstctl-opaque-access-token", Description: "trstctl opaque access token",
		Regex: `\btrsto_[A-Za-z0-9_-]{40,}`, Keywords: []string{"trsto_"}},
	{ID: "trstctl-vault-wrapping-token", Description: "trstctl Vault-compatible response-wrapping token",
		Regex: `\btrstw_[0-9a-f]{64}`, Keywords: []string{"trstw_"}},
	{ID: "trstctl-doppler-scoped-token", Description: "Doppler service, service account, CLI, SCIM or audit token",
		Regex:    `\bdp\.(?:st|sa|ct|scim|audit)\.(?:[a-z0-9_-]{1,64}\.)?[A-Za-z0-9]{40,64}\b`,
		Keywords: []string{"dp.st.", "dp.sa.", "dp.ct.", "dp.scim.", "dp.audit."}},
	{ID: "trstctl-infisical-service-token", Description: "Infisical service token",
		Regex: `\bst\.[0-9a-f]{24}\.[0-9a-f]{32}\.[0-9a-f]{32}\b`, Keywords: []string{"st."}},
	{ID: "trstctl-bitwarden-secrets-manager-access-token", Description: "Bitwarden Secrets Manager machine account access token",
		Regex:    `\b0\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[A-Za-z0-9]{30}:[A-Za-z0-9+/]{22}==`,
		Keywords: []string{"0."}},
}

// TrstctlRulesActive is how many trstctl-owned rules every scan adds to the
// pinned defaults.
var TrstctlRulesActive = len(trstctlRules)

// trstctlRulesFragment is the rules as a Gitleaks config fragment of [[rules]]
// tables, the same shape an operator's custom rules take.
func trstctlRulesFragment() []byte {
	var b strings.Builder
	b.WriteString("# trstctl-owned rules (P14-L4): formats the pinned Gitleaks' defaults miss.\n")
	for _, r := range trstctlRules {
		quoted := make([]string, 0, len(r.Keywords))
		for _, k := range r.Keywords {
			quoted = append(quoted, fmt.Sprintf("%q", k))
		}
		fmt.Fprintf(&b, "\n[[rules]]\nid = %q\ndescription = %q\nregex = '''%s'''\nkeywords = [%s]\n",
			r.ID, r.Description, r.Regex, strings.Join(quoted, ", "))
	}
	return []byte(b.String())
}
