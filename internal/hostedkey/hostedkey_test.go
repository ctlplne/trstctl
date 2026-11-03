// SPDX-License-Identifier: BUSL-1.1

package hostedkey

import (
	"strings"
	"testing"
)

// A240: each hosted API key provider's role binding names the target its keys
// are created under and the least authority they get there; the canonical
// form is what a revocation reference carries, so a binding never parses to
// two shapes.
func TestBindingsParseToOneCanonicalTargetA240(t *testing.T) {
	for _, tc := range []struct{ provider, binding, want string }{
		{"openrouter", "unlimited", "unlimited"},
		{"openrouter", "limit 25", "limit-25"},
		{"openrouter", "limit  2.50", "limit-2.5"},
		{"fireworks", "acme/ci-bot", "acme:ci-bot"},
		{"litellm", "all-models", "all-models"},
		{"litellm", "models openai/gpt-4o,claude-sonnet", "models:openai/gpt-4o,claude-sonnet"},
		{"supabase", "abcdefghijklmnopqrst", "abcdefghijklmnopqrst"},
		{"convex", "happy-animal-123", "happy-animal-123"},
		{"convex", "happy-animal-123 deployment:deploy,deployment:env:view", "happy-animal-123:deployment:deploy,deployment:env:view"},
		{"dbt", "70403 job_runner", "70403:job_runner"},
		{"dbt", " 70403 developer project 12 ", "70403:developer:12"},
		{"cloudflare", "template 0123456789abcdef0123456789abcdef", "user:0123456789abcdef0123456789abcdef"},
		{"cloudflare", "account fedcba9876543210fedcba9876543210 template 0123456789abcdef0123456789abcdef", "account:fedcba9876543210fedcba9876543210:0123456789abcdef0123456789abcdef"},
		{"cloudflare-r2", "account fedcba9876543210fedcba9876543210 template 0123456789abcdef0123456789abcdef", "account:fedcba9876543210fedcba9876543210:0123456789abcdef0123456789abcdef"},
		{"okta", "0oa1b2c3d4e5f6g7h8i9", "0oa1b2c3d4e5f6g7h8i9"},
		{"databricks", "a1b2c3d4-0000-4000-8000-0123456789ab 4471234567890123", "a1b2c3d4-0000-4000-8000-0123456789ab:4471234567890123"},
	} {
		got, err := ParseBinding(tc.provider, tc.binding)
		if err != nil || got != tc.want {
			t.Errorf("%s %q = %q, %v; want %q", tc.provider, tc.binding, got, err, tc.want)
		}
	}
}

func TestBindingsRefuseWhatTheVendorCannotScopeA240(t *testing.T) {
	for _, tc := range []struct{ provider, binding string }{
		{"openrouter", "limit 0"},
		{"openrouter", "limit -5"},
		{"openrouter", "limit 1000001"},
		{"openrouter", "limit"},
		{"openrouter", "25"},
		{"fireworks", "acme"},
		{"fireworks", "acme/ci-bot/extra"},
		{"fireworks", "Acme/ci-bot"},
		{"litellm", "models"},
		{"litellm", "models gpt-4o,"},
		{"litellm", "models gpt 4o"},
		{"supabase", "abcdefghijklmnopqrs"},
		{"supabase", "ABCDEFGHIJKLMNOPQRST"},
		{"convex", ""},
		{"convex", "happy-animal-123 admin"},
		{"convex", "Happy-Animal"},
		{"dbt", "70403"},
		{"dbt", "70403 superuser"},
		{"dbt", "070403 job_runner"},
		{"dbt", "70403 job_runner project"},
		{"dbt", "70403 job_runner folder 12"},
		{"cloudflare", "template 0123456789abcdef0123456789abcde"},
		{"cloudflare", "template 0123456789ABCDEF0123456789ABCDEF"},
		{"cloudflare", "account fedcba9876543210fedcba9876543210 0123456789abcdef0123456789abcdef"},
		{"cloudflare-r2", "template 0123456789abcdef0123456789abcdef"},
		{"okta", "1oa1b2c3d4e5f6g7h8i9"},
		{"okta", "0oa1b2/c3d4"},
		{"databricks", "a1b2c3d4-0000-4000-8000-0123456789ab"},
		{"databricks", "not-a-uuid 44712"},
		{"databricks", "a1b2c3d4-0000-4000-8000-0123456789ab sp-1"},
		{"unknown", "anything"},
	} {
		if got, err := ParseBinding(tc.provider, tc.binding); err == nil {
			t.Errorf("%s %q parsed to %q", tc.provider, tc.binding, got)
		}
	}
}

// Every provider documents its endpoint, its administrator credential and its
// binding, which configuration errors and the catalog quote.
func TestEveryProviderDescribesItsConfigurationA240(t *testing.T) {
	types := Types()
	if len(types) != len(Providers) || strings.Join(types, ",") != "cloudflare,cloudflare-r2,convex,databricks,dbt,fireworks,litellm,okta,openrouter,supabase" {
		t.Fatalf("types = %v", types)
	}
	for name, spec := range Providers {
		if spec.Endpoint == "" || spec.AdminKey == "" || spec.Binding == "" || spec.parse == nil {
			t.Errorf("%s is missing a description or its parser", name)
		}
	}
}

func TestNumericIDsAreCanonicalA240(t *testing.T) {
	for v, want := range map[string]bool{"1": true, "70403": true, "0": false, "-1": false, "07": false, "1e3": false, "": false} {
		if NumericID(v) != want {
			t.Errorf("NumericID(%q) = %v", v, !want)
		}
	}
}
