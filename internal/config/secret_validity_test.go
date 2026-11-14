// SPDX-License-Identifier: BUSL-1.1

package config

import "testing"

// P14: validity checks name only known providers (AWS's alone before P14-L1),
// HTTPS endpoints and destinations, and a bounded rate.
func TestSecretValidityChecksValidateP14(t *testing.T) {
	good := SecretValidityChecks{Enabled: true, Endpoints: map[string]string{"aws": "https://sts.us-east-1.amazonaws.com"},
		Allowlist: []string{"https://sts.us-east-1.amazonaws.com"}, Rates: map[string]float64{"aws": 5}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]SecretValidityChecks{
		"an unknown provider":    {Endpoints: map[string]string{"bitbucket": "https://api.bitbucket.org"}},
		"a plaintext endpoint":   {Endpoints: map[string]string{"aws": "http://sts.amazonaws.com"}},
		"a path in an allowlist": {Allowlist: []string{"https://sts.amazonaws.com/x"}},
		"a plaintext allowlist":  {Allowlist: []string{"http://sts.amazonaws.com"}},
		"an unbounded rate":      {Rates: map[string]float64{"aws": 1000}},
		"no rate":                {Rates: map[string]float64{"aws": 0}},
	} {
		if err := bad.Validate(); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// P14-L1: the providers whose checks run are named, each known provider at
// most once, and every known provider may have its own endpoint and rate (a
// GitHub Enterprise Server's /api/v3 base included).
func TestSecretValidityChecksNameTheirProvidersP14L1(t *testing.T) {
	good := SecretValidityChecks{Enabled: true, Providers: []string{"aws", "github", "gitlab", "slack", "azure", "gcp"},
		Endpoints: map[string]string{"github": "https://ghe.example.test/api/v3", "gitlab": "https://gitlab.example.test",
			"azure": "https://login.microsoftonline.us", "gcp": "https://oauth2.googleapis.com", "slack": "https://slack.com"},
		Allowlist: []string{"https://ghe.example.test", "https://gitlab.example.test"},
		Rates:     map[string]float64{"github": 10, "slack": 1, "gcp": 2}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]SecretValidityChecks{
		"an unknown provider":         {Providers: []string{"aws", "bitbucket"}},
		"a provider named twice":      {Providers: []string{"github", "github"}},
		"a plaintext GitHub endpoint": {Endpoints: map[string]string{"github": "http://ghe.example.test/api/v3"}},
		"an endpoint with a query":    {Endpoints: map[string]string{"gitlab": "https://gitlab.example.test/?x=1"}},
		"an unknown provider's rate":  {Rates: map[string]float64{"jira": 1}},
		"an unbounded Slack rate":     {Rates: map[string]float64{"slack": 101}},
	} {
		if err := bad.Validate(); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}
