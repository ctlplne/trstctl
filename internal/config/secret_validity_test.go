// SPDX-License-Identifier: BUSL-1.1

package config

import "testing"

// P14: validity checks name only AWS, HTTPS endpoints and destinations, and a
// bounded rate.
func TestSecretValidityChecksValidateP14(t *testing.T) {
	good := SecretValidityChecks{Enabled: true, Endpoints: map[string]string{"aws": "https://sts.us-east-1.amazonaws.com"},
		Allowlist: []string{"https://sts.us-east-1.amazonaws.com"}, Rates: map[string]float64{"aws": 5}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]SecretValidityChecks{
		"another provider":       {Endpoints: map[string]string{"github": "https://api.github.com"}},
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
