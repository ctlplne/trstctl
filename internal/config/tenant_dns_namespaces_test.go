// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/tenantnames"
)

func TestCR042OperatorTenantDNSNamespacesRejectAmbiguousOrMalformedGrants(t *testing.T) {
	const a = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	const b = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	for _, tc := range []struct {
		name   string
		grants tenantnames.Grants
		want   string
	}{
		{"overlap", tenantnames.Grants{a: {"example.test"}, b: {"payments.example.test"}}, "overlap"},
		{"bad suffix", tenantnames.Grants{a: {"*.example.test"}}, "invalid suffix"},
		{"noncanonical tenant", tenantnames.Grants{strings.ToUpper(a): {"example.test"}}, "canonical tenant UUID"},
		{"distinct", tenantnames.Grants{a: {"apps.example.test"}, b: {"payments.example.test"}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			errs := validateGovernanceConfig(&Config{CA: CA{TenantDNSNamespaces: tc.grants}})
			joined := make([]string, 0, len(errs))
			for _, err := range errs {
				joined = append(joined, err.Error())
			}
			got := strings.Join(joined, "; ")
			if tc.want == "" && got != "" || tc.want != "" && !strings.Contains(got, tc.want) {
				t.Fatalf("namespace validation = %q, want %q", got, tc.want)
			}
		})
	}
}
