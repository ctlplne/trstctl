// SPDX-License-Identifier: MPL-2.0

package spiffe

import "testing"

func TestRegistrationCannotClaimAutomaticWorkloadNamespace(t *testing.T) {
	issuer := testIssuer(t)
	for _, id := range []string{"spiffe://example.org/_trstctl", "spiffe://example.org/_trstctl/v1/tenant/other/attested/method/k8s_sat/subject/web"} {
		_, err := New(Config{Issuer: issuer, TenantID: "t1", Entries: []RegistrationEntry{{SPIFFEID: id, Selectors: []string{"unix:uid:1000"}}}})
		if err == nil {
			t.Errorf("manual registration can bypass automatic tenant/attestation policy for %q", id)
		}
	}
	if _, err := New(Config{Issuer: issuer, TenantID: "t1", Entries: []RegistrationEntry{{SPIFFEID: "spiffe://example.org/ns/prod/service"}}}); err != nil {
		t.Fatalf("ordinary operator registration no longer works: %v", err)
	}
}
