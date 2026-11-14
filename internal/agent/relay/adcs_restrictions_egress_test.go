// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/netsec"
)

// A229-L1 Done-when: before the Windows CA-policy read hands a directory-named
// CA to certutil, which connects outside the Go dialer's guard, the CA host is
// checked against this agent's egress policy. Cloud metadata and link-local
// hosts are refused always; with an allowlist, a CA outside it is refused and
// one inside it is read; a refusal leaves the evidence unobserved, never
// enabled or disabled.
func TestCARestrictionsReadChecksTheEgressPolicyA229L1(t *testing.T) {
	t.Cleanup(func() { SetEgressPolicy(nil) })
	SetEgressPolicy(nil)
	ctx := context.Background()
	check := func(host string) (adcs.EnrollmentAgentRestrictions, bool) {
		return caRestrictionsEgress(ctx, adcs.EnrollmentService{Name: "CORP-CA", DNSName: host})
	}
	for _, host := range []string{"169.254.169.254", "fe80::1", "0.0.0.0"} {
		if got, allowed := check(host); allowed || got.State != adcs.EvidenceUnobserved || got.Source != "egress_refused" {
			t.Fatalf("CA host %s with no allowlist = %+v %t; want refused", host, got, allowed)
		}
	}
	if _, allowed := check("10.30.1.5"); !allowed {
		t.Fatal("a private CA host was refused with no allowlist configured")
	}
	if got, allowed := check(""); allowed || got.Source != "ca_identity_unobserved" {
		t.Fatalf("a CA with no host = %+v %t", got, allowed)
	}
	policy, err := netsec.ParseRelayEgress([]string{"10.20.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	SetEgressPolicy(policy)
	if got, allowed := check("10.30.1.5"); allowed || got.Source != "egress_refused" {
		t.Fatalf("a CA outside the allowlist = %+v %t; want refused", got, allowed)
	}
	if _, allowed := check("10.20.1.5"); !allowed {
		t.Fatal("a CA inside the allowlist was refused")
	}
}
