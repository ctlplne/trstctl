// SPDX-License-Identifier: BUSL-1.1

package policy_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/policy"
)

const nhiPostureOAuthModule = policy.BaseModule + `
nhi_posture contains {"rule": "abusive-oauth-revoke", "severity": "critical", "reason": "abusive grants are revoked", "remediation": "revoke_oauth_grant"} if {
	input.action == "nhi_posture"
	"malicious_oauth_grant" in input.nhi.finding_types
}

nhi_posture contains {"rule": "okta-abuse-block", "severity": "critical", "reason": "abusive Okta apps are blocked", "remediation": "block_oauth_app"} if {
	input.action == "nhi_posture"
	"oauth_abuse" in input.nhi.posture
	input.nhi.provider == "okta"
}
`

// A170-L3: an nhi_posture rule may ask to revoke a discovered OAuth grant or
// block its application at the provider, and may name the provider; both
// remediations stay in the closed set, and a certificate rule cannot ask for
// them.
func TestNHIPostureRulesMayAskToRevokeOrBlockAnOAuthGrantA170L3(t *testing.T) {
	ctx := context.Background()
	engine, err := policy.New(policy.Config{Module: nhiPostureOAuthModule})
	if err != nil {
		t.Fatal(err)
	}
	in := policy.Input{Action: policy.ActionNHIPosture, TenantID: "t1", NHI: &policy.NHIFacts{
		InventoryID: "finding/11111111-1111-1111-1111-111111111111", Kind: "oauth_grant_abuse", Source: "discovery_finding",
		Status: "open", Posture: []string{"oauth_abuse"}, Provider: "okta",
		FindingTypes: []string{"malicious_oauth_grant", "provider_threat_signal"}, Severity: "critical", RiskScore: 95,
	}}
	violations, err := engine.EvaluateNHIPosture(ctx, in)
	if err != nil || len(violations) != 2 {
		t.Fatalf("violations = %+v err=%v; want both rules", violations, err)
	}
	want := map[string]string{"abusive-oauth-revoke": policy.PostureRemediationRevokeOAuthGrant,
		"okta-abuse-block": policy.PostureRemediationBlockOAuthApp}
	for _, v := range violations {
		if r, ok := want[v.Rule]; !ok || v.Remediation != r {
			t.Fatalf("violation %+v; want remediation %q", v, r)
		}
	}
	in.NHI.Provider = "google"
	violations, err = engine.EvaluateNHIPosture(ctx, in)
	if err != nil || len(violations) != 1 || violations[0].Rule != "abusive-oauth-revoke" {
		t.Fatalf("a Google grant matched %+v (%v); the block rule names Okta only", violations, err)
	}
	cert, err := policy.New(policy.Config{Module: policy.BaseModule + `
certificate_posture contains {"rule": "revoke-grant", "remediation": "revoke_oauth_grant"} if { input.action == "certificate_posture" }
`})
	if err != nil {
		t.Fatal(err)
	}
	if violations, err := cert.EvaluatePosture(ctx, policy.Input{Action: policy.ActionCertificatePosture, TenantID: "t1",
		Certificate: &policy.CertificateFacts{Subject: "CN=x"}}); err != nil || len(violations) != 1 || violations[0].Remediation != "" {
		t.Fatalf("certificate posture = %+v (%v); revoke_oauth_grant is not a certificate remediation", violations, err)
	}
}
