// SPDX-License-Identifier: BUSL-1.1

package policy_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/policy"
)

const nhiPostureModule = policy.BaseModule + `
nhi_posture contains {"rule": "dormant-managed-revoke", "severity": "high", "reason": "dormant managed NHIs are revoked", "remediation": "revoke"} if {
	input.action == "nhi_posture"
	input.nhi.managed
	"dormant_activity" in input.nhi.finding_types
}

nhi_posture contains {"rule": "unused-scopes-trim", "severity": "medium", "reason": "unused grants are removed", "remediation": "right_size"} if {
	input.action == "nhi_posture"
	count(input.nhi.unused_scopes) > 0
}

nhi_posture contains {"rule": "typo-remediation", "reason": "an unknown remediation is reported but never acted on", "remediation": "delete_everything"} if {
	input.action == "nhi_posture"
	input.nhi.kind == "api_key"
}
`

// A100: a tenant's lifecycle module may declare nhi_posture rules over one NHI
// inventory row's posture; a rule may ask for one of a closed set of automatic
// remediations (revoke, right_size). Anything else is reported but asks for
// nothing. Modules without the rule, including the boot module, report nothing.
func TestNHIPostureRulesAreOptInAndAskOnlyForKnownRemediations(t *testing.T) {
	ctx := context.Background()
	engine, err := policy.New(policy.Config{Module: nhiPostureModule})
	if err != nil {
		t.Fatal(err)
	}
	in := policy.Input{Action: policy.ActionNHIPosture, TenantID: "t1", NHI: &policy.NHIFacts{
		InventoryID: "identity/11111111-1111-1111-1111-111111111111", Kind: "api_key", Source: "managed_identity",
		Managed: true, Status: "deployed", Posture: []string{"stale", "overprivilege"},
		FindingTypes: []string{"dormant_activity", "excessive_scope"}, UnusedScopes: []string{"admin:*"},
	}}
	violations, err := engine.EvaluateNHIPosture(ctx, in)
	if err != nil || len(violations) != 3 {
		t.Fatalf("violations = %+v err=%v; want three rules", violations, err)
	}
	want := map[string]string{"dormant-managed-revoke": policy.PostureRemediationRevoke,
		"typo-remediation": "", "unused-scopes-trim": policy.PostureRemediationRightSize}
	for _, v := range violations {
		if r, ok := want[v.Rule]; !ok || v.Remediation != r {
			t.Fatalf("violation %+v; want remediation %q", v, r)
		}
	}
	in.NHI.Managed, in.NHI.Kind, in.NHI.UnusedScopes = false, "service_account", nil
	if violations, err := engine.EvaluateNHIPosture(ctx, in); err != nil || len(violations) != 0 {
		t.Fatalf("an unmanaged row without unused grants reported %+v (%v)", violations, err)
	}
	base, err := policy.New(policy.Config{Module: policy.BaseModule})
	if err != nil {
		t.Fatal(err)
	}
	in.NHI.Managed = true
	if violations, err := base.EvaluateNHIPosture(ctx, in); err != nil || len(violations) != 0 {
		t.Fatalf("the boot module reported %+v (%v); NHI posture must be opt-in", violations, err)
	}
	if _, err := engine.EvaluateNHIPosture(ctx, policy.Input{Action: policy.ActionNHIPosture, TenantID: "t1"}); err == nil {
		t.Fatal("an NHI posture evaluation without NHI facts was accepted")
	}
	// A certificate rule's remediation set does not leak into NHI posture, and
	// an NHI remediation does not ask a certificate rule to act.
	cert, err := policy.New(policy.Config{Module: policy.BaseModule + `
certificate_posture contains {"rule": "revoke-me", "remediation": "revoke"} if { input.action == "certificate_posture" }
`})
	if err != nil {
		t.Fatal(err)
	}
	if violations, err := cert.EvaluatePosture(ctx, policy.Input{Action: policy.ActionCertificatePosture, TenantID: "t1",
		Certificate: &policy.CertificateFacts{Subject: "CN=x"}}); err != nil || len(violations) != 1 || violations[0].Remediation != "" {
		t.Fatalf("certificate posture = %+v (%v); revoke is not a certificate remediation", violations, err)
	}
}

// The workbench previews an nhi_posture rule against sample facts.
func TestNHIPostureDryRunReportsViolations(t *testing.T) {
	res, err := policy.DryRun(context.Background(), policy.DryRunConfig{Kind: policy.DryRunKindLifecycle, Module: nhiPostureModule,
		Input: map[string]any{
			"action": "nhi_posture", "tenant_id": "t1",
			"nhi": map[string]any{"kind": "service_account", "managed": true, "finding_types": []any{"dormant_activity"}},
		}})
	if err != nil || !res.Valid || !res.Deny || len(res.Violations) != 1 || res.Violations[0].Rule != "dormant-managed-revoke" ||
		res.Violations[0].Remediation != policy.PostureRemediationRevoke {
		t.Fatalf("dry run = %+v err=%v", res, err)
	}
	if _, err := policy.DryRun(context.Background(), policy.DryRunConfig{Kind: policy.DryRunKindLifecycle, Module: nhiPostureModule,
		Input: map[string]any{"action": "nhi_posture", "tenant_id": "t1"}}); err == nil {
		t.Fatal("a dry run without input.nhi was accepted")
	}
}
