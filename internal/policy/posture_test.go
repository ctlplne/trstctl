// SPDX-License-Identifier: BUSL-1.1

package policy_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/policy"
)

const postureModule = policy.BaseModule + `
certificate_posture contains {"rule": "vendor-ca-forbidden", "severity": "high", "reason": "leaves from the vendor CA are not sanctioned"} if {
	input.action == "certificate_posture"
	input.certificate.issuer == "CN=Untrusted Vendor CA"
}

certificate_posture contains {"rule": "short-lived-only", "severity": "medium", "reason": "production leaves must live 90 days or less"} if {
	input.action == "certificate_posture"
	input.certificate.lifetime_days > 90
}
`

// Tenant posture rules (A42): a module may declare certificate_posture
// violations over inventory facts; modules without the rule, including the
// boot module, report nothing rather than denying everything.
func TestCertificatePostureRulesAreOptInAndReportEachViolation(t *testing.T) {
	ctx := context.Background()
	engine, err := policy.New(policy.Config{Module: postureModule})
	if err != nil {
		t.Fatal(err)
	}
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	in := policy.Input{Action: policy.ActionCertificatePosture, TenantID: "t1", Certificate: &policy.CertificateFacts{
		Subject: "CN=api.example.test", Issuer: "CN=Untrusted Vendor CA", KeyAlgorithm: "ECDSA-P256",
		NotBefore: &notBefore, LifetimeDays: 397, Status: "active", Source: "import",
	}}
	violations, err := engine.EvaluatePosture(ctx, in)
	if err != nil || len(violations) != 2 {
		t.Fatalf("violations = %+v err=%v; want the vendor and lifetime rules", violations, err)
	}
	if violations[0].Rule != "short-lived-only" || violations[1].Rule != "vendor-ca-forbidden" || violations[1].Severity != "high" || violations[1].Reason == "" {
		t.Fatalf("violations are not sorted by rule with their severity and reason: %+v", violations)
	}
	in.Certificate.Issuer, in.Certificate.LifetimeDays = "CN=Internal CA", 30
	if violations, err := engine.EvaluatePosture(ctx, in); err != nil || len(violations) != 0 {
		t.Fatalf("a compliant certificate reported %+v (%v)", violations, err)
	}
	base, err := policy.New(policy.Config{Module: policy.BaseModule})
	if err != nil {
		t.Fatal(err)
	}
	in.Certificate.Issuer = "CN=Untrusted Vendor CA"
	if violations, err := base.EvaluatePosture(ctx, in); err != nil || len(violations) != 0 {
		t.Fatalf("the boot module without posture rules reported %+v (%v); posture must be opt-in", violations, err)
	}
	if _, err := engine.EvaluatePosture(ctx, policy.Input{Action: policy.ActionIssue, TenantID: "t1"}); err == nil {
		t.Fatal("a posture evaluation without certificate facts was accepted")
	}

	live, err := policy.NewLive(policy.Config{Module: policy.BaseModule})
	if err != nil {
		t.Fatal(err)
	}
	_, info, _, err := live.PrepareModule(postureModule)
	if err != nil {
		t.Fatal(err)
	}
	live.SetModuleResolver(func(_ context.Context, tenant string) (string, policy.ModuleInfo, error) {
		if tenant == "t1" {
			return postureModule, info, nil
		}
		return policy.BaseModule, func() policy.ModuleInfo { _, i := live.BootModule(); return i }(), nil
	})
	if violations, err := live.EvaluatePosture(ctx, in); err != nil || len(violations) != 1 || violations[0].Rule != "vendor-ca-forbidden" {
		t.Fatalf("live tenant posture = %+v (%v)", violations, err)
	}
	in.TenantID = "t2"
	if violations, err := live.EvaluatePosture(ctx, in); err != nil || len(violations) != 0 {
		t.Fatalf("another tenant inherited t1's posture rules: %+v (%v)", violations, err)
	}

	result, err := policy.DryRun(ctx, policy.DryRunConfig{Kind: policy.DryRunKindLifecycle, Module: postureModule, Input: map[string]any{
		"action": "certificate_posture", "tenant_id": "t1",
		"certificate": map[string]any{"issuer": "CN=Untrusted Vendor CA", "lifetime_days": 30},
	}})
	if err != nil || !result.Valid || len(result.Violations) != 1 || result.Violations[0].Rule != "vendor-ca-forbidden" || !result.Deny {
		t.Fatalf("dry run = %+v err=%v; want the vendor violation", result, err)
	}
}

// A47: a rule may ask for a remediation; only "renew" is recognized, so a
// typo or an invented action never queues work.
func TestCertificatePostureRemediationIsReadOnlyForRenew(t *testing.T) {
	ctx := context.Background()
	engine, err := policy.New(policy.Config{Module: policy.BaseModule + `
certificate_posture contains {"rule": "renew-me", "severity": "high", "reason": "replace", "remediation": "renew"} if {
	input.action == "certificate_posture"
	input.certificate.source == "import"
}
certificate_posture contains {"rule": "typo", "severity": "low", "reason": "typo", "remediation": "renw"} if {
	input.action == "certificate_posture"
	input.certificate.source == "import"
}
certificate_posture contains {"rule": "silent", "severity": "low", "reason": "no action"} if {
	input.action == "certificate_posture"
	input.certificate.source == "import"
}
`})
	if err != nil {
		t.Fatal(err)
	}
	violations, err := engine.EvaluatePosture(ctx, policy.Input{Action: policy.ActionCertificatePosture, TenantID: "t1",
		Certificate: &policy.CertificateFacts{Subject: "CN=x", Source: "import", Status: "active"}})
	if err != nil || len(violations) != 3 {
		t.Fatalf("violations = %+v err=%v", violations, err)
	}
	got := map[string]string{}
	for _, v := range violations {
		got[v.Rule] = v.Remediation
	}
	if got["renew-me"] != policy.PostureRemediationRenew || got["typo"] != "" || got["silent"] != "" {
		t.Fatalf("remediations = %v; want only renew-me to carry renew", got)
	}
}
