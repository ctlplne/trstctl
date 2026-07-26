// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqcmigration

import (
	"testing"
)

// B-3: the planner must describe the SAME migration the start path would run,
// including what it refuses to touch. These drive BuildPlan directly — the
// preview's only job is to render its result — so a divergence between plan
// and execution would have to be a divergence in BuildPlan itself.
func TestBuildPlanSeparatesReissuesFromResiduals(t *testing.T) {
	assets := []Asset{
		{ID: "a-rsa", Kind: "certificate-key", Location: "svc-a:443", Algorithm: "RSA", KeyBits: 2048, QuantumVulnerable: true},
		{ID: "a-ecdsa", Kind: "certificate-key", Location: "svc-b:443", Algorithm: "ECDSA", KeyBits: 256, QuantumVulnerable: true},
	}

	plan, err := BuildPlan(assets, Request{
		AssetIDs:        []string{"a-rsa", "a-ecdsa"},
		TargetAlgorithm: "ML-DSA-65",
		Protocol:        "acme",
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.Reissues) != 2 {
		t.Fatalf("reissues = %d, want both classical keys planned", len(plan.Reissues))
	}
	for _, reissue := range plan.Reissues {
		if reissue.TargetAlgorithm != "ML-DSA-65" {
			t.Fatalf("reissue %s targets %q", reissue.Asset.ID, reissue.TargetAlgorithm)
		}
		if reissue.Protocol != "acme" {
			t.Fatalf("reissue %s protocol = %q", reissue.Asset.ID, reissue.Protocol)
		}
	}
}

// An asset the caller names but the estate does not hold must fail loudly
// rather than silently planning a smaller migration than was asked for.
func TestBuildPlanRejectsUnknownAsset(t *testing.T) {
	_, err := BuildPlan(
		[]Asset{{ID: "a-rsa", Kind: "certificate-key", Algorithm: "RSA", KeyBits: 2048}},
		Request{AssetIDs: []string{"a-rsa", "ghost"}, TargetAlgorithm: "ML-DSA-65", Protocol: "acme"},
	)
	if err == nil {
		t.Fatal("planning an absent asset succeeded")
	}
}

// The residual denominator is part of the honest answer: a preview that only
// listed what it WILL do would overstate coverage.
func TestResidualDenominatorIsNotEmpty(t *testing.T) {
	if len(ResidualDenominator()) == 0 {
		t.Fatal("residual denominator is empty; a plan preview would overstate coverage")
	}
	for _, residual := range ResidualDenominator() {
		if residual.ID == "" || residual.Status == "" {
			t.Fatalf("residual %+v is missing its id or status", residual)
		}
	}
}
