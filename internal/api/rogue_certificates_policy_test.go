// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/policy"
	"trstctl.com/trstctl/internal/store"
)

// Tenant posture violations become rogue-certificate findings (A42): one
// finding per certificate, policy rules appended to the built-in checks, the
// severity raised to the strongest rule, and the evidence naming the module.
func TestRoguePostureAppliesTenantPolicyViolations(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	notBefore, notAfter := now.Add(-time.Hour), now.Add(30*24*time.Hour)
	owner := "owner-1"
	cert := store.Certificate{ID: "cert-1", Subject: "CN=api.example.test", Issuer: "CN=Internal CA", Fingerprint: "ab", KeyAlgorithm: "ECDSA-P256",
		NotBefore: &notBefore, NotAfter: &notAfter, OwnerID: &owner, Status: "active", Source: "trstctl"}
	facts := rogueCertificateFacts(cert, now)
	if facts.Issuer != "CN=Internal CA" || facts.LifetimeDays != 30 || facts.DaysUntilExpiry != 30 || facts.OwnerID != "owner-1" || facts.KeyAlgorithm != "ECDSA-P256" {
		t.Fatalf("facts = %+v", facts)
	}
	var out rogueCertificatePostureResponse
	out.Findings = []rogueCertificateFinding{}
	// A compliant certificate with one policy violation gets a policy-only finding.
	out.applyRoguePolicyViolations(cert, nil, []policy.PostureViolation{{Rule: "vendor-ca-forbidden", Severity: "high", Reason: "not sanctioned"}}, "sha-1")
	if len(out.Findings) != 1 || out.Findings[0].FindingTypes[0] != "customer_policy:vendor-ca-forbidden" || out.Findings[0].Severity != "high" ||
		out.Findings[0].PolicyStatus != "non_compliant" || len(out.Findings[0].PolicyViolations) != 1 || out.Summary.PolicyViolations != 1 {
		t.Fatalf("policy-only finding = %+v summary=%+v", out.Findings, out.Summary)
	}
	if refs := out.Findings[0].EvidenceRefs; len(refs) == 0 || refs[len(refs)-1] != "policy:module:sha-1" {
		t.Fatalf("policy evidence missing: %v", refs)
	}
	// A certificate that already has a built-in finding gets the rules merged
	// and its severity raised to the strongest.
	existing := rogueCertificateFinding{ID: "certificate:cert-2", CertificateID: "cert-2", FindingTypes: []string{"owner_missing"}, Severity: "low", RiskScore: 20, PolicyStatus: "non_compliant"}
	out.applyRoguePolicyViolations(store.Certificate{ID: "cert-2"}, &existing, []policy.PostureViolation{{Rule: "key-too-small", Severity: "critical", Reason: "2048-bit RSA"}}, "sha-1")
	if existing.Severity != "critical" || existing.RiskScore < 90 || len(existing.FindingTypes) != 2 || out.Summary.PolicyViolations != 2 {
		t.Fatalf("merged finding = %+v summary=%+v", existing, out.Summary)
	}
	// Unknown severities fall back to medium rather than being dropped.
	out.applyRoguePolicyViolations(store.Certificate{ID: "cert-3"}, nil, []policy.PostureViolation{{Rule: "odd", Severity: "whatever"}}, "sha-1")
	if out.Findings[len(out.Findings)-1].Severity != "medium" {
		t.Fatalf("unknown severity = %q, want medium", out.Findings[len(out.Findings)-1].Severity)
	}
}
