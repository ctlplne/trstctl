// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqcmigration

import (
	"context"
	"reflect"
	"testing"

	"trstctl.com/trstctl/internal/cbom"
)

func vulnCred(id string, ct CredentialType, alg string) Credential {
	return Credential{AssetID: id, IdentityID: "spiffe://d/" + id, Type: ct, Algorithm: alg, QuantumVulnerable: true, Protocol: ProtocolACME}
}

// TestBuildSuccessionJobs_TargetAndPolicyRef: a quantum-vulnerable asset yields a
// succession job carrying the correct target + effective algorithm and a non-empty
// policy_ref equal to the digest of the job's recorded decision (acceptance 1).
func TestBuildSuccessionJobs_TargetAndPolicyRef(t *testing.T) {
	jobs, _, err := BuildSuccessionJobs(context.Background(),
		[]Credential{vulnCred("asset-rsa", CredentialX509, "RSA")}, StaticDecider{Posture: PostureClassicalToHybrid})
	if err != nil {
		t.Fatalf("BuildSuccessionJobs: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("jobs = %d, want 1", len(jobs))
	}
	j := jobs[0]
	if j.TargetAlgorithm != TargetMLDSA65 || j.EffectiveAlgorithm != EffectiveHybridTLS {
		t.Fatalf("target/effective = %q/%q, want %q/%q", j.TargetAlgorithm, j.EffectiveAlgorithm, TargetMLDSA65, EffectiveHybridTLS)
	}
	if j.PolicyRef == "" {
		t.Fatal("empty policy_ref")
	}
	if j.PolicyRef != PolicyRef(j.Decision) {
		t.Fatalf("job policy_ref %q != digest of recorded decision %q", j.PolicyRef, PolicyRef(j.Decision))
	}
	if !j.Decision.Allow || j.Decision.TargetAlgorithm != TargetMLDSA65 {
		t.Fatalf("recorded decision not aligned with job: %+v", j.Decision)
	}
}

// TestPolicyRef_Reproducible: an auditor recomputes the same policy_ref from the
// recorded decision, and any change to any decision field changes the ref
// (acceptance 2).
func TestPolicyRef_Reproducible(t *testing.T) {
	jobs, _, err := BuildSuccessionJobs(context.Background(),
		[]Credential{vulnCred("a1", CredentialX509, "RSA")}, StaticDecider{})
	if err != nil {
		t.Fatal(err)
	}
	d := jobs[0].Decision

	// Recompute from the recorded decision alone — must match, repeatably.
	if got := PolicyRef(d); got != jobs[0].PolicyRef {
		t.Fatalf("recompute %q != job %q", got, jobs[0].PolicyRef)
	}
	if PolicyRef(d) != PolicyRef(d) {
		t.Fatal("policy_ref is not stable across recomputation")
	}

	// Every field is bound: mutating any one changes the ref.
	base := PolicyRef(d)
	for name, mut := range map[string]func(*Decision){
		"target":    func(x *Decision) { x.TargetAlgorithm = "ML-DSA-87" },
		"effective": func(x *Decision) { x.EffectiveAlgorithm = "changed" },
		"identity":  func(x *Decision) { x.IdentityID = "other" },
		"predAlg":   func(x *Decision) { x.PredecessorAlg = "ECDSA" },
		"allow":     func(x *Decision) { x.Allow = !x.Allow },
		"module":    func(x *Decision) { x.PolicyModuleSHA256 = "deadbeef" },
		"posture":   func(x *Decision) { x.Posture = "other" },
		"credtype":  func(x *Decision) { x.CredentialType = CredentialSSH },
	} {
		cp := d
		mut(&cp)
		if PolicyRef(cp) == base {
			t.Fatalf("policy_ref did not change when %s changed", name)
		}
	}
}

// TestBuildSuccessionJobs_Idempotent: the same inputs yield identical jobs and
// residuals in the same order (acceptance 3).
func TestBuildSuccessionJobs_Idempotent(t *testing.T) {
	creds := []Credential{
		vulnCred("a1", CredentialX509, "RSA"),
		vulnCred("a2", CredentialSSH, "ECDSA"),
		{AssetID: "a3", Type: CredentialSecret, Algorithm: "RSA", QuantumVulnerable: false}, // residual
	}
	j1, r1, err := BuildSuccessionJobs(context.Background(), creds, StaticDecider{})
	if err != nil {
		t.Fatal(err)
	}
	j2, r2, err := BuildSuccessionJobs(context.Background(), creds, StaticDecider{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(j1, j2) {
		t.Fatal("jobs are not deterministic across identical runs")
	}
	if !reflect.DeepEqual(r1, r2) {
		t.Fatal("residuals are not deterministic across identical runs")
	}
	if len(j1) != 2 {
		t.Fatalf("jobs = %d, want 2", len(j1))
	}
}

// TestIdentityTypes_X509_SSH_SVID_Token_Secret: every member of the claim-9
// identity/credential genus maps to a plannable succession job (claim 9).
func TestIdentityTypes_X509_SSH_SVID_Token_Secret(t *testing.T) {
	genus := PlannableCredentialTypes()
	if len(genus) != 5 {
		t.Fatalf("plannable genus size = %d, want 5", len(genus))
	}
	var creds []Credential
	for i, ct := range genus {
		creds = append(creds, vulnCred(string(rune('a'+i)), ct, "RSA"))
	}
	jobs, _, err := BuildSuccessionJobs(context.Background(), creds, StaticDecider{})
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != len(genus) {
		t.Fatalf("plannable jobs = %d, want %d (one per credential type)", len(jobs), len(genus))
	}
	seen := map[CredentialType]bool{}
	for _, j := range jobs {
		if j.TargetAlgorithm == "" || j.PolicyRef == "" {
			t.Fatalf("credential type %q did not yield a plannable succession: %+v", j.CredentialType, j)
		}
		seen[j.CredentialType] = true
	}
	for _, ct := range genus {
		if !seen[ct] {
			t.Fatalf("credential type %q was not planned", ct)
		}
	}

	// A credential type outside the genus is an explicit residual, never a silent drop.
	_, residuals, err := BuildSuccessionJobs(context.Background(),
		[]Credential{{AssetID: "x", Type: CredentialType("kerberos"), Algorithm: "RSA", QuantumVulnerable: true}}, StaticDecider{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasResidual(residuals, "x", "not_planned") {
		t.Fatal("an out-of-genus credential must surface as a not_planned residual")
	}
}

// TestSuccessionJobs_PolicyGate_OPA: the OPA-backed decider (internal/policy,
// consumed read-only) authorizes an allowed succession and denies a policy-vetoed
// one, which becomes a residual. This exercises the real policy engine.
func TestSuccessionJobs_PolicyGate_OPA(t *testing.T) {
	// Deny successions whose target is not ML-DSA-65; allow otherwise.
	module := `package trstctl.policy

default allow := false
default reason := ""

allow if {
	input.action == "issue"
	input.attrs.target_algorithm == "ML-DSA-65"
}

reason := "target algorithm not authorized" if {
	input.action == "issue"
	input.attrs.target_algorithm != "ML-DSA-65"
}
`
	dec, err := NewPolicyDecider(module, PostureClassicalToHybrid)
	if err != nil {
		t.Fatalf("NewPolicyDecider: %v", err)
	}
	jobs, residuals, err := BuildSuccessionJobs(context.Background(),
		[]Credential{vulnCred("ok", CredentialX509, "RSA")}, dec)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || !jobs[0].Decision.Allow {
		t.Fatalf("expected one authorized job, got %d jobs / residuals %+v", len(jobs), residuals)
	}
	if jobs[0].Decision.PolicyModuleSHA256 == "" {
		t.Fatal("policy decision did not bind the policy module identity")
	}

	// A module that denies the succession yields no job, only a policy_denied residual.
	denyAll, err := NewPolicyDecider(`package trstctl.policy
default allow := false
default reason := "denied for test"
`, PostureClassicalToHybrid)
	if err != nil {
		t.Fatal(err)
	}
	jobs2, residuals2, err := BuildSuccessionJobs(context.Background(),
		[]Credential{vulnCred("blocked", CredentialX509, "RSA")}, denyAll)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs2) != 0 {
		t.Fatalf("policy-denied credential still produced %d jobs", len(jobs2))
	}
	if !hasResidual(residuals2, "blocked", "policy_denied") {
		t.Fatalf("policy-denied credential must be a policy_denied residual: %+v", residuals2)
	}
}

// TestSuccessionJobs_HybridToPurePQCSeam: the hybrid→pure-PQC posture relaxes the
// effective leaf to a pure ML-DSA-65 deployment while keeping the same key target
// (the seam whose cutover is gated by PCAS-10).
func TestSuccessionJobs_HybridToPurePQCSeam(t *testing.T) {
	jobs, _, err := BuildSuccessionJobs(context.Background(),
		[]Credential{vulnCred("h1", CredentialX509, "ECDSA-P256+ML-DSA-65")}, StaticDecider{Posture: PostureHybridToPurePQC})
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 {
		t.Fatalf("jobs = %d, want 1", len(jobs))
	}
	if jobs[0].TargetAlgorithm != TargetMLDSA65 || jobs[0].EffectiveAlgorithm != "ML-DSA-65" {
		t.Fatalf("pure-PQC seam target/effective = %q/%q, want %q/ML-DSA-65", jobs[0].TargetAlgorithm, jobs[0].EffectiveAlgorithm, TargetMLDSA65)
	}
}

// TestCredentialsFromPlan_BridgesReissues: a BuildPlan result bridges into X.509
// credentials that then plan as succession jobs — the wiring that replaces bare
// reissues with succession jobs.
func TestCredentialsFromPlan_BridgesReissues(t *testing.T) {
	plan, err := BuildPlan([]Asset{{
		ID: "asset-rsa", Kind: string(cbom.AssetCertKey), Algorithm: "RSA", KeyBits: 2048,
		QuantumVulnerable: true, Reasons: []string{"RSA is quantum-vulnerable"},
	}}, Request{AssetIDs: []string{"asset-rsa"}, TargetAlgorithm: TargetMLDSA65, Protocol: ProtocolACME, RollbackOnFailure: true})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	creds := CredentialsFromPlan(plan, func(id string) string { return "spiffe://d/" + id })
	if len(creds) != 1 || creds[0].Type != CredentialX509 || creds[0].IdentityID != "spiffe://d/asset-rsa" {
		t.Fatalf("bridged credentials wrong: %+v", creds)
	}
	jobs, _, err := BuildSuccessionJobs(context.Background(), creds, StaticDecider{})
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].IdentityID != "spiffe://d/asset-rsa" || jobs[0].RollbackOnFailure != true {
		t.Fatalf("job from bridged plan wrong: %+v", jobs)
	}
}

func hasResidual(rs []Residual, id, status string) bool {
	for _, r := range rs {
		if r.ID == id && r.Status == status {
			return true
		}
	}
	return false
}
