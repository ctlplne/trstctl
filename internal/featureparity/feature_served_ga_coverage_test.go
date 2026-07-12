// SPDX-License-Identifier: MPL-2.0

package featureparity

import (
	"strings"
	"testing"
)

const (
	gaServedScopeIn  = "in_ga"
	gaServedScopeOut = "out_of_ga"
)

var residualServedStates = map[string]bool{
	"conditional": true,
	"partial":     true,
	"library":     true,
	"roadmap":     true,
}

func requireResidualServedState(t *testing.T, trace string, item Item, want string) {
	t.Helper()
	if item.ServedState != want {
		t.Fatalf("%s: %s must be classified %s, got served_state=%q", trace, item.FeatureID, want, item.ServedState)
	}
	if item.GAServedScope != gaServedScopeOut {
		t.Fatalf("%s: residual %s must be outside the GA served denominator, got ga_served_scope=%q", trace, item.FeatureID, item.GAServedScope)
	}
	if !strings.Contains(strings.ToLower(item.GAScopeReason), "residual") {
		t.Fatalf("%s: residual %s must carry an explicit residual reason, got %q", trace, item.FeatureID, item.GAScopeReason)
	}
}

// TestFeatureServedGACoverageCOVER001 locks the COVER-001 acceptance:
// the GA served denominator must be 100% served. Rows that remain conditional
// or partial must be explicitly out of GA scope, with a human-readable reason,
// so the catalog does not count residual capability as fully GA-served.
func TestFeatureServedGACoverageCOVER001(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	gaRows := 0
	gaServedRows := 0
	for _, item := range catalog.Items {
		scope := strings.TrimSpace(item.GAServedScope)
		if scope == "" {
			scope = gaServedScopeIn
		}

		switch {
		case item.ServedState == "served":
			if scope == gaServedScopeOut {
				t.Errorf("%s (%s) is served but excluded from the GA served denominator", item.FeatureID, item.Feature)
				continue
			}
			if scope != gaServedScopeIn {
				t.Errorf("%s (%s) has invalid ga_served_scope %q", item.FeatureID, item.Feature, item.GAServedScope)
				continue
			}
			if reason := strings.TrimSpace(item.GAScopeReason); reason != "" {
				t.Errorf("%s (%s) is served and must not carry a residual GA reason, got %q", item.FeatureID, item.Feature, reason)
				continue
			}
			gaRows++
			gaServedRows++
		case residualServedStates[item.ServedState]:
			if scope != gaServedScopeOut {
				t.Errorf("%s (%s) served_state=%s must set ga_served_scope=%q or be promoted to served", item.FeatureID, item.Feature, item.ServedState, gaServedScopeOut)
			}
			reason := strings.TrimSpace(item.GAScopeReason)
			if len(strings.Fields(reason)) < 6 {
				t.Errorf("%s (%s) must explain why the residual row is out of GA scope, got %q", item.FeatureID, item.Feature, reason)
			}
			if !strings.Contains(strings.ToLower(reason), "residual") {
				t.Errorf("%s (%s) ga_scope_reason must name the residual GA gap, got %q", item.FeatureID, item.Feature, reason)
			}
		default:
			t.Errorf("%s (%s) has invalid served_state %q", item.FeatureID, item.Feature, item.ServedState)
		}
	}

	if gaRows == 0 {
		t.Fatal("GA served denominator is empty")
	}
	if gaServedRows != gaRows {
		t.Fatalf("GA served coverage = %d/%d, want 100%%", gaServedRows, gaRows)
	}
}

// TestTRACE019ACMERowRemainsConditionalUntilEnabled locks the remediation for
// TRACE-019. The served ACME protocol workflow belongs in the GA denominator; the
// richer ACME admin console remains visible as a roadmap residual and must not be
// hidden inside a conditional F5 row.
func TestTRACE019ACMERowRemainsConditionalUntilEnabled(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f5, ok := featureByID(catalog, "F5")
	if !ok {
		t.Fatal("F5 Built-in ACME server row is missing")
	}
	requireResidualServedState(t, "TRACE-019", f5, "conditional")

	servedEvidence := strings.ToLower(strings.Join([]string{
		f5.BackendStatus,
		f5.CurrentMapping,
		strings.Join(f5.FacetEvidence.Served.Evidence, "\n"),
	}, "\n"))
	for _, want := range []string{"/directory", "/acme/", "stock", "revokecert", "fail closed"} {
		if !strings.Contains(servedEvidence, want) {
			t.Errorf("TRACE-019: F5 served evidence must name %q, got %q", want, servedEvidence)
		}
	}

	testRefs := map[string]bool{}
	for _, ref := range f5.FacetEvidence.Test.Refs {
		testRefs[ref] = true
	}
	for _, wantRef := range []string{
		"internal/server/protocols_served_test.go",
		"internal/server/protect_correct102_guard_test.go",
		"internal/featureparity/feature_served_ga_coverage_test.go",
	} {
		if !testRefs[wantRef] {
			t.Errorf("TRACE-019: F5 test facet must cite %s", wantRef)
		}
	}

	testEvidence := strings.ToLower(strings.Join(f5.FacetEvidence.Test.Evidence, "\n"))
	for _, want := range []string{"trace-019", "testservedacmeendtoend", "testservedacmestaterebuildsafterserverrestart"} {
		if !strings.Contains(testEvidence, want) {
			t.Errorf("TRACE-019: F5 test evidence must mention %q, got %q", want, testEvidence)
		}
	}

	residual := strings.ToLower(strings.Join([]string{f5.TargetMapping, f5.AcceptanceTest}, "\n"))
	for _, want := range []string{"roadmap residual", "admin console"} {
		if !strings.Contains(residual, want) {
			t.Errorf("TRACE-019: F5 must explicitly park the unsatisfied admin surface as a roadmap residual; missing %q in %q", want, residual)
		}
	}
}

// TestTRACE020ESTRowRemainsConditionalUntilEnabled locks the remediation for
// TRACE-020. The served EST protocol workflow belongs in the GA denominator; the
// richer EST admin console remains visible as a roadmap residual and must not be
// hidden inside a conditional F22 row.
func TestTRACE020ESTRowRemainsConditionalUntilEnabled(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f22, ok := featureByID(catalog, "F22")
	if !ok {
		t.Fatal("F22 EST server row is missing")
	}
	requireResidualServedState(t, "TRACE-020", f22, "conditional")

	servedEvidence := strings.ToLower(strings.Join([]string{
		f22.BackendStatus,
		f22.CurrentMapping,
		strings.Join(f22.FacetEvidence.Served.Evidence, "\n"),
	}, "\n"))
	for _, want := range []string{"/.well-known/est/", "/cacerts", "/simpleenroll", "/simplereenroll", "/csrattrs", "bearer", "signer"} {
		if !strings.Contains(servedEvidence, want) {
			t.Errorf("TRACE-020: F22 served evidence must name %q, got %q", want, servedEvidence)
		}
	}

	testRefs := map[string]bool{}
	for _, ref := range f22.FacetEvidence.Test.Refs {
		testRefs[ref] = true
	}
	for _, wantRef := range []string{
		"internal/server/protocols_served_enroll_test.go",
		"internal/server/protect_correct102_guard_test.go",
		"internal/featureparity/feature_served_ga_coverage_test.go",
	} {
		if !testRefs[wantRef] {
			t.Errorf("TRACE-020: F22 test facet must cite %s", wantRef)
		}
	}

	testEvidence := strings.ToLower(strings.Join(f22.FacetEvidence.Test.Evidence, "\n"))
	for _, want := range []string{"trace-020", "testservedestendtoend", "testprotectinterop003_protocolmountsgatedandfailclosed"} {
		if !strings.Contains(testEvidence, want) {
			t.Errorf("TRACE-020: F22 test evidence must mention %q, got %q", want, testEvidence)
		}
	}

	residual := strings.ToLower(strings.Join([]string{f22.TargetMapping, f22.AcceptanceTest}, "\n"))
	for _, want := range []string{"roadmap residual", "admin console"} {
		if !strings.Contains(residual, want) {
			t.Errorf("TRACE-020: F22 must explicitly park the unsatisfied admin surface as a roadmap residual; missing %q in %q", want, residual)
		}
	}
}

// TestTRACE021SCEPRowRemainsConditionalUntilEnabled locks the remediation for
// TRACE-021. The served SCEP protocol workflow belongs in the GA denominator; the
// richer SCEP admin console remains visible as a roadmap residual and must not be
// hidden inside a conditional F23 row.
func TestTRACE021SCEPRowRemainsConditionalUntilEnabled(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f23, ok := featureByID(catalog, "F23")
	if !ok {
		t.Fatal("F23 SCEP server row is missing")
	}
	requireResidualServedState(t, "TRACE-021", f23, "conditional")

	servedEvidence := strings.ToLower(strings.Join([]string{
		f23.BackendStatus,
		f23.CurrentMapping,
		strings.Join(f23.FacetEvidence.Served.Evidence, "\n"),
	}, "\n"))
	for _, want := range []string{"/scep", "getcacaps", "getcacert", "pkioperation", "cms", "signer", "certificate.recorded"} {
		if !strings.Contains(servedEvidence, want) {
			t.Errorf("TRACE-021: F23 served evidence must name %q, got %q", want, servedEvidence)
		}
	}

	testRefs := map[string]bool{}
	for _, ref := range f23.FacetEvidence.Test.Refs {
		testRefs[ref] = true
	}
	for _, wantRef := range []string{
		"internal/server/protocols_served_enroll_test.go",
		"internal/server/protect_correct102_guard_test.go",
		"internal/protocols/scep/scep_test.go",
		"internal/featureparity/feature_served_ga_coverage_test.go",
	} {
		if !testRefs[wantRef] {
			t.Errorf("TRACE-021: F23 test facet must cite %s", wantRef)
		}
	}

	testEvidence := strings.ToLower(strings.Join(f23.FacetEvidence.Test.Evidence, "\n"))
	for _, want := range []string{"trace-021", "testservedscependtoend", "testgetcacapsadvertisespost", "testmalformedpkioperationfailsclosed", "testprotectinterop003_protocolmountsgatedandfailclosed"} {
		if !strings.Contains(testEvidence, want) {
			t.Errorf("TRACE-021: F23 test evidence must mention %q, got %q", want, testEvidence)
		}
	}

	residual := strings.ToLower(strings.Join([]string{f23.TargetMapping, f23.AcceptanceTest}, "\n"))
	for _, want := range []string{"roadmap residual", "admin console"} {
		if !strings.Contains(residual, want) {
			t.Errorf("TRACE-021: F23 must explicitly park the unsatisfied admin surface as a roadmap residual; missing %q in %q", want, residual)
		}
	}
}

// TestTRACE022CMPRowRemainsConditionalUntilEnabled locks the remediation for
// TRACE-022. The served CMP p10cr workflow belongs in the GA denominator; the
// richer CMP admin console remains visible as a roadmap residual and must not be
// hidden inside a conditional F55 row.
func TestTRACE022CMPRowRemainsConditionalUntilEnabled(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f55, ok := featureByID(catalog, "F55")
	if !ok {
		t.Fatal("F55 CMP server row is missing")
	}
	requireResidualServedState(t, "TRACE-022", f55, "conditional")

	servedEvidence := strings.ToLower(strings.Join([]string{
		f55.BackendStatus,
		f55.CurrentMapping,
		strings.Join(f55.FacetEvidence.Served.Evidence, "\n"),
	}, "\n"))
	for _, want := range []string{"/cmp", "p10cr", "pkimessage", "openssl", "signer", "certificate.recorded", "fail closed"} {
		if !strings.Contains(servedEvidence, want) {
			t.Errorf("TRACE-022: F55 served evidence must name %q, got %q", want, servedEvidence)
		}
	}

	testRefs := map[string]bool{}
	for _, ref := range f55.FacetEvidence.Test.Refs {
		testRefs[ref] = true
	}
	for _, wantRef := range []string{
		"internal/server/protocols_served_enroll_test.go",
		"internal/server/protocols_served_stock_clients_test.go",
		"internal/server/protect_correct102_guard_test.go",
		"internal/protocols/cmp/cmp_test.go",
		"internal/featureparity/feature_served_ga_coverage_test.go",
	} {
		if !testRefs[wantRef] {
			t.Errorf("TRACE-022: F55 test facet must cite %s", wantRef)
		}
	}

	testEvidence := strings.ToLower(strings.Join(f55.FacetEvidence.Test.Evidence, "\n"))
	for _, want := range []string{"trace-022", "testservedcmpendtoend", "testservedcmpopensslclientp10crenrollment", "testcmpmalformedfailsclosed", "testprotectinterop003_protocolmountsgatedandfailclosed"} {
		if !strings.Contains(testEvidence, want) {
			t.Errorf("TRACE-022: F55 test evidence must mention %q, got %q", want, testEvidence)
		}
	}

	residual := strings.ToLower(strings.Join([]string{f55.TargetMapping, f55.AcceptanceTest}, "\n"))
	for _, want := range []string{"roadmap residual", "admin console"} {
		if !strings.Contains(residual, want) {
			t.Errorf("TRACE-022: F55 must explicitly park the unsatisfied admin surface as a roadmap residual; missing %q in %q", want, residual)
		}
	}
}

// TestTRACE023SPIFFERowRemainsConditionalUntilEnabled locks the remediation for
// TRACE-023. The served SPIFFE Workload API UDS workflow belongs in the GA
// denominator; the richer SPIFFE admin console remains visible as a roadmap residual
// and must not be hidden inside a conditional F24 row.
func TestTRACE023SPIFFERowRemainsConditionalUntilEnabled(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f24, ok := featureByID(catalog, "F24")
	if !ok {
		t.Fatal("F24 SPIFFE Workload API row is missing")
	}
	requireResidualServedState(t, "TRACE-023", f24, "conditional")

	servedEvidence := strings.ToLower(strings.Join([]string{
		f24.BackendStatus,
		f24.CurrentMapping,
		strings.Join(f24.FacetEvidence.Served.Evidence, "\n"),
	}, "\n"))
	for _, want := range []string{"runs spiffe", "uds", "fetchx509svid", "fetchjwtsvid", "fetchjwtbundles", "validatejwtsvid", "go-spiffe", "spiffe.svid.issued", "fail closed"} {
		if !strings.Contains(servedEvidence, want) {
			t.Errorf("TRACE-023: F24 served evidence must name %q, got %q", want, servedEvidence)
		}
	}

	testRefs := map[string]bool{}
	for _, ref := range f24.FacetEvidence.Test.Refs {
		testRefs[ref] = true
	}
	for _, wantRef := range []string{
		"internal/server/protocols_served_spiffe_ssh_test.go",
		"internal/server/protect_correct102_guard_test.go",
		"internal/server/protocol_authz_test.go",
		"internal/featureparity/feature_served_ga_coverage_test.go",
	} {
		if !testRefs[wantRef] {
			t.Errorf("TRACE-023: F24 test facet must cite %s", wantRef)
		}
	}

	testEvidence := strings.ToLower(strings.Join(f24.FacetEvidence.Test.Evidence, "\n"))
	for _, want := range []string{"trace-023", "testservedspiffeworkloadapiendtoend", "testservedspiffegospiffeclient", "testservedspiffegospiffejwtclient", "testprotectinterop003_protocolmountsgatedandfailclosed"} {
		if !strings.Contains(testEvidence, want) {
			t.Errorf("TRACE-023: F24 test evidence must mention %q, got %q", want, testEvidence)
		}
	}

	residual := strings.ToLower(strings.Join([]string{f24.TargetMapping, f24.AcceptanceTest}, "\n"))
	for _, want := range []string{"roadmap residual", "admin console"} {
		if !strings.Contains(residual, want) {
			t.Errorf("TRACE-023: F24 must explicitly park the unsatisfied admin surface as a roadmap residual; missing %q in %q", want, residual)
		}
	}
}

// TestTRACE024EphemeralCredentialRowSplitsServedGAFromRoadmapResidual locks the
// remediation for TRACE-024. The approval-gated ephemeral/JIT credential REST and
// CLI workflow belongs in the GA denominator; the richer dedicated issuance UI
// remains visible as a roadmap residual and must not be hidden inside a
// conditional F25 row.
func TestTRACE024EphemeralCredentialRowSplitsServedGAFromRoadmapResidual(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f25, ok := featureByID(catalog, "F25")
	if !ok {
		t.Fatal("F25 Ephemeral credential issuance row is missing")
	}
	if f25.ServedState != "served" {
		t.Fatalf("TRACE-024: F25 must be promoted to served after splitting residual scope, got served_state=%q", f25.ServedState)
	}
	if f25.GAServedScope != "" && f25.GAServedScope != gaServedScopeIn {
		t.Fatalf("TRACE-024: served F25 must be in the GA denominator, got ga_served_scope=%q", f25.GAServedScope)
	}
	if strings.TrimSpace(f25.GAScopeReason) != "" {
		t.Fatalf("TRACE-024: served F25 must not carry the old residual GA exclusion, got %q", f25.GAScopeReason)
	}

	servedEvidence := strings.ToLower(strings.Join([]string{
		f25.BackendStatus,
		f25.CurrentMapping,
		strings.Join(f25.FacetEvidence.Served.Evidence, "\n"),
	}, "\n"))
	for _, want := range []string{"/api/v1/ephemeral", "attestation", "approval", "outbox", "short-ttl", "idempot", "ephemeral.issued", "certificate.recorded"} {
		if !strings.Contains(servedEvidence, want) {
			t.Errorf("TRACE-024: F25 served evidence must name %q, got %q", want, servedEvidence)
		}
	}

	testRefs := map[string]bool{}
	for _, ref := range f25.FacetEvidence.Test.Refs {
		testRefs[ref] = true
	}
	for _, wantRef := range []string{
		"internal/server/ephemeral_served_test.go",
		"internal/api/openapi_golden_test.go",
		"internal/cli/cli_test.go",
		"internal/featureparity/feature_served_ga_coverage_test.go",
	} {
		if !testRefs[wantRef] {
			t.Errorf("TRACE-024: F25 test facet must cite %s", wantRef)
		}
	}

	testEvidence := strings.ToLower(strings.Join(f25.FacetEvidence.Test.Evidence, "\n"))
	for _, want := range []string{"trace-024", "testservedephemeraljitissuesafterattestationandapproval", "idempotent", "outbox", "ttl expiry"} {
		if !strings.Contains(testEvidence, want) {
			t.Errorf("TRACE-024: F25 test evidence must mention %q, got %q", want, testEvidence)
		}
	}

	residual := strings.ToLower(strings.Join([]string{f25.TargetMapping, f25.AcceptanceTest}, "\n"))
	for _, want := range []string{"roadmap residual", "dedicated issuance ui"} {
		if !strings.Contains(residual, want) {
			t.Errorf("TRACE-024: F25 must explicitly park the unsatisfied dedicated issuance UI as a roadmap residual; missing %q in %q", want, residual)
		}
	}
}

// TestTRACE025WorkloadAttestationRowSplitsServedGAFromRoadmapResidual locks the
// remediation for TRACE-025. The served tenant attester-trust lifecycle and
// attested X.509-SVID issuance workflow belongs in the GA denominator; the richer
// evidence-review console remains visible as a roadmap residual and must not be
// hidden inside a conditional F30 row.
func TestTRACE025WorkloadAttestationRowSplitsServedGAFromRoadmapResidual(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f30, ok := featureByID(catalog, "F30")
	if !ok {
		t.Fatal("F30 Workload attestation chain row is missing")
	}
	if f30.ServedState != "served" {
		t.Fatalf("TRACE-025: F30 must be promoted to served after splitting residual scope, got served_state=%q", f30.ServedState)
	}
	if f30.GAServedScope != "" && f30.GAServedScope != gaServedScopeIn {
		t.Fatalf("TRACE-025: served F30 must be in the GA denominator, got ga_served_scope=%q", f30.GAServedScope)
	}
	if strings.TrimSpace(f30.GAScopeReason) != "" {
		t.Fatalf("TRACE-025: served F30 must not carry the old residual GA exclusion, got %q", f30.GAScopeReason)
	}

	servedEvidence := strings.ToLower(strings.Join([]string{
		f30.BackendStatus,
		f30.CurrentMapping,
		strings.Join(f30.FacetEvidence.Served.Evidence, "\n"),
	}, "\n"))
	for _, want := range []string{"/api/v1/workloads/attester-trust-sources", "/api/v1/workloads/attested-issuance", "tpm", "aws_iid", "gcp_iit", "azure_imds", "k8s_sat", "github_oidc", "signer", "certificate.recorded", "attestation.bound", "fails closed"} {
		if !strings.Contains(servedEvidence, want) {
			t.Errorf("TRACE-025: F30 served evidence must name %q, got %q", want, servedEvidence)
		}
	}

	testRefs := map[string]bool{}
	for _, ref := range f30.FacetEvidence.Test.Refs {
		testRefs[ref] = true
	}
	for _, wantRef := range []string{
		"internal/server/attested_issuance_served_test.go",
		"internal/server/workload_attester_trust_served_test.go",
		"internal/api/openapi_golden_test.go",
		"internal/cli/cli_test.go",
		"internal/featureparity/feature_served_ga_coverage_test.go",
	} {
		if !testRefs[wantRef] {
			t.Errorf("TRACE-025: F30 test facet must cite %s", wantRef)
		}
	}

	testEvidence := strings.ToLower(strings.Join(f30.FacetEvidence.Test.Evidence, "\n"))
	for _, want := range []string{"trace-025", "testservedattestedissuanceendpointissuesfork8sandaws", "testjourney001workloadownerselfservesattestedonboarding", "forged", "revoked", "idempotent"} {
		if !strings.Contains(testEvidence, want) {
			t.Errorf("TRACE-025: F30 test evidence must mention %q, got %q", want, testEvidence)
		}
	}

	residual := strings.ToLower(strings.Join([]string{f30.TargetMapping, f30.AcceptanceTest}, "\n"))
	for _, want := range []string{"roadmap residual", "evidence viewer"} {
		if !strings.Contains(residual, want) {
			t.Errorf("TRACE-025: F30 must explicitly park the richer evidence-review surface as a roadmap residual; missing %q in %q", want, residual)
		}
	}
}

// TestTRACE026AIAgentBrokerRowSplitsServedGAFromRoadmapResidual locks the
// remediation for TRACE-026. The policy-gated broker issuance API, CLI, and
// metadata-safe Workloads workflow belong in the GA denominator; the richer
// tenant-wide broker history console remains visible as a roadmap residual and
// must not be hidden inside a conditional F61 row.
func TestTRACE026AIAgentBrokerRowSplitsServedGAFromRoadmapResidual(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f61, ok := featureByID(catalog, "F61")
	if !ok {
		t.Fatal("F61 AI-agent / NHI identity broker row is missing")
	}
	if f61.ServedState != "served" {
		t.Fatalf("TRACE-026: F61 must be promoted to served after splitting residual scope, got served_state=%q", f61.ServedState)
	}
	if f61.GAServedScope != "" && f61.GAServedScope != gaServedScopeIn {
		t.Fatalf("TRACE-026: served F61 must be in the GA denominator, got ga_served_scope=%q", f61.GAServedScope)
	}
	if strings.TrimSpace(f61.GAScopeReason) != "" {
		t.Fatalf("TRACE-026: served F61 must not carry the old residual GA exclusion, got %q", f61.GAScopeReason)
	}

	servedEvidence := strings.ToLower(strings.Join([]string{
		f61.BackendStatus,
		f61.CurrentMapping,
		strings.Join(f61.FacetEvidence.Served.Evidence, "\n"),
	}, "\n"))
	for _, want := range []string{"/api/v1/broker/agent-identities", "policy", "idempot", "graph", "agent.identity.issued", "agent.identity.refused", "certificate.recorded"} {
		if !strings.Contains(servedEvidence, want) {
			t.Errorf("TRACE-026: F61 served evidence must name %q, got %q", want, servedEvidence)
		}
	}

	testRefs := map[string]bool{}
	for _, ref := range f61.FacetEvidence.Test.Refs {
		testRefs[ref] = true
	}
	for _, wantRef := range []string{
		"internal/server/broker_served_test.go",
		"internal/api/openapi_golden_test.go",
		"internal/cli/cli_test.go",
		"internal/featureparity/feature_served_ga_coverage_test.go",
	} {
		if !testRefs[wantRef] {
			t.Errorf("TRACE-026: F61 test facet must cite %s", wantRef)
		}
	}

	testEvidence := strings.ToLower(strings.Join(f61.FacetEvidence.Test.Evidence, "\n"))
	for _, want := range []string{"trace-026", "testservedaiagentbrokerissuespolicygatedcredentialintograph", "idempotent", "policy denial", "graph projection"} {
		if !strings.Contains(testEvidence, want) {
			t.Errorf("TRACE-026: F61 test evidence must mention %q, got %q", want, testEvidence)
		}
	}

	residual := strings.ToLower(strings.Join([]string{f61.TargetMapping, f61.AcceptanceTest}, "\n"))
	for _, want := range []string{"roadmap residual", "broker history"} {
		if !strings.Contains(residual, want) {
			t.Errorf("TRACE-026: F61 must explicitly park tenant-wide broker history as a roadmap residual; missing %q in %q", want, residual)
		}
	}
}

// TestTRACE027SSHCertificateAuthorityRemainsConditionalUntilEnabled locks
// the remediation for TRACE-027. The served SSH CA protocol, API, CLI, and console
// workflow belongs in the GA denominator; the richer dedicated host-certificate CA
// console remains visible as a roadmap residual and must not be hidden inside a
// conditional F43 row.
func TestTRACE027SSHCertificateAuthorityRemainsConditionalUntilEnabled(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f43, ok := featureByID(catalog, "F43")
	if !ok {
		t.Fatal("F43 SSH certificate authority row is missing")
	}
	requireResidualServedState(t, "TRACE-027", f43, "conditional")

	servedEvidence := strings.ToLower(strings.Join([]string{
		f43.BackendStatus,
		f43.CurrentMapping,
		strings.Join(f43.SourceBackend, "\n"),
		strings.Join(f43.FacetEvidence.Served.Evidence, "\n"),
	}, "\n"))
	for _, want := range []string{"/ssh/ca", "/ssh/issue/user", "/ssh/issue/host", "/ssh/krl", "openssh", "binary krl", "ssh.cert.issued", "ssh.cert.revoked"} {
		if !strings.Contains(servedEvidence, want) {
			t.Errorf("TRACE-027: F43 served evidence must name %q, got %q", want, servedEvidence)
		}
	}

	testRefs := map[string]bool{}
	for _, ref := range f43.FacetEvidence.Test.Refs {
		testRefs[ref] = true
	}
	for _, wantRef := range []string{
		"internal/server/protocols_served_spiffe_ssh_test.go",
		"internal/server/ssh_journey_served_test.go",
		"internal/server/protect_correct102_guard_test.go",
		"internal/api/openapi_golden_test.go",
		"internal/cli/cli_test.go",
		"internal/featureparity/feature_served_ga_coverage_test.go",
	} {
		if !testRefs[wantRef] {
			t.Errorf("TRACE-027: F43 test facet must cite %s", wantRef)
		}
	}

	testEvidence := strings.ToLower(strings.Join(f43.FacetEvidence.Test.Evidence, "\n"))
	for _, want := range []string{"trace-027", "testservedsshendtoend", "testservedsshatscalejourneyjourney002endtoend", "openssh binary krl", "revocation"} {
		if !strings.Contains(testEvidence, want) {
			t.Errorf("TRACE-027: F43 test evidence must mention %q, got %q", want, testEvidence)
		}
	}

	residual := strings.ToLower(strings.Join([]string{f43.TargetMapping, f43.AcceptanceTest}, "\n"))
	for _, want := range []string{"roadmap residual", "host-certificate ca console"} {
		if !strings.Contains(residual, want) {
			t.Errorf("TRACE-027: F43 must explicitly park the richer host-certificate CA console as a roadmap residual; missing %q in %q", want, residual)
		}
	}
}

// TestTRACE028SSHTrustDeploymentRowSplitsServedGAFromRoadmapResidual locks the
// remediation for TRACE-028. The explicit-confirmation SSH trust rollout API,
// CLI, and console workflow belongs in the GA denominator; closed-loop host
// rewrite automation remains visible as a roadmap residual and must not be
// hidden inside a conditional F44 row.
func TestTRACE028SSHTrustDeploymentRowSplitsServedGAFromRoadmapResidual(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f44, ok := featureByID(catalog, "F44")
	if !ok {
		t.Fatal("F44 SSH deployment and trust configuration row is missing")
	}
	if f44.ServedState != "served" {
		t.Fatalf("TRACE-028: F44 must be promoted to served after splitting residual scope, got served_state=%q", f44.ServedState)
	}
	if f44.GAServedScope != "" && f44.GAServedScope != gaServedScopeIn {
		t.Fatalf("TRACE-028: served F44 must be in the GA denominator, got ga_served_scope=%q", f44.GAServedScope)
	}
	if strings.TrimSpace(f44.GAScopeReason) != "" {
		t.Fatalf("TRACE-028: served F44 must not carry the old residual GA exclusion, got %q", f44.GAScopeReason)
	}

	servedEvidence := strings.ToLower(strings.Join([]string{
		f44.BackendStatus,
		f44.CurrentMapping,
		strings.Join(f44.FacetEvidence.Served.Evidence, "\n"),
	}, "\n"))
	for _, want := range []string{"/api/v1/ssh/trust-rollouts", "/api/v1/ssh/hosts/retire", "explicit confirmation", "rollback", "health", "ssh.trust_rollout.recorded", "ssh.host.retired"} {
		if !strings.Contains(servedEvidence, want) {
			t.Errorf("TRACE-028: F44 served evidence must name %q, got %q", want, servedEvidence)
		}
	}

	testRefs := map[string]bool{}
	for _, ref := range f44.FacetEvidence.Test.Refs {
		testRefs[ref] = true
	}
	for _, wantRef := range []string{
		"internal/server/ssh_journey_served_test.go",
		"internal/api/openapi_golden_test.go",
		"internal/cli/cli_test.go",
		"cmd/trstctl/main_test.go",
		"web/src/__tests__/ssh_trust.test.tsx",
		"internal/featureparity/feature_served_ga_coverage_test.go",
	} {
		if !testRefs[wantRef] {
			t.Errorf("TRACE-028: F44 test facet must cite %s", wantRef)
		}
	}

	testEvidence := strings.ToLower(strings.Join(f44.FacetEvidence.Test.Evidence, "\n"))
	for _, want := range []string{"trace-028", "testservedsshatscalejourneyjourney002endtoend", "explicit confirmation", "retire", "openapi/cli parity"} {
		if !strings.Contains(testEvidence, want) {
			t.Errorf("TRACE-028: F44 test evidence must mention %q, got %q", want, testEvidence)
		}
	}

	residual := strings.ToLower(strings.Join([]string{f44.TargetMapping, f44.AcceptanceTest}, "\n"))
	for _, want := range []string{"roadmap residual", "closed-loop host rewrite"} {
		if !strings.Contains(residual, want) {
			t.Errorf("TRACE-028: F44 must explicitly park closed-loop host rewrite automation as a roadmap residual; missing %q in %q", want, residual)
		}
	}
}

// TestTRACE029AttestedSSHUserCertRowPromotedToServedGA locks the remediation
// for TRACE-029. The attestation-gated SSH user certificate API, CLI, and
// console workflow belongs in the GA denominator because the complete served
// workflow is wired through the product surface and covered by route-level
// tests.
func TestTRACE029AttestedSSHUserCertRowPromotedToServedGA(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f45, ok := featureByID(catalog, "F45")
	if !ok {
		t.Fatal("F45 attestation-gated SSH user cert row is missing")
	}
	if f45.ServedState != "served" {
		t.Fatalf("TRACE-029: F45 must be promoted to served after the attested SSH cert workflow is served end-to-end, got served_state=%q", f45.ServedState)
	}
	if f45.GAServedScope != "" && f45.GAServedScope != gaServedScopeIn {
		t.Fatalf("TRACE-029: served F45 must be in the GA denominator, got ga_served_scope=%q", f45.GAServedScope)
	}
	if strings.TrimSpace(f45.GAScopeReason) != "" {
		t.Fatalf("TRACE-029: served F45 must not carry the old conditional GA exclusion, got %q", f45.GAScopeReason)
	}

	servedEvidence := strings.ToLower(strings.Join([]string{
		f45.BackendStatus,
		f45.CurrentMapping,
		strings.Join(f45.FacetEvidence.Served.Evidence, "\n"),
	}, "\n"))
	for _, want := range []string{"/api/v1/ssh/attested-user-certs", "distinct approver", "principal", "source-address", "force-command", "ssh.attested_cert.issued"} {
		if !strings.Contains(servedEvidence, want) {
			t.Errorf("TRACE-029: F45 served evidence must name %q, got %q", want, servedEvidence)
		}
	}

	testRefs := map[string]bool{}
	for _, ref := range f45.FacetEvidence.Test.Refs {
		testRefs[ref] = true
	}
	for _, wantRef := range []string{
		"internal/server/ssh_journey_served_test.go",
		"internal/api/openapi_golden_test.go",
		"internal/cli/cli_test.go",
		"cmd/trstctl/main_test.go",
		"web/src/__tests__/ssh_trust.test.tsx",
		"internal/featureparity/feature_served_ga_coverage_test.go",
	} {
		if !testRefs[wantRef] {
			t.Errorf("TRACE-029: F45 test facet must cite %s", wantRef)
		}
	}

	testEvidence := strings.ToLower(strings.Join(f45.FacetEvidence.Test.Evidence, "\n"))
	for _, want := range []string{"trace-029", "testservedsshatscalejourneyjourney002endtoend", "expired attestation", "self-approval", "openapi/cli parity"} {
		if !strings.Contains(testEvidence, want) {
			t.Errorf("TRACE-029: F45 test evidence must mention %q, got %q", want, testEvidence)
		}
	}
}

// TestTRACE030TSARowRemainsConditionalUntilEnabled locks TRACE-030.
// The RFC 3161 /tsa responder belongs in the GA denominator because it is a
// complete served protocol workflow with stock OpenSSL verification coverage.
// Any richer dedicated TSA admin console remains visible as a roadmap residual
// and must not be hidden inside a conditional F51 row.
func TestTRACE030TSARowRemainsConditionalUntilEnabled(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f51, ok := featureByID(catalog, "F51")
	if !ok {
		t.Fatal("F51 Timestamping authority row is missing")
	}
	requireResidualServedState(t, "TRACE-030", f51, "conditional")

	servedEvidence := strings.ToLower(strings.Join([]string{
		f51.BackendStatus,
		f51.CurrentMapping,
		strings.Join(f51.SourceBackend, "\n"),
		strings.Join(f51.FacetEvidence.Served.Evidence, "\n"),
	}, "\n"))
	for _, want := range []string{"/tsa", "rfc 3161", "timestampresp", "application/timestamp-reply", "openssl", "tsa.timestamp.issued", "fail closed"} {
		if !strings.Contains(servedEvidence, want) {
			t.Errorf("TRACE-030: F51 served evidence must name %q, got %q", want, servedEvidence)
		}
	}

	testRefs := map[string]bool{}
	for _, ref := range f51.FacetEvidence.Test.Refs {
		testRefs[ref] = true
	}
	for _, wantRef := range []string{
		"internal/server/protocols_served_tsa_test.go",
		"internal/tsa/http_test.go",
		"internal/featureparity/feature_served_ga_coverage_test.go",
	} {
		if !testRefs[wantRef] {
			t.Errorf("TRACE-030: F51 test facet must cite %s", wantRef)
		}
	}

	testEvidence := strings.ToLower(strings.Join(f51.FacetEvidence.Test.Evidence, "\n"))
	for _, want := range []string{"trace-030", "testservedtsaopenssltimestampoverhttp", "testtimestamphttppostopenssltsverify", "rfc 3161"} {
		if !strings.Contains(testEvidence, want) {
			t.Errorf("TRACE-030: F51 test evidence must mention %q, got %q", want, testEvidence)
		}
	}

	residual := strings.ToLower(strings.Join([]string{f51.TargetMapping, f51.AcceptanceTest}, "\n"))
	for _, want := range []string{"roadmap residual", "dedicated tsa admin console"} {
		if !strings.Contains(residual, want) {
			t.Errorf("TRACE-030: F51 must explicitly park the richer dedicated TSA admin console as a roadmap residual; missing %q in %q", want, residual)
		}
	}
}

// TestTRACE031NativeSecretStoreRemainsConditionalUntilEnabled locks the remediation for
// TRACE-031. The native store belongs in the GA denominator once the complete
// create/list/reveal/rotate/delete plus history and point-in-time recovery
// workflow is served through API, CLI, and the Secrets UI.
func TestTRACE031NativeSecretStoreRemainsConditionalUntilEnabled(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f63, ok := featureByID(catalog, "F63")
	if !ok {
		t.Fatal("F63 Native secret store row is missing")
	}
	requireResidualServedState(t, "TRACE-031", f63, "conditional")

	servedEvidence := strings.ToLower(strings.Join([]string{
		f63.BackendStatus,
		f63.CurrentMapping,
		strings.Join(f63.SourceBackend, "\n"),
		strings.Join(f63.FacetEvidence.Served.Evidence, "\n"),
	}, "\n"))
	for _, want := range []string{
		"/api/v1/secrets/store",
		"/api/v1/secrets/store/history",
		"/api/v1/secrets/store/recover",
		"create",
		"reveal",
		"rotate",
		"delete",
		"secret.version.written",
		"secret.recovered",
		"tenant",
		"plaintext",
	} {
		if !strings.Contains(servedEvidence, want) {
			t.Errorf("TRACE-031: F63 served evidence must name %q, got %q", want, servedEvidence)
		}
	}

	cliEvidence := strings.ToLower(strings.Join(append(append([]string{}, f63.CLISurface...), f63.FacetEvidence.CLI.Evidence...), "\n"))
	for _, want := range []string{
		"secrets store put",
		"secrets store list",
		"secrets store get",
		"secrets store history",
		"secrets store recover",
		"secrets store update",
		"secrets store delete",
	} {
		if !strings.Contains(cliEvidence, want) {
			t.Errorf("TRACE-031: F63 CLI evidence must name %q, got %q", want, cliEvidence)
		}
	}

	testRefs := map[string]bool{}
	for _, ref := range f63.FacetEvidence.Test.Refs {
		testRefs[ref] = true
	}
	for _, wantRef := range []string{
		"internal/server/secrets_served_test.go",
		"internal/api/feature_parity_test.go",
		"internal/cli/feature_parity_test.go",
		"web/src/__tests__/secrets.test.tsx",
		"web/src/__tests__/accept/U2-4.test.tsx",
		"internal/featureparity/feature_served_ga_coverage_test.go",
	} {
		if !testRefs[wantRef] {
			t.Errorf("TRACE-031: F63 test facet must cite %s", wantRef)
		}
	}

	testEvidence := strings.ToLower(strings.Join(f63.FacetEvidence.Test.Evidence, "\n"))
	for _, want := range []string{"trace-031", "testservedsecretstorecreatereadrotate", "testservedsecretstoreversionhistoryandpitr", "u2-4", "feature parity"} {
		if !strings.Contains(testEvidence, want) {
			t.Errorf("TRACE-031: F63 test evidence must mention %q, got %q", want, testEvidence)
		}
	}
}

// TestTRACE032DynamicSecretsRemainConditionalWhenConfigured locks the production
// wiring proof while preserving the operator-configuration condition.
func TestTRACE032DynamicSecretsRemainConditionalWhenConfigured(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f65, ok := featureByID(catalog, "F65")
	if !ok {
		t.Fatal("F65 Dynamic secrets row is missing")
	}
	requireResidualServedState(t, "TRACE-032", f65, "conditional")

	servedEvidence := strings.ToLower(strings.Join([]string{
		f65.BackendStatus,
		f65.CurrentMapping,
		strings.Join(f65.SourceBackend, "\n"),
		strings.Join(f65.APISurface, "\n"),
		strings.Join(f65.FacetEvidence.Served.Evidence, "\n"),
	}, "\n"))
	for _, want := range []string{
		"tenantdynamicsecretproviders",
		"buildrundeps",
		"sealed dynsecret.issue",
		"testdodsecretintegrationsproductionassembly",
		"issuedynamicsecretlease",
		"renewdynamicsecretlease",
		"revokedynamicsecretlease",
	} {
		if !strings.Contains(servedEvidence, want) {
			t.Errorf("TRACE-032: F65 served evidence must name %q, got %q", want, servedEvidence)
		}
	}

	cliEvidence := strings.ToLower(strings.Join(append(append([]string{}, f65.CLISurface...), f65.FacetEvidence.CLI.Evidence...), "\n"))
	for _, want := range []string{
		"secrets leases issue",
		"secrets leases get",
		"secrets leases renew",
		"secrets leases revoke",
	} {
		if !strings.Contains(cliEvidence, want) {
			t.Errorf("TRACE-032: F65 CLI evidence must name %q, got %q", want, cliEvidence)
		}
	}

	testRefs := map[string]bool{}
	for _, ref := range f65.FacetEvidence.Test.Refs {
		testRefs[ref] = true
	}
	for _, wantRef := range []string{
		"internal/server/dod_secret_integrations_runtime_test.go",
		"tools/dodcensus/substrates/secret_integrations.py",
		"tools/dodcensus/manifest.json",
		"internal/server/secrets_served_test.go",
		"internal/api/feature_parity_test.go",
		"internal/cli/feature_parity_test.go",
		"web/src/lib/api.test.ts",
		"web/src/__tests__/secrets.test.tsx",
		"web/src/__tests__/accept/WIRE-07.test.tsx",
		"internal/featureparity/feature_served_ga_coverage_test.go",
	} {
		if !testRefs[wantRef] {
			t.Errorf("TRACE-032: F65 test facet must cite %s", wantRef)
		}
	}

	testEvidence := strings.ToLower(strings.Join(f65.FacetEvidence.Test.Evidence, "\n"))
	for _, want := range []string{"unit and route tests", "required dynamic_secret census", "tenantdynamicsecretproviders", "universal production-assembly runtime proof"} {
		if !strings.Contains(testEvidence, want) {
			t.Errorf("TRACE-032: F65 test evidence must mention %q, got %q", want, testEvidence)
		}
	}
}

// TestTRACE033PKISecretsRemainConditionalUntilEnabled locks TRACE-033.
// The dynamic PKI secret workflow belongs in the GA denominator once the product
// serves short-lived certificate + private-key issuance through API, CLI, and the
// Secrets UI with signer-backed issuance, event evidence, and revocation linkage.
func TestTRACE033PKISecretsRemainConditionalUntilEnabled(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f67, ok := featureByID(catalog, "F67")
	if !ok {
		t.Fatal("F67 PKI as a secrets engine row is missing")
	}
	requireResidualServedState(t, "TRACE-033", f67, "conditional")

	servedEvidence := strings.ToLower(strings.Join([]string{
		f67.BackendStatus,
		f67.CurrentMapping,
		strings.Join(f67.SourceBackend, "\n"),
		strings.Join(f67.FacetEvidence.Served.Evidence, "\n"),
	}, "\n"))
	for _, want := range []string{
		"/api/v1/secrets/pki",
		"short-lived certificate",
		"private key",
		"signer",
		"revocation",
		"pkisecret.issued",
		"usable tls identity",
	} {
		if !strings.Contains(servedEvidence, want) {
			t.Errorf("TRACE-033: F67 served evidence must name %q, got %q", want, servedEvidence)
		}
	}

	cliEvidence := strings.ToLower(strings.Join(append(append([]string{}, f67.CLISurface...), f67.FacetEvidence.CLI.Evidence...), "\n"))
	if !strings.Contains(cliEvidence, "secrets pki") {
		t.Errorf("TRACE-033: F67 CLI evidence must name secrets pki, got %q", cliEvidence)
	}

	testRefs := map[string]bool{}
	for _, ref := range f67.FacetEvidence.Test.Refs {
		testRefs[ref] = true
	}
	for _, wantRef := range []string{
		"internal/server/secrets_served_test.go",
		"internal/api/feature_parity_test.go",
		"internal/cli/feature_parity_test.go",
		"web/src/lib/api.test.ts",
		"web/src/__tests__/secrets.test.tsx",
		"internal/featureparity/feature_served_ga_coverage_test.go",
	} {
		if !testRefs[wantRef] {
			t.Errorf("TRACE-033: F67 test facet must cite %s", wantRef)
		}
	}

	testEvidence := strings.ToLower(strings.Join(f67.FacetEvidence.Test.Evidence, "\n"))
	for _, want := range []string{"trace-033", "testservedpkisecretissuesusablekeypair", "usable tls identity", "pkisecret.issued", "feature parity"} {
		if !strings.Contains(testEvidence, want) {
			t.Errorf("TRACE-033: F67 test evidence must mention %q, got %q", want, testEvidence)
		}
	}

	residual := strings.ToLower(strings.Join([]string{f67.TargetMapping, f67.AcceptanceTest}, "\n"))
	for _, want := range []string{"roadmap residual", "ocsp/crl"} {
		if !strings.Contains(residual, want) {
			t.Errorf("TRACE-033: F67 must explicitly park richer OCSP/CRL revocation-state UI as a roadmap residual; missing %q in %q", want, residual)
		}
	}
}

// TestTRACE034SecretSyncPlatformIntegrationsAreConditionallyServed locks the
// remediation for TRACE-034. The served secret-sync/platform-integration workflow
// belongs in the GA denominator once API, CLI, Kubernetes operator, workload
// injection, and unvaulted-secret posture paths are all served and tested.
func TestTRACE034SecretSyncPlatformIntegrationsAreConditionallyServed(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f68, ok := featureByID(catalog, "F68")
	if !ok {
		t.Fatal("F68 Secret sync / platform integrations row is missing")
	}
	requireResidualServedState(t, "TRACE-034", f68, "conditional")

	servedEvidence := strings.ToLower(strings.Join([]string{
		f68.BackendStatus,
		f68.CurrentMapping,
		strings.Join(f68.SourceBackend, "\n"),
		strings.Join(f68.FacetEvidence.Served.Evidence, "\n"),
	}, "\n"))
	for _, want := range []string{
		"/api/v1/secrets/cloud-secret-managers",
		"/api/v1/secrets/syncs/targets",
		"/api/v1/secrets/syncs",
		"/api/v1/secrets/kubernetes-operator",
		"/api/v1/secrets/workload-injection",
		"/api/v1/secrets/unvaulted",
		"aws secrets manager",
		"gcp secret manager",
		"azure key vault",
		"hashicorp vault kv",
		"terraform cloud/opentofu",
		"vault kv v2",
		"kubernetes",
		"trstctlsecretsync",
		"trstctlsecretinjection",
		"redacted leaked_secret",
	} {
		if !strings.Contains(servedEvidence, want) {
			t.Errorf("TRACE-034: F68 served evidence must name %q, got %q", want, servedEvidence)
		}
	}

	cliEvidence := strings.ToLower(strings.Join(append(append([]string{}, f68.CLISurface...), f68.FacetEvidence.CLI.Evidence...), "\n"))
	for _, want := range []string{
		"secrets cloud-secret-managers",
		"secrets syncs run",
		"secrets syncs targets",
		"secrets kubernetes-operator",
		"secrets workload-injection",
		"secrets unvaulted",
	} {
		if !strings.Contains(cliEvidence, want) {
			t.Errorf("TRACE-034: F68 CLI evidence must name %q, got %q", want, cliEvidence)
		}
	}

	testRefs := map[string]bool{}
	for _, ref := range f68.FacetEvidence.Test.Refs {
		testRefs[ref] = true
	}
	for _, wantRef := range []string{
		"internal/server/dod_secret_integrations_runtime_test.go",
		"tools/dodcensus/substrates/secret_integrations.py",
		"tools/dodcensus/manifest.json",
		"internal/server/secrets_sync_served_test.go",
		"internal/server/unvaulted_secret_posture_served_test.go",
		"internal/operator/reconcile_test.go",
		"internal/api/feature_parity_test.go",
		"internal/cli/feature_parity_test.go",
		"internal/featureparity/feature_served_ga_coverage_test.go",
	} {
		if !testRefs[wantRef] {
			t.Errorf("TRACE-034: F68 test facet must cite %s", wantRef)
		}
	}

	testEvidence := strings.ToLower(strings.Join(f68.FacetEvidence.Test.Evidence, "\n"))
	for _, want := range []string{
		"cloud-secret discovery",
		"kubernetes/workload posture",
		"vendor create/update semantics",
		"testdodsecretsyncproductionassembly",
		"authenticated external write/readback",
		"required secret_sync census",
	} {
		if !strings.Contains(testEvidence, want) {
			t.Errorf("TRACE-034: F68 test evidence must mention %q, got %q", want, testEvidence)
		}
	}

	residual := strings.ToLower(f68.TargetMapping)
	for _, want := range []string{"roadmap residual", "arbitrary webhook"} {
		if !strings.Contains(residual, want) {
			t.Errorf("TRACE-034: F68 must explicitly park arbitrary webhook-specific managed forms as a roadmap residual; missing %q in %q", want, residual)
		}
	}
	for _, servedTarget := range []string{"terraform/opentofu", "vault kv"} {
		if strings.Contains(residual, servedTarget) {
			t.Errorf("TRACE-034: F68 must not park served target %q as a roadmap residual: %q", servedTarget, residual)
		}
	}
}

// TestTRACE035SSOOIDCRowRemainsConditionalUntilConfigured locks the
// remediation for TRACE-035. The served browser OIDC workflow belongs in the GA
// denominator; richer provider-specific setup and diagnostics remain visible as a
// roadmap residual and must not be hidden inside a conditional F13 row.
func TestTRACE035SSOOIDCRowRemainsConditionalUntilConfigured(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f13, ok := featureByID(catalog, "F13")
	if !ok {
		t.Fatal("F13 SSO/OIDC row is missing")
	}
	requireResidualServedState(t, "TRACE-035", f13, "conditional")

	servedEvidence := strings.ToLower(strings.Join([]string{
		f13.BackendStatus,
		f13.CurrentMapping,
		strings.Join(f13.SourceBackend, "\n"),
		strings.Join(f13.FacetEvidence.Served.Evidence, "\n"),
	}, "\n"))
	for _, want := range []string{
		"/auth/login",
		"/auth/callback",
		"/auth/me",
		"/auth/logout",
		"/auth/oidc/back-channel-logout",
		"pkce s256",
		"state",
		"nonce",
		"authorization response iss",
		"tenant mapping",
		"confidential-client secret",
		"csrf",
		"fail closed",
	} {
		if !strings.Contains(servedEvidence, want) {
			t.Errorf("TRACE-035: F13 served evidence must name %q, got %q", want, servedEvidence)
		}
	}

	testRefs := map[string]bool{}
	for _, ref := range f13.FacetEvidence.Test.Refs {
		testRefs[ref] = true
	}
	for _, wantRef := range []string{
		"internal/api/auth_test.go",
		"web/src/__tests__/auth_and_dashboards.test.tsx",
		"web/src/lib/api.test.ts",
		"internal/featureparity/feature_served_ga_coverage_test.go",
	} {
		if !testRefs[wantRef] {
			t.Errorf("TRACE-035: F13 test facet must cite %s", wantRef)
		}
	}

	testEvidence := strings.ToLower(strings.Join(f13.FacetEvidence.Test.Evidence, "\n"))
	for _, want := range []string{
		"trace-035",
		"testauthloginusespkces256",
		"testauthcallbackestablishessession",
		"testauthcallbackrejectswrongauthorizationresponseissuer",
		"testauthlogoutclearssession",
		"no fake-token login path",
	} {
		if !strings.Contains(testEvidence, want) {
			t.Errorf("TRACE-035: F13 test evidence must mention %q, got %q", want, testEvidence)
		}
	}

	residual := strings.ToLower(strings.Join([]string{f13.TargetMapping, f13.AcceptanceTest}, "\n"))
	for _, want := range []string{"roadmap residual", "provider setup wizard", "login diagnostics"} {
		if !strings.Contains(residual, want) {
			t.Errorf("TRACE-035: F13 must explicitly park richer provider setup/diagnostics as a roadmap residual; missing %q in %q", want, residual)
		}
	}
}

// TestTRACE036SemanticQueryLayerRemainsConditionalUntilEnabled locks the
// remediation for TRACE-036. The served typed semantic query layer belongs in the
// GA denominator; richer saved-prompt/model-analysis workflow polish remains visible
// as a roadmap residual and must not be hidden inside a conditional F75 row.
func TestTRACE036SemanticQueryLayerRemainsConditionalUntilEnabled(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f75, ok := featureByID(catalog, "F75")
	if !ok {
		t.Fatal("F75 Unified semantic query layer row is missing")
	}
	requireResidualServedState(t, "TRACE-036", f75, "conditional")

	servedEvidence := strings.ToLower(strings.Join([]string{
		f75.BackendStatus,
		f75.CurrentMapping,
		strings.Join(f75.SourceBackend, "\n"),
		strings.Join(f75.FacetEvidence.Served.Evidence, "\n"),
	}, "\n"))
	for _, want := range []string{
		"/api/v1/ai/query",
		"/api/v1/ai/rca",
		"/api/v1/graph/query",
		"tenant-then-rbac",
		"typed",
		"citations",
		"insufficient evidence",
		"inert",
		"bounded",
	} {
		if !strings.Contains(servedEvidence, want) {
			t.Errorf("TRACE-036: F75 served evidence must name %q, got %q", want, servedEvidence)
		}
	}

	cliEvidence := strings.ToLower(strings.Join(append(append([]string{}, f75.CLISurface...), f75.FacetEvidence.CLI.Evidence...), "\n"))
	for _, want := range []string{"ai query", "ai rca", "graph query"} {
		if !strings.Contains(cliEvidence, want) {
			t.Errorf("TRACE-036: F75 CLI evidence must name %q, got %q", want, cliEvidence)
		}
	}

	testRefs := map[string]bool{}
	for _, ref := range f75.FacetEvidence.Test.Refs {
		testRefs[ref] = true
	}
	for _, wantRef := range []string{
		"internal/server/aisurface_served_test.go",
		"internal/api/aisurface_contract_test.go",
		"internal/api/feature_parity_test.go",
		"internal/cli/feature_parity_test.go",
		"internal/featureparity/feature_served_ga_coverage_test.go",
	} {
		if !testRefs[wantRef] {
			t.Errorf("TRACE-036: F75 test facet must cite %s", wantRef)
		}
	}

	testEvidence := strings.ToLower(strings.Join(f75.FacetEvidence.Test.Evidence, "\n"))
	for _, want := range []string{
		"trace-036",
		"testservedaIquerygroundedandscoped",
		"testaisurfaceroutesstaygraphscopedwithguardedmcpwrites",
		"feature parity",
		"tenant-scoped",
	} {
		if !strings.Contains(testEvidence, strings.ToLower(want)) {
			t.Errorf("TRACE-036: F75 test evidence must mention %q, got %q", want, testEvidence)
		}
	}

	residual := strings.ToLower(strings.Join([]string{f75.TargetMapping, f75.AcceptanceTest}, "\n"))
	for _, want := range []string{"roadmap residual", "saved prompts", "model-assisted analysis"} {
		if !strings.Contains(residual, want) {
			t.Errorf("TRACE-036: F75 must explicitly park richer semantic-query workflow polish as a roadmap residual; missing %q in %q", want, residual)
		}
	}
}

// TestTRACE037AIModelAdapterRemainsConditionalUntilEnabled locks the
// remediation for TRACE-037. The optional off/local/cloud model adapter, status
// route, CLI surface, and Assistant diagnostics belong in the GA denominator; a
// richer self-service model settings editor remains visible as a roadmap residual
// and must not be hidden inside a conditional F76 row.
func TestTRACE037AIModelAdapterRemainsConditionalUntilEnabled(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f76, ok := featureByID(catalog, "F76")
	if !ok {
		t.Fatal("F76 Pluggable AI model adapter row is missing")
	}
	requireResidualServedState(t, "TRACE-037", f76, "conditional")

	servedEvidence := strings.ToLower(strings.Join([]string{
		f76.BackendStatus,
		f76.CurrentMapping,
		strings.Join(f76.SourceBackend, "\n"),
		strings.Join(f76.APISurface, "\n"),
		strings.Join(f76.FacetEvidence.Served.Evidence, "\n"),
		strings.Join(f76.FacetEvidence.API.Evidence, "\n"),
	}, "\n"))
	for _, want := range []string{
		"/api/v1/ai/status",
		"off",
		"local",
		"cloud",
		"endpoint host",
		"egress",
		"redaction",
		"residual-secret refusal",
		"personal-data",
	} {
		if !strings.Contains(servedEvidence, want) {
			t.Errorf("TRACE-037: F76 served evidence must name %q, got %q", want, servedEvidence)
		}
	}

	cliEvidence := strings.ToLower(strings.Join(append(append([]string{}, f76.CLISurface...), f76.FacetEvidence.CLI.Evidence...), "\n"))
	for _, want := range []string{"ai status", "ai query", "ai rca"} {
		if !strings.Contains(cliEvidence, want) {
			t.Errorf("TRACE-037: F76 CLI evidence must name %q, got %q", want, cliEvidence)
		}
	}

	testRefs := map[string]bool{}
	for _, ref := range f76.FacetEvidence.Test.Refs {
		testRefs[ref] = true
	}
	for _, wantRef := range []string{
		"internal/server/aisurface_model_config_test.go",
		"internal/server/aisurface_served_test.go",
		"internal/api/feature_parity_test.go",
		"internal/cli/feature_parity_test.go",
		"web/src/__tests__/assistant.test.tsx",
		"internal/featureparity/feature_served_ga_coverage_test.go",
	} {
		if !testRefs[wantRef] {
			t.Errorf("TRACE-037: F76 test facet must cite %s", wantRef)
		}
	}

	testEvidence := strings.ToLower(strings.Join(f76.FacetEvidence.Test.Evidence, "\n"))
	for _, want := range []string{
		"trace-037",
		"testaimodelfromconfigbuildslocaladapter",
		"testservedaiStatusReportsDisabledAndConfiguredPosture",
		"redaction",
		"personal-data",
		"feature parity",
	} {
		if !strings.Contains(testEvidence, strings.ToLower(want)) {
			t.Errorf("TRACE-037: F76 test evidence must mention %q, got %q", want, testEvidence)
		}
	}

	residual := strings.ToLower(strings.Join([]string{f76.TargetMapping, f76.AcceptanceTest}, "\n"))
	for _, want := range []string{"roadmap residual", "model settings editor"} {
		if !strings.Contains(residual, want) {
			t.Errorf("TRACE-037: F76 must explicitly park richer model settings workflow as a roadmap residual; missing %q in %q", want, residual)
		}
	}
}

// TestTRACE038GroundedRCARemainsConditionalUntilEnabled locks TRACE-038.
// The grounded RCA / natural-language workflow is served by POST /api/v1/ai/rca,
// the ai rca CLI command, and the Assistant RCA workspace; richer RCA export/timeline
// workflow polish remains visible as a roadmap residual instead of excluding F77 from GA.
func TestTRACE038GroundedRCARemainsConditionalUntilEnabled(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f77, ok := featureByID(catalog, "F77")
	if !ok {
		t.Fatal("F77 Grounded RCA and natural-language query row is missing")
	}
	requireResidualServedState(t, "TRACE-038", f77, "conditional")

	servedEvidence := strings.ToLower(strings.Join([]string{
		f77.BackendStatus,
		f77.CurrentMapping,
		strings.Join(f77.SourceBackend, "\n"),
		strings.Join(f77.APISurface, "\n"),
		strings.Join(f77.FacetEvidence.Served.Evidence, "\n"),
		strings.Join(f77.FacetEvidence.UI.Evidence, "\n"),
		strings.Join(f77.FacetEvidence.API.Evidence, "\n"),
	}, "\n"))
	for _, want := range []string{
		"/api/v1/ai/rca",
		"read-only",
		"grounded",
		"cited",
		"citations",
		"insufficient evidence",
		"hostile record text",
		"inert",
		"fail closed",
	} {
		if !strings.Contains(servedEvidence, want) {
			t.Errorf("TRACE-038: F77 served evidence must name %q, got %q", want, servedEvidence)
		}
	}

	cliEvidence := strings.ToLower(strings.Join(append(append([]string{}, f77.CLISurface...), f77.FacetEvidence.CLI.Evidence...), "\n"))
	if !strings.Contains(cliEvidence, "ai rca") {
		t.Errorf("TRACE-038: F77 CLI evidence must name ai rca, got %q", cliEvidence)
	}

	testRefs := map[string]bool{}
	for _, ref := range f77.FacetEvidence.Test.Refs {
		testRefs[ref] = true
	}
	for _, wantRef := range []string{
		"internal/server/aisurface_served_test.go",
		"internal/api/aisurface_contract_test.go",
		"internal/api/feature_parity_test.go",
		"internal/cli/feature_parity_test.go",
		"web/src/__tests__/assistant.test.tsx",
		"internal/featureparity/feature_served_ga_coverage_test.go",
	} {
		if !testRefs[wantRef] {
			t.Errorf("TRACE-038: F77 test facet must cite %s", wantRef)
		}
	}

	testEvidence := strings.ToLower(strings.Join(f77.FacetEvidence.Test.Evidence, "\n"))
	for _, want := range []string{
		"trace-038",
		"testservedrcagroundedandcited",
		"testservedaIinjectioninertandredacted",
		"testservedaisurfacedisabledfailsclosed",
		"assistant ui",
		"feature parity",
	} {
		if !strings.Contains(testEvidence, strings.ToLower(want)) {
			t.Errorf("TRACE-038: F77 test evidence must mention %q, got %q", want, testEvidence)
		}
	}

	residual := strings.ToLower(strings.Join([]string{f77.TargetMapping, f77.AcceptanceTest}, "\n"))
	for _, want := range []string{"roadmap residual", "timeline", "export"} {
		if !strings.Contains(residual, want) {
			t.Errorf("TRACE-038: F77 must explicitly park richer RCA timeline/export workflow polish as a roadmap residual; missing %q in %q", want, residual)
		}
	}
}

// TestTRACE039MCPServerRemainsConditionalUntilEnabled locks TRACE-039.
// The served MCP server workflow belongs in the GA denominator via the MCP routes,
// CLI commands, and Assistant tool UI; richer external-agent/session-history polish
// remains visible as a roadmap residual instead of excluding F78 from GA.
func TestTRACE039MCPServerRemainsConditionalUntilEnabled(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f78, ok := featureByID(catalog, "F78")
	if !ok {
		t.Fatal("F78 trstctl MCP server row is missing")
	}
	requireResidualServedState(t, "TRACE-039", f78, "conditional")

	servedEvidence := strings.ToLower(strings.Join([]string{
		f78.BackendStatus,
		f78.CurrentMapping,
		strings.Join(f78.SourceBackend, "\n"),
		strings.Join(f78.APISurface, "\n"),
		strings.Join(f78.FacetEvidence.Served.Evidence, "\n"),
		strings.Join(f78.FacetEvidence.UI.Evidence, "\n"),
		strings.Join(f78.FacetEvidence.API.Evidence, "\n"),
	}, "\n"))
	for _, want := range []string{
		"/api/v1/mcp/tools",
		"/api/v1/mcp/tools/{tool}",
		"read-only",
		"route-backed",
		"rest",
		"citations",
		"rate-limit",
		"denied",
		"external-agent-safe",
	} {
		if !strings.Contains(servedEvidence, want) {
			t.Errorf("TRACE-039: F78 served evidence must name %q, got %q", want, servedEvidence)
		}
	}

	cliEvidence := strings.ToLower(strings.Join(append(append([]string{}, f78.CLISurface...), f78.FacetEvidence.CLI.Evidence...), "\n"))
	for _, want := range []string{"mcp tools", "mcp call"} {
		if !strings.Contains(cliEvidence, want) {
			t.Errorf("TRACE-039: F78 CLI evidence must name %q, got %q", want, cliEvidence)
		}
	}

	testRefs := map[string]bool{}
	for _, ref := range f78.FacetEvidence.Test.Refs {
		testRefs[ref] = true
	}
	for _, wantRef := range []string{
		"internal/api/aisurface_contract_test.go",
		"internal/featureparity/mcp_rest_coverage_test.go",
		"internal/api/feature_parity_test.go",
		"internal/cli/feature_parity_test.go",
		"web/src/__tests__/assistant.test.tsx",
		"internal/featureparity/feature_served_ga_coverage_test.go",
	} {
		if !testRefs[wantRef] {
			t.Errorf("TRACE-039: F78 test facet must cite %s", wantRef)
		}
	}

	testEvidence := strings.ToLower(strings.Join(f78.FacetEvidence.Test.Evidence, "\n"))
	for _, want := range []string{
		"trace-039",
		"testmcprestroutetoolsinheritrestguardandidempotency",
		"testmcprestcoverageguardcoversservedroutes",
		"assistant ui",
		"feature parity",
	} {
		if !strings.Contains(testEvidence, strings.ToLower(want)) {
			t.Errorf("TRACE-039: F78 test evidence must mention %q, got %q", want, testEvidence)
		}
	}

	residual := strings.ToLower(strings.Join([]string{f78.TargetMapping, f78.AcceptanceTest}, "\n"))
	for _, want := range []string{"roadmap residual", "external agent identity", "session history"} {
		if !strings.Contains(residual, want) {
			t.Errorf("TRACE-039: F78 must explicitly park richer external-agent/session-history polish as a roadmap residual; missing %q in %q", want, residual)
		}
	}
}

func featureByID(catalog Catalog, id string) (Item, bool) {
	for _, item := range catalog.Items {
		if item.FeatureID == id {
			return item, true
		}
	}
	return Item{}, false
}
