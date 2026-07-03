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

// TestTRACE019ACMERowSplitsServedGAFromRoadmapResidual locks the remediation for
// TRACE-019. The served ACME protocol workflow belongs in the GA denominator; the
// richer ACME admin console remains visible as a roadmap residual and must not be
// hidden inside a conditional F5 row.
func TestTRACE019ACMERowSplitsServedGAFromRoadmapResidual(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f5, ok := featureByID(catalog, "F5")
	if !ok {
		t.Fatal("F5 Built-in ACME server row is missing")
	}
	if f5.ServedState != "served" {
		t.Fatalf("TRACE-019: F5 must be promoted to served after splitting residual scope, got served_state=%q", f5.ServedState)
	}
	if f5.GAServedScope != "" && f5.GAServedScope != gaServedScopeIn {
		t.Fatalf("TRACE-019: served F5 must be in the GA denominator, got ga_served_scope=%q", f5.GAServedScope)
	}
	if strings.TrimSpace(f5.GAScopeReason) != "" {
		t.Fatalf("TRACE-019: served F5 must not carry the old residual GA exclusion, got %q", f5.GAScopeReason)
	}

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

// TestTRACE020ESTRowSplitsServedGAFromRoadmapResidual locks the remediation for
// TRACE-020. The served EST protocol workflow belongs in the GA denominator; the
// richer EST admin console remains visible as a roadmap residual and must not be
// hidden inside a conditional F22 row.
func TestTRACE020ESTRowSplitsServedGAFromRoadmapResidual(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f22, ok := featureByID(catalog, "F22")
	if !ok {
		t.Fatal("F22 EST server row is missing")
	}
	if f22.ServedState != "served" {
		t.Fatalf("TRACE-020: F22 must be promoted to served after splitting residual scope, got served_state=%q", f22.ServedState)
	}
	if f22.GAServedScope != "" && f22.GAServedScope != gaServedScopeIn {
		t.Fatalf("TRACE-020: served F22 must be in the GA denominator, got ga_served_scope=%q", f22.GAServedScope)
	}
	if strings.TrimSpace(f22.GAScopeReason) != "" {
		t.Fatalf("TRACE-020: served F22 must not carry the old residual GA exclusion, got %q", f22.GAScopeReason)
	}

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

// TestTRACE021SCEPRowSplitsServedGAFromRoadmapResidual locks the remediation for
// TRACE-021. The served SCEP protocol workflow belongs in the GA denominator; the
// richer SCEP admin console remains visible as a roadmap residual and must not be
// hidden inside a conditional F23 row.
func TestTRACE021SCEPRowSplitsServedGAFromRoadmapResidual(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f23, ok := featureByID(catalog, "F23")
	if !ok {
		t.Fatal("F23 SCEP server row is missing")
	}
	if f23.ServedState != "served" {
		t.Fatalf("TRACE-021: F23 must be promoted to served after splitting residual scope, got served_state=%q", f23.ServedState)
	}
	if f23.GAServedScope != "" && f23.GAServedScope != gaServedScopeIn {
		t.Fatalf("TRACE-021: served F23 must be in the GA denominator, got ga_served_scope=%q", f23.GAServedScope)
	}
	if strings.TrimSpace(f23.GAScopeReason) != "" {
		t.Fatalf("TRACE-021: served F23 must not carry the old residual GA exclusion, got %q", f23.GAScopeReason)
	}

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

// TestTRACE022CMPRowSplitsServedGAFromRoadmapResidual locks the remediation for
// TRACE-022. The served CMP p10cr workflow belongs in the GA denominator; the
// richer CMP admin console remains visible as a roadmap residual and must not be
// hidden inside a conditional F55 row.
func TestTRACE022CMPRowSplitsServedGAFromRoadmapResidual(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f55, ok := featureByID(catalog, "F55")
	if !ok {
		t.Fatal("F55 CMP server row is missing")
	}
	if f55.ServedState != "served" {
		t.Fatalf("TRACE-022: F55 must be promoted to served after splitting residual scope, got served_state=%q", f55.ServedState)
	}
	if f55.GAServedScope != "" && f55.GAServedScope != gaServedScopeIn {
		t.Fatalf("TRACE-022: served F55 must be in the GA denominator, got ga_served_scope=%q", f55.GAServedScope)
	}
	if strings.TrimSpace(f55.GAScopeReason) != "" {
		t.Fatalf("TRACE-022: served F55 must not carry the old residual GA exclusion, got %q", f55.GAScopeReason)
	}

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

// TestTRACE023SPIFFERowSplitsServedGAFromRoadmapResidual locks the remediation for
// TRACE-023. The served SPIFFE Workload API UDS workflow belongs in the GA
// denominator; the richer SPIFFE admin console remains visible as a roadmap residual
// and must not be hidden inside a conditional F24 row.
func TestTRACE023SPIFFERowSplitsServedGAFromRoadmapResidual(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	f24, ok := featureByID(catalog, "F24")
	if !ok {
		t.Fatal("F24 SPIFFE Workload API row is missing")
	}
	if f24.ServedState != "served" {
		t.Fatalf("TRACE-023: F24 must be promoted to served after splitting residual scope, got served_state=%q", f24.ServedState)
	}
	if f24.GAServedScope != "" && f24.GAServedScope != gaServedScopeIn {
		t.Fatalf("TRACE-023: served F24 must be in the GA denominator, got ga_served_scope=%q", f24.GAServedScope)
	}
	if strings.TrimSpace(f24.GAScopeReason) != "" {
		t.Fatalf("TRACE-023: served F24 must not carry the old residual GA exclusion, got %q", f24.GAScopeReason)
	}

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

func featureByID(catalog Catalog, id string) (Item, bool) {
	for _, item := range catalog.Items {
		if item.FeatureID == id {
			return item, true
		}
	}
	return Item{}, false
}
