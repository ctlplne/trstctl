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

func featureByID(catalog Catalog, id string) (Item, bool) {
	for _, item := range catalog.Items {
		if item.FeatureID == id {
			return item, true
		}
	}
	return Item{}, false
}
