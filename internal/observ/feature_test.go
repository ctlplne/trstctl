package observ_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/observ"
)

// TestFeatureMetricsExposition is the COVER-009 acceptance: per-feature telemetry
// renders a non-sensitive Prometheus signal for every feature in the manifest. It
// exercises each manifested feature/action through the served helper, renders the
// registry, and asserts (1) every feature emits an operations counter line and a
// duration histogram, and (2) NO label carries tenant_id or secret/identifying data
// (AN-1, AN-8). Before this change the registry had only HTTP/process metrics and no
// per-feature signal, so this test had nothing to assert.
func TestFeatureMetricsExposition(t *testing.T) {
	reg := observ.NewRegistry()
	fm := observ.NewFeatureMetrics(reg)

	// Drive every manifested feature/action with one success and one error, plus a
	// measurable duration, exactly as the served paths do.
	for _, fs := range observ.FeatureTelemetryManifest {
		if fs.Feature == "signer" {
			continue // signer up/restart signals come from SignerMetrics, asserted below
		}
		for _, action := range fs.Actions {
			fm.Observe(fs.Feature, action, observ.OutcomeSuccess, 0.2)
			fm.Observe(fs.Feature, action, observ.OutcomeError, 0.4)
		}
	}
	// The signer is a separate HTTP-less process (AN-4); its signal is the up gauge +
	// restart counter on the same registry. Exercise it so the manifest's "signer"
	// entry is backed by a real exposition line too.
	sm := observ.NewSignerMetrics(reg)
	sm.Observe(true, 3)

	var sb strings.Builder
	if err := reg.WriteProm(&sb); err != nil {
		t.Fatal(err)
	}
	out := sb.String()

	// (1) Every non-signer manifested feature emits a counter and histogram signal.
	for _, fs := range observ.FeatureTelemetryManifest {
		if fs.Feature == "signer" {
			if !strings.Contains(out, "trstctl_signer_up") {
				t.Errorf("manifest lists signer but exposition has no trstctl_signer_up")
			}
			continue
		}
		for _, action := range fs.Actions {
			wantCounter := `trstctl_feature_operations_total{feature="` + fs.Feature + `",action="` + action + `",outcome="success"}`
			if !strings.Contains(out, wantCounter) {
				t.Errorf("missing per-feature counter for %s/%s\nwant line containing: %s", fs.Feature, action, wantCounter)
			}
			wantHist := `trstctl_feature_operation_duration_seconds_count{feature="` + fs.Feature + `",action="` + action + `"}`
			if !strings.Contains(out, wantHist) {
				t.Errorf("missing per-feature duration histogram for %s/%s\nwant line containing: %s", fs.Feature, action, wantHist)
			}
		}
	}

	// (2) No label carries tenant or secret data. The per-feature metrics are labelled
	// only by feature/action/outcome; assert the forbidden label keys never appear on
	// any feature exposition line.
	forbidden := []string{"tenant_id", "tenant=", "subject", "serial", "fingerprint", "secret", "token", "email"}
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "trstctl_feature_") {
			continue
		}
		for _, bad := range forbidden {
			if strings.Contains(line, bad) {
				t.Errorf("per-feature metric line leaks %q label/value (AN-1/AN-8): %s", bad, line)
			}
		}
	}
}

// TestFeatureManifestLabelsAreNonSensitive locks the manifest's label contract: the
// per-feature label set must be exactly feature/action/outcome — never tenant or
// secret — so a future edit cannot quietly add a high-cardinality or identifying
// label. The exposition test above proves the rendered lines respect it; this proves
// the documented contract (the manifest) does too.
func TestFeatureManifestLabelsAreNonSensitive(t *testing.T) {
	if len(observ.FeatureTelemetryManifest) == 0 {
		t.Fatal("feature telemetry manifest is empty; COVER-009 requires per-feature signals")
	}
	// The high-risk features the finding named must all be present.
	want := map[string]bool{"issuance": false, "revocation": false, "deployment": false, "discovery": false, "signer": false}
	for _, fs := range observ.FeatureTelemetryManifest {
		if fs.FeatureID == "" || fs.Feature == "" || len(fs.Actions) == 0 {
			t.Errorf("manifest row %+v is missing feature id, feature, or actions", fs)
		}
		// A feature/action label value must never look tenant- or secret-derived.
		for _, bad := range []string{"tenant", "secret", "token", "subject"} {
			if strings.Contains(fs.Feature, bad) {
				t.Errorf("manifest feature label %q contains forbidden token %q", fs.Feature, bad)
			}
			for _, a := range fs.Actions {
				if strings.Contains(a, bad) {
					t.Errorf("manifest action label %q (feature %s) contains forbidden token %q", a, fs.Feature, bad)
				}
			}
		}
		if _, ok := want[fs.Feature]; ok {
			want[fs.Feature] = true
		}
	}
	for feat, present := range want {
		if !present {
			t.Errorf("COVER-009 requires a per-feature signal for high-risk feature %q; manifest is missing it", feat)
		}
	}
}

// TestNilFeatureMetricsIsSafe proves the helper is a safe no-op when no registry is
// wired, so a deployment without metrics never panics on a served feature path.
func TestNilFeatureMetricsIsSafe(t *testing.T) {
	var fm *observ.FeatureMetrics // nil
	fm.Observe("issuance", "issue", observ.OutcomeSuccess, 0.1)
	if hook := fm.Hook(); hook != nil {
		t.Error("nil FeatureMetrics.Hook() should be nil so the API treats it as 'no telemetry'")
	}
	if hook := observ.NewFeatureMetrics(observ.NewRegistry()).Hook(); hook == nil {
		t.Error("a real FeatureMetrics.Hook() must be non-nil")
	}
}
