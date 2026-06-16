package example_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
	"trstctl.com/trstctl/internal/ca/example"
)

// TestExamplePluginPassesConformance is the S4.6 acceptance: a CA plugin
// generated from the template — the example, which fills in only the CA-specific
// Backend — builds and passes the shared conformance suite.
func TestExamplePluginPassesConformance(t *testing.T) {
	p, err := example.New("example-ca")
	if err != nil {
		t.Fatalf("example.New: %v", err)
	}

	// It is a ca.CA on the same interface every authority satisfies.
	var _ ca.CA = p

	report := catemplate.Conformance(context.Background(), p)
	if !report.OK() {
		t.Fatalf("example plugin failed conformance: %+v", report.Checks)
	}
	// The suite must actually exercise the plugin, not pass vacuously.
	if len(report.Checks) < 4 {
		t.Errorf("conformance ran only %d checks, want several", len(report.Checks))
	}
}
