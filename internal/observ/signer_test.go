package observ_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/observ"
)

func TestSignerMetricsExposeUpAndRestarts(t *testing.T) {
	reg := observ.NewRegistry()
	m := observ.NewSignerMetrics(reg)

	// Down, no restarts yet.
	m.Observe(false, 0)
	if got := renderProm(t, reg); !strings.Contains(got, "trstctl_signer_up 0") {
		t.Errorf("expected signer_up 0 while down:\n%s", got)
	}

	// Up, after two restarts.
	m.Observe(true, 2)
	got := renderProm(t, reg)
	if !strings.Contains(got, "trstctl_signer_up 1") {
		t.Errorf("expected signer_up 1 while healthy:\n%s", got)
	}
	if !strings.Contains(got, "trstctl_signer_restarts_total 2") {
		t.Errorf("expected restarts_total 2:\n%s", got)
	}
}

func TestSignerRestartsCounterIsMonotonic(t *testing.T) {
	reg := observ.NewRegistry()
	m := observ.NewSignerMetrics(reg)

	m.Observe(true, 3)
	// A lower cumulative value (e.g. a fresh supervisor) must not decrement the
	// exported counter.
	m.Observe(true, 1)
	if got := renderProm(t, reg); !strings.Contains(got, "trstctl_signer_restarts_total 3") {
		t.Errorf("counter must not go backwards; want 3:\n%s", got)
	}
	// A higher value adds only the delta.
	m.Observe(true, 5)
	if got := renderProm(t, reg); !strings.Contains(got, "trstctl_signer_restarts_total 5") {
		t.Errorf("want 5 after delta:\n%s", got)
	}
}

func renderProm(t *testing.T, reg *observ.Registry) string {
	t.Helper()
	var sb strings.Builder
	if err := reg.WriteProm(&sb); err != nil {
		t.Fatal(err)
	}
	return sb.String()
}
