// SPDX-License-Identifier: BUSL-1.1

package observ_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/observ"
)

func TestBulkheadMetricsExposeAllStatsFields(t *testing.T) {
	reg := observ.NewRegistry()
	metrics := observ.NewBulkheadMetrics(reg)
	metrics.Observe([]bulkhead.Stats{{
		Name:      bulkhead.SubsystemOutbox,
		Workers:   4,
		Capacity:  256,
		Queued:    3,
		Submitted: 10,
		Completed: 7,
		Rejected:  2,
		Panicked:  1,
	}})
	metrics.Observe([]bulkhead.Stats{{
		Name:      bulkhead.SubsystemOutbox,
		Workers:   4,
		Capacity:  256,
		Queued:    1,
		Submitted: 12,
		Completed: 9,
		Rejected:  2,
		Panicked:  1,
	}})

	var sb strings.Builder
	if err := reg.WriteProm(&sb); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	for _, want := range []string{
		`trstctl_bulkhead_workers{subsystem="outbox"} 4`,
		`trstctl_bulkhead_queue_capacity{subsystem="outbox"} 256`,
		`trstctl_bulkhead_queue_depth{subsystem="outbox"} 1`,
		`trstctl_bulkhead_submitted_total{subsystem="outbox"} 12`,
		`trstctl_bulkhead_completed_total{subsystem="outbox"} 9`,
		`trstctl_bulkhead_rejected_total{subsystem="outbox"} 2`,
		`trstctl_bulkhead_panicked_total{subsystem="outbox"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("bulkhead metric missing %q from:\n%s", want, out)
		}
	}
}
