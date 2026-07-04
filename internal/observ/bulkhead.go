// SPDX-License-Identifier: MPL-2.0

package observ

import (
	"sync"

	"trstctl.com/trstctl/internal/bulkhead"
)

// BulkheadMetrics publishes AN-7 pool shape and pressure without tenant or
// secret labels. Live values are gauges; lifetime work/rejection counters are
// emitted as monotonic counters by adding only each sample's positive delta.
type BulkheadMetrics struct {
	workers  *GaugeVec
	capacity *GaugeVec
	queued   *GaugeVec

	submitted *CounterVec
	completed *CounterVec
	rejected  *CounterVec
	panicked  *CounterVec

	mu   sync.Mutex
	last map[string]bulkhead.Stats
}

// NewBulkheadMetrics registers the bulkhead metrics on r.
func NewBulkheadMetrics(r *Registry) *BulkheadMetrics {
	return &BulkheadMetrics{
		workers: r.GaugeVec("trstctl_bulkhead_workers",
			"Configured worker count for each subsystem bulkhead.", []string{"subsystem"}),
		capacity: r.GaugeVec("trstctl_bulkhead_queue_capacity",
			"Configured queue capacity for each subsystem bulkhead.", []string{"subsystem"}),
		queued: r.GaugeVec("trstctl_bulkhead_queue_depth",
			"Currently queued tasks for each subsystem bulkhead.", []string{"subsystem"}),
		submitted: r.CounterVec("trstctl_bulkhead_submitted_total",
			"Tasks accepted by each subsystem bulkhead.", []string{"subsystem"}),
		completed: r.CounterVec("trstctl_bulkhead_completed_total",
			"Tasks completed by each subsystem bulkhead.", []string{"subsystem"}),
		rejected: r.CounterVec("trstctl_bulkhead_rejected_total",
			"Tasks rejected by each subsystem bulkhead.", []string{"subsystem"}),
		panicked: r.CounterVec("trstctl_bulkhead_panicked_total",
			"Tasks recovered after panicking inside each subsystem bulkhead.", []string{"subsystem"}),
		last: map[string]bulkhead.Stats{},
	}
}

// Observe records one snapshot of all known subsystem pools.
func (m *BulkheadMetrics) Observe(stats []bulkhead.Stats) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, st := range stats {
		m.workers.WithLabelValues(st.Name).Set(float64(st.Workers))
		m.capacity.WithLabelValues(st.Name).Set(float64(st.Capacity))
		m.queued.WithLabelValues(st.Name).Set(float64(st.Queued))

		prev := m.last[st.Name]
		addCounterDelta(m.submitted, st.Name, prev.Submitted, st.Submitted)
		addCounterDelta(m.completed, st.Name, prev.Completed, st.Completed)
		addCounterDelta(m.rejected, st.Name, prev.Rejected, st.Rejected)
		addCounterDelta(m.panicked, st.Name, prev.Panicked, st.Panicked)
		m.last[st.Name] = st
	}
}

func addCounterDelta(vec *CounterVec, subsystem string, previous, current int64) {
	if current < previous {
		return
	}
	vec.WithLabelValues(subsystem).Add(float64(current - previous))
}
