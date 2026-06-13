package observ

import "sync"

// SignerMetrics is the shared-library surface for the out-of-process signer's
// telemetry (SF.3). The signer is a separate, HTTP-less process (AN-4), so it
// cannot expose its own /metrics; the control plane samples its health and
// restart count and publishes them here, on the same registry as everything
// else. New components observe the signer through this helper rather than
// re-deriving metric names.
//
//	signer up:        trustctl_signer_up               (1 healthy, 0 down)
//	signer restarts:  trustctl_signer_restarts_total   (cumulative relaunches)
type SignerMetrics struct {
	up       *Gauge
	restarts *Counter

	mu   sync.Mutex
	last uint64 // last observed cumulative restart count, to add only the delta
}

// NewSignerMetrics registers the signer metrics on r (idempotent: the underlying
// registry returns existing series if the names already exist).
func NewSignerMetrics(r *Registry) *SignerMetrics {
	return &SignerMetrics{
		up: r.Gauge("trustctl_signer_up",
			"1 if the out-of-process signer is currently healthy, else 0."),
		restarts: r.CounterVec("trustctl_signer_restarts_total",
			"Times the signer child process has been relaunched by the supervisor.", nil).
			WithLabelValues(),
	}
}

// Observe records one sample: whether the signer is currently up, and the
// supervisor's cumulative restart count. The restart counter is monotonic, so
// only the increase since the previous sample is added (a supervisor that resets
// — e.g. a fresh process — never decrements the exported counter).
func (m *SignerMetrics) Observe(up bool, cumulativeRestarts uint64) {
	if up {
		m.up.Set(1)
	} else {
		m.up.Set(0)
	}
	m.mu.Lock()
	if cumulativeRestarts > m.last {
		m.restarts.Add(float64(cumulativeRestarts - m.last))
		m.last = cumulativeRestarts
	}
	m.mu.Unlock()
}
