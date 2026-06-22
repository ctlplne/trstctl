package observ

import "sync"

// This file adds per-feature telemetry (COVER-009). The audit finding was that the
// control plane's metrics were HTTP/process-oriented (trstctl_http_requests_total by
// method/route/status, signer up/restarts, projection lag) with no signal scoped to
// the product features an operator actually reasons about — "are issuances
// succeeding?", "how long does a discovery run take to enqueue?". You could not
// answer those from telemetry alone for the highest-risk features.
//
// FeatureMetrics is the served, low-cardinality answer. It exposes ONE counter and
// ONE histogram, both partitioned only by (feature, action, outcome) — never by
// tenant_id, subject, serial, fingerprint, or any secret/identifying value (AN-1,
// AN-8). The set of feature/action label values is closed and small (it comes from
// FeatureTelemetryManifest below), so cardinality is bounded and no opaque
// identifier can leak into a label.
//
// FeatureTelemetryManifest is the source-of-truth list the audit finding asked for:
// the features that carry per-feature signals, the metric names, and the exact label
// set. A test (feature_test.go) asserts the manifest's label set excludes tenant and
// secret data and that every manifested feature actually emits a signal.

const (
	// featureOpsMetric counts served feature operations by outcome.
	featureOpsMetric = "trstctl_feature_operations_total"
	// featureDurationMetric is the served feature operation latency histogram.
	featureDurationMetric = "trstctl_feature_operation_duration_seconds"
)

// Outcome label values for a feature operation. They are a closed set so the label
// stays low-cardinality.
const (
	OutcomeSuccess = "success"
	OutcomeError   = "error"
)

// featureLabels is the ONLY label set per-feature metrics carry. It is deliberately
// free of tenant_id and any secret/identifying field (AN-1, AN-8): an operator can
// see issuance health without the metric backend ever learning which tenant or which
// credential was involved.
var featureLabels = []string{"feature", "action", "outcome"}

// FeatureSignal documents one feature's per-feature telemetry in the manifest: the
// catalog feature id, the actions that emit a signal, and the metric names. It is
// the disclosed contract for COVER-009.
type FeatureSignal struct {
	FeatureID string   // catalog feature id, e.g. "F4"
	Feature   string   // stable feature label value used in the metric, e.g. "issuance"
	Actions   []string // action label values this feature emits, e.g. ["issue","revoke"]
}

// FeatureTelemetryManifest is the source-of-truth list of features that carry
// per-feature signals and the label values they use (COVER-009). The highest-risk
// served features are covered: issuance, revocation, deployment, discovery, and the
// out-of-process signer. Adding a feature signal means adding it here; the test asserts
// every manifested feature/action actually produces an exposition line, and that the
// label set never carries tenant or secret data.
var FeatureTelemetryManifest = []FeatureSignal{
	{FeatureID: "F4", Feature: "issuance", Actions: []string{"issue"}},
	{FeatureID: "F47", Feature: "revocation", Actions: []string{"revoke"}},
	{FeatureID: "F6", Feature: "deployment", Actions: []string{"deploy", "renew"}},
	{FeatureID: "F2", Feature: "discovery", Actions: []string{"start_run"}},
	{FeatureID: "F1", Feature: "inventory", Actions: []string{"ingest"}},
	// The signer is a separate HTTP-less process (AN-4); its up/restart signals are
	// published via SignerMetrics on this same registry. It is listed here so the
	// manifest is the single place an operator reads "which features have signals",
	// and the test cross-checks the SignerMetrics names against it.
	{FeatureID: "SF", Feature: "signer", Actions: []string{"sign"}},
}

// FeatureMetrics records per-feature operation signals on a registry (COVER-009).
// It is wired into the served mutating feature paths (issuance/revocation/deployment
// via the lifecycle transition handler, discovery run start, certificate ingest) so
// an operator can answer "is feature X healthy" from /metrics alone.
type FeatureMetrics struct {
	ops *CounterVec
	dur *HistogramVec
}

// featureBuckets are latency buckets (seconds) for a feature operation — coarser at
// the top than the HTTP histogram because feature work (issuance, a discovery enqueue)
// can be slower than a bare request.
var featureBuckets = []float64{0.005, 0.025, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

// NewFeatureMetrics registers the per-feature metrics on r (idempotent: the registry
// returns existing series if the names already exist). A nil registry yields a nil
// *FeatureMetrics whose methods are safe no-ops, so callers need no nil checks.
func NewFeatureMetrics(r *Registry) *FeatureMetrics {
	if r == nil {
		return nil
	}
	return &FeatureMetrics{
		ops: r.CounterVec(featureOpsMetric,
			"Served feature operations by feature, action, and outcome (no tenant or secret labels).", featureLabels),
		dur: r.HistogramVec(featureDurationMetric,
			"Served feature operation latency in seconds by feature and action.", featureBuckets,
			[]string{"feature", "action"}),
	}
}

// Observe records one served feature operation: its feature, action, and outcome
// (OutcomeSuccess or OutcomeError), plus its duration in seconds. feature and action
// MUST be closed-set label values from the manifest, never tenant- or
// credential-derived strings (that would both leak and explode cardinality). A nil
// receiver is a no-op.
func (m *FeatureMetrics) Observe(feature, action, outcome string, seconds float64) {
	if m == nil {
		return
	}
	m.ops.WithLabelValues(feature, action, outcome).Inc()
	m.dur.WithLabelValues(feature, action).Observe(seconds)
}

// Hook returns a closure the served API layer calls on a feature operation. It is the
// wiring seam: the API depends only on a func value (no observ import), and the server
// passes this hook. A nil receiver returns nil, which the API treats as "no per-feature
// telemetry configured".
func (m *FeatureMetrics) Hook() func(feature, action, outcome string, seconds float64) {
	if m == nil {
		return nil
	}
	return m.Observe
}

// featureNames returns the set of manifested feature label values, used by the test
// and by any consumer that wants to validate a label value is in the closed set.
var featureNamesOnce sync.Once
var featureNamesCache map[string]struct{}

// ManifestFeatureNames returns the closed set of feature label values in the manifest.
func ManifestFeatureNames() map[string]struct{} {
	featureNamesOnce.Do(func() {
		featureNamesCache = make(map[string]struct{}, len(FeatureTelemetryManifest))
		for _, fs := range FeatureTelemetryManifest {
			featureNamesCache[fs.Feature] = struct{}{}
		}
	})
	out := make(map[string]struct{}, len(featureNamesCache))
	for k := range featureNamesCache {
		out[k] = struct{}{}
	}
	return out
}
