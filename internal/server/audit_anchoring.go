// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/observ"
)

// auditAnchoring supervises the licensed continuous anchoring worker (A147)
// on the leader, and reports its state to the audit anchoring status surface.
type auditAnchoring struct {
	worker   editionseam.AuditAnchorWorker
	state    string // configured state when no worker runs: "unlicensed" or "off"
	detail   string
	cadence  time.Duration
	runs     *observ.Counter
	anchored *observ.Counter
	failures *observ.Counter
	lastOK   *observ.Gauge

	mu         sync.Mutex
	lastRunAt  time.Time
	lastFailed bool
}

func newAuditAnchoring(registry *observ.Registry, worker editionseam.AuditAnchorWorker, licensed bool, cadence time.Duration, offReason string) *auditAnchoring {
	a := &auditAnchoring{worker: worker, cadence: cadence}
	switch {
	case worker != nil:
		a.cadence = worker.Interval()
	case !licensed:
		a.state, a.detail = "unlicensed", "Continuous audit anchoring is part of Enterprise audit compliance."
	default:
		a.state, a.detail = "off", offReason
	}
	if registry != nil && worker != nil {
		a.runs = registry.CounterVec("trstctl_audit_anchor_runs_total", "Continuous audit anchoring passes.", nil).WithLabelValues()
		a.anchored = registry.CounterVec("trstctl_audit_anchors_total", "Tenant audit chains timestamped by continuous anchoring.", nil).WithLabelValues()
		a.failures = registry.CounterVec("trstctl_audit_anchor_failures_total", "Continuous audit anchoring passes that failed.", nil).WithLabelValues()
		a.lastOK = registry.Gauge("trstctl_audit_anchor_last_success_timestamp_seconds", "Unix timestamp of the last successful continuous audit anchoring pass.")
	}
	return a
}

// RunAuditAnchoring runs continuous audit anchoring on its cadence until ctx is
// canceled. It anchors once on start, so a restart does not leave the newest
// records waiting a full interval. A deployment without the worker returns at
// once.
func (s *Server) RunAuditAnchoring(ctx context.Context) {
	if s.anchoring == nil || s.anchoring.worker == nil {
		return
	}
	_, _ = s.RunAuditAnchoringOnce(ctx)
	t := time.NewTicker(s.anchoring.worker.Interval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = s.RunAuditAnchoringOnce(ctx)
		}
	}
}

// RunAuditAnchoringOnce performs one anchoring pass and records its outcome.
// It is exported so tests can drive the assembled server through one pass.
func (s *Server) RunAuditAnchoringOnce(ctx context.Context) (editionseam.AuditAnchorSummary, error) {
	a := s.anchoring
	if a == nil || a.worker == nil {
		return editionseam.AuditAnchorSummary{}, nil
	}
	sum, err := a.worker.RunOnce(ctx)
	a.mu.Lock()
	a.lastRunAt, a.lastFailed = time.Now().UTC(), err != nil
	a.mu.Unlock()
	if a.runs != nil {
		a.runs.Inc()
		a.anchored.Add(float64(sum.TenantsAnchored))
	}
	if err != nil {
		if a.failures != nil {
			a.failures.Inc()
		}
		s.logger.Error("audit anchoring run failed", slog.String("error", err.Error()))
		return sum, err
	}
	if a.lastOK != nil {
		a.lastOK.Set(float64(time.Now().Unix()))
	}
	if sum.TenantsAnchored > 0 {
		s.logger.Info("audit anchoring timestamped tenant audit chains", slog.Int("tenants", sum.TenantsAnchored))
	}
	return sum, nil
}

// status reports the supervisor's state for the status surface.
func (a *auditAnchoring) status() api.AuditAnchoringRuntime {
	if a == nil {
		return api.AuditAnchoringRuntime{State: "unlicensed", Detail: "Continuous audit anchoring is part of Enterprise audit compliance."}
	}
	if a.worker == nil {
		return api.AuditAnchoringRuntime{State: a.state, Detail: a.detail}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	out := api.AuditAnchoringRuntime{State: "anchoring", Cadence: a.cadence, LastRunAt: a.lastRunAt}
	if a.lastFailed {
		// The cause names a tenant and stays in the server log; a tenant's
		// status says only that the pass failed.
		out.State = "failing"
		out.Detail = "The last anchoring pass failed: the timestamp authority or the audit log could not be reached. The server log has the cause; the next pass retries."
	}
	return out
}

// auditAnchorCadence is the continuous anchoring cadence the deployment runs
// at, or zero with the reason it is off.
func auditAnchorCadence(d Deps) (time.Duration, string) {
	switch {
	case d.AuditAnchorInterval <= 0:
		return 0, "Continuous anchoring is off: audit.anchor_interval is 0s."
	case !d.Protocols.TSA.Enabled:
		return 0, "Continuous anchoring is off: protocols.tsa is not enabled, so there is no timestamp authority."
	default:
		return d.AuditAnchorInterval, ""
	}
}

// auditAnchorIntervalFromConfig reads audit.anchor_interval; configuration
// validation has already refused an invalid value.
func auditAnchorIntervalFromConfig(cfg *config.Config) time.Duration {
	interval, err := cfg.Audit.AnchorIntervalDuration()
	if err != nil {
		return 0
	}
	return interval
}
