// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"errors"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/observ"
	"trstctl.com/trstctl/internal/store"
)

// loadSensitiveProbeBudget bounds each datastore-reading readiness probe so a
// saturated request pool cannot stretch /readyz past a probe's own timeout.
const loadSensitiveProbeBudget = time.Second

// loadSensitiveGrace is how long a datastore-reading probe may keep being shed
// by load before readiness stops calling it "degraded" and fails it. A tenant
// burst sheds for seconds; a datastore that has been too slow for this long is
// a stall, and a stalled replica must leave rotation (DP2-054 review).
const loadSensitiveGrace = 2 * time.Minute

// shedProbe wraps a readiness probe that reads through the shared request pool.
// Under AN-7 the main pool sheds load with a 503 while it is saturated; that is
// correct serving behaviour, not a reason to take the replica out of rotation,
// so a pool-acquire/statement timeout (store.IsBusy) or an exhausted probe
// budget answers observ.Degraded rather than failing readiness. PostgreSQL
// reachability is proven separately by the db check on the dedicated probe pool
// (DP2-054). A genuine probe failure (a real projection stall, a missing recovery
// authority) still fails, and so does shedding that outlasts loadSensitiveGrace.
type shedProbe struct {
	name  string
	probe func(context.Context) error
	gauge *observ.Gauge // 1 while the probe is being shed, 0 otherwise; may be nil
	now   func() time.Time

	mu        sync.Mutex
	shedSince time.Time // zero when the probe last answered ok or failed for real
}

func readyDespiteBackpressure(name string, probe func(context.Context) error, gauge *observ.Gauge) func(context.Context) error {
	sp := &shedProbe{name: name, probe: probe, gauge: gauge, now: time.Now}
	return sp.run
}

func (sp *shedProbe) run(ctx context.Context) error {
	// A saturated pool makes the probe wait for the whole acquire window;
	// readiness must answer promptly, so the probe gets a short budget and
	// running out of it is read the same way as the store's busy signal.
	probeCtx, cancel := context.WithTimeout(ctx, loadSensitiveProbeBudget)
	defer cancel()
	err := sp.probe(probeCtx)
	if err == nil {
		sp.setShed(false)
		return nil
	}
	// Some probes wrap their datastore error opaquely; running out of the
	// budget is itself the busy signal. A probe that fails fast (a genuine
	// stall or a missing authority) still fails readiness.
	shed := store.IsBusy(err) || errors.Is(err, context.DeadlineExceeded) || probeCtx.Err() != nil
	if !shed {
		sp.setShed(false)
		return err
	}
	since := sp.setShed(true)
	if sp.now().Sub(since) > loadSensitiveGrace {
		return errors.Join(errors.New("shed by load for longer than the readiness grace window"), err)
	}
	return observ.Degraded(sp.name + " probe shed by load (datastore busy or probe budget exhausted); retrying each readiness call")
}

// setShed records the shedding state and returns when the current run of
// shedding began (the zero time when not shedding).
func (sp *shedProbe) setShed(shed bool) time.Time {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if !shed {
		sp.shedSince = time.Time{}
		if sp.gauge != nil {
			sp.gauge.Set(0)
		}
		return sp.shedSince
	}
	if sp.shedSince.IsZero() {
		sp.shedSince = sp.now()
	}
	if sp.gauge != nil {
		sp.gauge.Set(1)
	}
	return sp.shedSince
}
