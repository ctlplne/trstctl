// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"errors"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// readyDespiteBackpressure wraps a readiness probe that reads through the shared
// request pool so a pool-acquire or statement timeout (store.IsBusy) reads as
// ready rather than not-ready. Under AN-7 the main pool sheds load with a 503
// while it is saturated; that is correct serving behaviour, not a reason to take
// the replica out of rotation. PostgreSQL reachability is proven separately by
// the db check on the dedicated probe pool (DP2-054). A genuine probe failure
// (a real projection stall, a missing recovery authority) still fails.
func readyDespiteBackpressure(probe func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		// A saturated pool makes the probe wait for the whole acquire window;
		// readiness must answer promptly, so the probe gets a short budget and
		// running out of it is read the same way as the store's busy signal.
		probeCtx, cancel := context.WithTimeout(ctx, loadSensitiveProbeBudget)
		defer cancel()
		err := probe(probeCtx)
		if err == nil {
			return nil
		}
		// Some probes wrap their datastore error opaquely; running out of the
		// budget is itself the busy signal, so a probe that failed only after its
		// budget elapsed reads as ready too. A probe that fails fast (a genuine
		// stall or a missing authority) still fails readiness.
		if store.IsBusy(err) || errors.Is(err, context.DeadlineExceeded) || probeCtx.Err() != nil {
			return nil
		}
		return err
	}
}

// loadSensitiveProbeBudget bounds each datastore-reading readiness probe so a
// saturated request pool cannot stretch /readyz past a probe's own timeout.
const loadSensitiveProbeBudget = time.Second
