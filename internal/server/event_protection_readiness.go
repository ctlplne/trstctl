// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"

	"trstctl.com/trstctl/internal/observ"
)

// One in-flight check, no waiting queue. Contention is temporary load shedding;
// a completed custody check still fails readiness when current custody is lost.
// Public errors contain no path, tenant, key reference or private diagnostics.
func (r *eventProtectionRuntime) probeCurrentCustody(ctx context.Context) error {
	const unavailable = "event-key custody cannot be verified yet"
	if r == nil || r.reader == nil {
		return errors.New(unavailable)
	}
	select {
	case r.probeSlots <- struct{}{}:
		defer func() { <-r.probeSlots }()
	default:
		return observ.Degraded("event-key custody check is already running")
	}
	probe, cancel := context.WithTimeout(ctx, loadSensitiveProbeBudget)
	defer cancel()
	if err := r.reader.VerifyCurrentCustody(probe); err != nil {
		return errors.New(unavailable)
	}
	return nil
}
