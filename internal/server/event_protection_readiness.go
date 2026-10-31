// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
)

// One in-flight check, no waiting queue. Current custody errors and an exhausted
// probe budget do not inherit the datastore's ready-while-shed grace policy.
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
		return errors.New(unavailable)
	}
	probe, cancel := context.WithTimeout(ctx, loadSensitiveProbeBudget)
	defer cancel()
	if err := r.reader.VerifyCurrentCustody(probe); err != nil {
		return errors.New(unavailable)
	}
	return nil
}
