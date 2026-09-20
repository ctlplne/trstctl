// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"time"

	"trstctl.com/trstctl/internal/projections"
)

// Share ownership authority between startup catch-up and one-shot recovery.
// An event accepted by the command path must be checked with the same configured
// cadence when rebuilding its read model; the projector's validation is intact.
func ownershipProjectionOptions(cadence time.Duration) []projections.Option {
	if cadence <= 0 {
		return nil
	}
	return []projections.Option{projections.WithOwnershipAttestationCadence(cadence)}
}
