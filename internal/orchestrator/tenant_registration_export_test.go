// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"

	"trstctl.com/trstctl/internal/events"
)

// EmitTenantOffboardForTest exposes the private durable producer to the external
// integration-test package without widening the production API.
func EmitTenantOffboardForTest(
	ctx context.Context,
	orchestrator *Orchestrator,
	next events.Event,
) (events.Event, error) {
	return orchestrator.emitPrepared(ctx, next)
}
