// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"
	"time"
)

// ReconcileStoppedIdentityWork delegates event-derived cleanup to the same
// projector used by live transitions and recovery.
func (o *Orchestrator) ReconcileStoppedIdentityWork(ctx context.Context, tenantID string, now time.Time) (int64, error) {
	return o.proj.ReconcileStoppedIdentityWork(ctx, tenantID, now)
}
