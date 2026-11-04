// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
)

// RecordSlackEvent appends one of the Slack app's events (N8) and projects it.
func (o *Orchestrator) RecordSlackEvent(ctx context.Context, tenantID, eventType string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, eventType, tenantID, data)
	return err
}
