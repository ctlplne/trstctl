// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// RecordTokenExchange records one OAuth token exchange (M4) as audit evidence.
func (o *Orchestrator) RecordTokenExchange(ctx context.Context, tenantID string, exchanged projections.TokenExchanged) error {
	payload, err := json.Marshal(exchanged)
	if err != nil {
		return err
	}
	_, err = o.emit(events.ContextWithoutActor(ctx), projections.EventTokenExchanged, tenantID, payload)
	return err
}
