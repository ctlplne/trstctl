// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"
	"encoding/json"

	"trstctl.com/trstctl/internal/projections"
)

// RecordEndpointVerification shares certificate metadata admission with issuance
// and revocation. The observation can supersede discovered certificates, so its
// append and projection must finish before a later certificate writer proceeds.
func (o *Orchestrator) RecordEndpointVerification(ctx context.Context, tenantID string, observation projections.EndpointVerificationObserved) error {
	payload, err := json.Marshal(observation)
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventEndpointVerified, tenantID, payload)
	return err
}
