// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// N1-L1: an external CA issuance the CA holds for a manager's approval is
// recorded once, by the CA's own request id, and resolved once.

// RecordExternalCAIssueHeld records that an authority holds an issuance's
// request for approval. Recording it twice records it once.
func (o *Orchestrator) RecordExternalCAIssueHeld(ctx context.Context, tenantID string, held projections.ExternalCAIssueHeld) error {
	if err := projections.ValidateExternalCAIssueHeld(held); err != nil {
		return err
	}
	data, err := json.Marshal(held)
	if err != nil {
		return err
	}
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte("external-ca-held\x00"+tenantID+"\x00"+held.AuthorityID+"\x00"+held.IssueKey)).String()
	ev, err := o.emitPrepared(ctx, events.Event{ID: id, Type: projections.EventExternalCAIssueHeld, TenantID: tenantID, Data: data})
	if err != nil {
		return err
	}
	if ev.ID != id || ev.Type != projections.EventExternalCAIssueHeld {
		return fmt.Errorf("%w: held external CA issuance changed", store.ErrIdempotencyConflict)
	}
	return nil
}

// RecordExternalCAIssueResumed records how a held issuance was resolved once
// the CA's answer was read back. Recording it twice records it once.
func (o *Orchestrator) RecordExternalCAIssueResumed(ctx context.Context, tenantID string, resumed projections.ExternalCAIssueResumed) error {
	if err := projections.ValidateExternalCAIssueResumed(resumed); err != nil {
		return err
	}
	data, err := json.Marshal(resumed)
	if err != nil {
		return err
	}
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte("external-ca-resumed\x00"+tenantID+"\x00"+resumed.AuthorityID+"\x00"+strconv.Itoa(resumed.CARequestID))).String()
	ev, err := o.emitPrepared(ctx, events.Event{ID: id, Type: projections.EventExternalCAIssueResumed, TenantID: tenantID, Data: data})
	if err != nil {
		return err
	}
	if ev.ID != id || ev.Type != projections.EventExternalCAIssueResumed {
		return fmt.Errorf("%w: resumed external CA issuance changed", store.ErrIdempotencyConflict)
	}
	return nil
}
