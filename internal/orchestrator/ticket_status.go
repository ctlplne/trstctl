// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/issuancerequest"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TicketDecisionEventID is the one decision event a ticket's approval records
// for the request intake opened from it.
func TicketDecisionEventID(tenantID, requestID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("issuance-request-ticket-decision\x00"+tenantID+"\x00"+requestID)).String()
}

// DecideIssuanceRequestFromTicket records the decision a ServiceNow change
// request's approval made for the request intake opened from it (P13): the
// same lifecycle and separation of duties as a reviewer's decision, under an
// event id derived from the request, so reading the same approval again — or
// a second relay racing the first — records it once. It reports whether this
// call recorded the decision.
func (o *Orchestrator) DecideIssuanceRequestFromTicket(ctx context.Context, tenantID, requestID, to, decidedBy, reason string) (bool, error) {
	if to != issuancerequest.StateApproved && to != issuancerequest.StateDenied {
		return false, fmt.Errorf("orchestrator: a ticket approval approves or denies, not %q", to)
	}
	current, err := o.store.GetIssuanceRequest(ctx, tenantID, requestID)
	if err != nil {
		return false, err
	}
	if current.Status != issuancerequest.StateRequested {
		return false, nil
	}
	if _, err := issuancerequest.Transition(current.Status, to); err != nil {
		return false, err
	}
	if err := issuancerequest.CanDecide(current.Requester, decidedBy); err != nil {
		return false, err
	}
	payload, err := json.Marshal(projections.IssuanceRequestDecided{ID: requestID, Status: to, DecidedBy: decidedBy,
		Reason: reason, DecidedAt: time.Now().UTC()})
	if err != nil {
		return false, err
	}
	id := TicketDecisionEventID(tenantID, requestID)
	ev, err := o.emitPrepared(ctx, events.Event{ID: id, Type: projections.EventIssuanceRequestDecided, TenantID: tenantID, Data: payload})
	if err != nil {
		return false, err
	}
	if ev.ID != id || ev.Type != projections.EventIssuanceRequestDecided {
		return false, fmt.Errorf("%w: ticket decision changed", store.ErrIdempotencyConflict)
	}
	return true, nil
}
