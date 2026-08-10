// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/issuancerequest"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// defaultIssuanceRequestTTL is how long an unattended request waits.
//
// A request that never expires is a queue entry nobody is ever forced to look
// at, and a queue whose size only grows stops being read at all. Seven days is
// long enough to survive a holiday and short enough that the queue means
// something.
const defaultIssuanceRequestTTL = 7 * 24 * time.Hour

// OpenIssuanceRequest records a new request (I3).
func (o *Orchestrator) OpenIssuanceRequest(ctx context.Context, tenantID string, in projections.IssuanceRequestOpened) (store.IssuanceRequest, error) {
	return o.openIssuanceRequest(ctx, tenantID, in, "")
}

// OpenIssuanceRequestFromRelay is the durable ticket-result receiver. Both the
// request and event identities derive from the outbox idempotency key and exact
// ticket reference, so a crash after append but before job completion replays
// the same fact instead of opening a second request.
func (o *Orchestrator) OpenIssuanceRequestFromRelay(ctx context.Context, tenantID, resultKey string, in projections.IssuanceRequestOpened) (store.IssuanceRequest, error) {
	binding := tenantID + "\x00" + resultKey + "\x00" + in.TicketRef
	in.ID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("ticket-intake-request\x00"+binding)).String()
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("ticket-intake-event\x00"+binding)).String()
	return o.openIssuanceRequest(ctx, tenantID, in, eventID)
}

func (o *Orchestrator) openIssuanceRequest(ctx context.Context, tenantID string, in projections.IssuanceRequestOpened, eventID string) (store.IssuanceRequest, error) {
	if strings.TrimSpace(in.Subject) == "" {
		return store.IssuanceRequest{}, fmt.Errorf("orchestrator: issuance request needs a subject")
	}
	if strings.TrimSpace(in.Requester) == "" {
		// Fail closed. A request with no requester cannot be separated from its
		// approver, so the separation-of-duties check would silently pass.
		return store.IssuanceRequest{}, fmt.Errorf(
			"orchestrator: issuance request needs a requester; without one the self-approval check " +
				"has nothing to compare and would pass by accident")
	}
	if in.ID == "" {
		in.ID = uuid.NewString()
	}
	if in.ExpiresAt.IsZero() {
		in.ExpiresAt = time.Now().UTC().Add(defaultIssuanceRequestTTL)
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return store.IssuanceRequest{}, err
	}
	var ev events.Event
	if eventID == "" {
		ev, err = o.emit(ctx, projections.EventIssuanceRequestOpened, tenantID, payload)
	} else {
		ev, err = o.emitPrepared(ctx, events.Event{
			ID: eventID, Type: projections.EventIssuanceRequestOpened, TenantID: tenantID, Data: payload,
		})
	}
	if err != nil {
		return store.IssuanceRequest{}, err
	}
	return store.IssuanceRequest{
		ID: in.ID, TenantID: tenantID, Subject: in.Subject, Profile: in.Profile,
		CSRPEM: in.CSRPEM, Requester: in.Requester, Justification: in.Justification,
		Origin: in.Origin, TicketRef: in.TicketRef, Status: issuancerequest.StateRequested,
		ExpiresAt: in.ExpiresAt, CreatedAt: ev.Time,
	}, nil
}

// DecideIssuanceRequest moves a request to a new state.
//
// The transition legality and the separation-of-duties rule are checked HERE,
// against the request's current stored state, rather than in the handler: a
// rule enforced by whichever handler happens to run is a rule that holds until
// somebody adds a second caller.
func (o *Orchestrator) DecideIssuanceRequest(ctx context.Context, tenantID, id, to, decidedBy, reason, identityID string) (store.IssuanceRequest, error) {
	current, err := o.store.GetIssuanceRequest(ctx, tenantID, id)
	if err != nil {
		return store.IssuanceRequest{}, err
	}
	if _, err := issuancerequest.Transition(current.Status, to); err != nil {
		return store.IssuanceRequest{}, err
	}
	// Expiry is the one transition with no decider: nobody chose it, time ran
	// out. Every other decision needs a principal who is not the requester.
	if to != issuancerequest.StateExpired && to != issuancerequest.StateIssued {
		if to == issuancerequest.StateApproved || to == issuancerequest.StateDenied {
			if err := issuancerequest.CanDecide(current.Requester, decidedBy); err != nil {
				return store.IssuanceRequest{}, err
			}
		}
	}
	// Cancelling is the requester's own right, and only theirs.
	if to == issuancerequest.StateCancelled && decidedBy != current.Requester {
		return store.IssuanceRequest{}, fmt.Errorf(
			"orchestrator: only %s can withdraw their own request; someone else closing it is a "+
				"denial and must be recorded as one", current.Requester)
	}
	at := time.Now().UTC()
	payload, err := json.Marshal(projections.IssuanceRequestDecided{
		ID: id, Status: to, DecidedBy: decidedBy, Reason: reason,
		IdentityID: identityID, DecidedAt: at,
	})
	if err != nil {
		return store.IssuanceRequest{}, err
	}
	if _, err := o.emit(ctx, projections.EventIssuanceRequestDecided, tenantID, payload); err != nil {
		return store.IssuanceRequest{}, err
	}
	current.Status = to
	current.DecidedBy = decidedBy
	current.DecisionReason = reason
	current.DecidedAt = &at
	if identityID != "" {
		current.IdentityID = identityID
	}
	return current, nil
}

// ConfigureTicketIntake records the standing instruction to read the ITSM for
// certificate-request tickets (I3). TokenRef is a reference, never a value.
func (o *Orchestrator) ConfigureTicketIntake(ctx context.Context, tenantID string, in projections.TicketIntakeConfigured) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventTicketIntakeConfigured, tenantID, payload)
	return err
}
