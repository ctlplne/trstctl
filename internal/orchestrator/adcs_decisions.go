// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Decisions on pending AD CS requests (N1). A decision is queued only with the
// exact operation approval it names, which its source event consumes; the
// relay job is enqueued in the same tenant transaction, so an approval is spent
// on exactly one job and a retried command finds the same decision.

// ADCSDecisionID is the decision an approval request authorizes.
func ADCSDecisionID(tenantID, approvalRequestID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("adcs-decision\x00"+tenantID+"\x00"+approvalRequestID)).String()
}

// ADCSDecisionJobKey is the relay job a decision queues.
func ADCSDecisionJobKey(decisionID string) string { return "adcs-decide:" + decisionID }

// QueueADCSDecision consumes one exact approval beside the decision projection
// and the relay job.
func (o *Orchestrator) QueueADCSDecision(ctx context.Context, tenantID string, queued projections.ADCSDecisionQueued) error {
	if o == nil || o.log == nil || o.store == nil || o.outbox == nil {
		return errors.New("AD CS decision execution is not configured")
	}
	if err := projections.ValidateADCSDecisionQueued(queued); err != nil {
		return err
	}
	if queued.ID != ADCSDecisionID(tenantID, queued.Approval.RequestID) {
		return errors.New("AD CS decision ID differs from its approved command")
	}
	intent := relay.ADCSDecideIntent{ID: queued.ID, CAConfig: queued.CAConfig, RequestID: queued.RequestID, Decision: queued.Decision,
		RequiredAgentID: queued.RelayAgentID}
	if err := relay.ValidateADCSDecideIntent(intent); err != nil {
		return err
	}
	raw, err := json.Marshal(queued)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	return o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		canonical, found, err := o.log.EventByID(ctx, queued.ID)
		if err != nil {
			return err
		}
		if !found {
			if _, err := o.store.ValidateOperationApprovalUseTx(ctx, tx, tenantID, queued.Approval, time.Now().UTC()); err != nil {
				return err
			}
			canonical, err = o.log.Append(ctx, events.Event{ID: queued.ID, TenantID: tenantID, Type: projections.EventADCSDecisionQueued, Data: raw})
			if err != nil {
				return err
			}
		}
		if canonical.ID != queued.ID || canonical.Type != projections.EventADCSDecisionQueued || canonical.TenantID != tenantID || canonical.SchemaVersion != 1 {
			return fmt.Errorf("%w: AD CS decision source envelope changed", store.ErrIdempotencyConflict)
		}
		matches, err := operationApprovalEventDataMatches(canonical, raw, tenantID, queued.Approval.Requester)
		if err != nil {
			return err
		}
		if !matches {
			return fmt.Errorf("%w: AD CS approved decision changed", store.ErrIdempotencyConflict)
		}
		if err := validateOperationApprovalBoundActor(canonical.Actor, tenantID, queued.Approval.Requester); err != nil {
			return err
		}
		if err := o.proj.ApplyTx(ctx, tx, canonical); err != nil {
			return err
		}
		_, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{TenantID: tenantID, Destination: relay.KindADCSDecide,
			IdempotencyKey: ADCSDecisionJobKey(queued.ID), Payload: payload,
			RequiredAgentRole: mtls.AgentRoleNetwork, RequiredAgentID: queued.RelayAgentID})
		return err
	})
}

// DestinationExternalCAResumeHeld resumes an external CA issuance the CA held
// for approval, once the issuer's relay approved its request (N1-L1).
const DestinationExternalCAResumeHeld = "external-ca.resume_held"

// ExternalCAResumeHeld is the payload of external-ca.resume_held.
type ExternalCAResumeHeld struct {
	AuthorityID string `json:"authority_id"`
	CARequestID int    `json:"ca_request_id"`
}

// ExternalCAResumeHeldKey is the resume an approved decision queues.
func ExternalCAResumeHeldKey(decisionID string) string { return "external-ca-resume:" + decisionID }

// RecordADCSDecided records what the relay's checked report says the CA now
// holds. Recording it twice records it once. When the decision approved a
// request a trstctl issuance is held on, the issuance's resume is queued in
// the same tenant transaction (N1-L1), so an approval recorded is never an
// approval forgotten.
func (o *Orchestrator) RecordADCSDecided(ctx context.Context, tenantID string, decided projections.ADCSDecided) error {
	if o == nil || o.log == nil || o.store == nil || o.outbox == nil {
		return errors.New("AD CS decision recording is not configured")
	}
	data, err := json.Marshal(decided)
	if err != nil {
		return err
	}
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte("adcs-decided\x00"+tenantID+"\x00"+decided.ID)).String()
	return o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		canonical, found, err := o.log.EventByID(ctx, id)
		if err != nil {
			return err
		}
		if !found {
			canonical, err = o.log.Append(ctx, events.Event{ID: id, Type: projections.EventADCSDecided, TenantID: tenantID, Data: data})
			if err != nil {
				return err
			}
		}
		if canonical.ID != id || canonical.Type != projections.EventADCSDecided || canonical.TenantID != tenantID {
			return fmt.Errorf("%w: AD CS decision result changed", store.ErrIdempotencyConflict)
		}
		if err := o.proj.ApplyTx(ctx, tx, canonical); err != nil {
			return err
		}
		if decided.Disposition != string(relay.ADCSDecisionDisposition(relay.ADCSDecisionApprove)) {
			return nil
		}
		held, ok, err := o.store.HeldIssueForADCSDecisionTx(ctx, tx, tenantID, decided.ID)
		if err != nil || !ok {
			return err
		}
		payload, err := json.Marshal(ExternalCAResumeHeld{AuthorityID: held.AuthorityID, CARequestID: held.CARequestID})
		if err != nil {
			return err
		}
		_, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{TenantID: tenantID, Destination: DestinationExternalCAResumeHeld,
			IdempotencyKey: ExternalCAResumeHeldKey(decided.ID), Payload: payload,
			EffectLane: "external-ca.issue:authority:" + held.AuthorityID})
		return err
	})
}
