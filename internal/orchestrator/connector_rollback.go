// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
)

// Queueing a rollback that actually executes (epic D4).
//
// The route used to record the operator's intent and stop. That was honest
// about what it did and useless in the moment it was needed: an operator
// staring at a listener serving a wrong certificate does not want a receipt,
// they want the previous certificate serving again.
//
// It executes as a re-BIND, queued like every other estate-touching effect —
// through the outbox, claimed by a relay over its own connection, reported back
// with a signed receipt. Nothing about the mechanism is special because nothing
// about it should be: a rollback is a deploy's inverse and belongs on the same
// rails.

// DestinationConnectorRollback is the outbox destination a relay claims.
const DestinationConnectorRollback = "connector.rollback"

// EventConnectorRollbackRequested records that an operator asked for a
// rollback, before anything is attempted.
const EventConnectorRollbackRequested = "connector.rollback.requested"

// ConnectorRollbackRequest is one queued re-bind.
//
// It carries no certificate and no key. The predecessor is identified by
// fingerprint alone, which is enough because the object is already on the
// appliance — and it is all we could carry anyway, since the control plane
// holds no subject key after CSR-first issuance.
type ConnectorRollbackRequest struct {
	Connector    string          `json:"connector"`
	Target       string          `json:"target"`
	TargetID     string          `json:"target_id,omitempty"`
	IdentityID   string          `json:"identity_id,omitempty"`
	TargetConfig json.RawMessage `json:"target_config,omitempty"`
	// PredecessorFingerprint names the installed object to bind back to.
	PredecessorFingerprint string `json:"predecessor_fingerprint"`
	// PredecessorSerial is carried for the operator-facing receipt only. The
	// relay binds by fingerprint; the serial is what a human recognizes.
	PredecessorSerial string `json:"predecessor_serial,omitempty"`
	Reason            string `json:"reason,omitempty"`
	RequestedBy       string `json:"requested_by,omitempty"`
}

// ConnectorRollbackQueued describes the queued job.
type ConnectorRollbackQueued struct {
	OutboxID       int64
	IdempotencyKey string
	Destination    string
	// Queued reports whether a relay can actually pick this up. It exists so a
	// caller cannot serve "queued" over a row that is not claimable — the
	// failure that turns an incident-time rollback into a lie the operator acts
	// on.
	Queued bool
}

// RequestConnectorRollback queues a re-bind for a relay to execute.
//
// The row demands the NETWORK role. A rollback re-points an appliance listener,
// which is relay work by definition — a host agent has no route to it, and
// letting one claim the job would move the work to a machine that cannot do it
// and then wait out the lease.
func (o *Orchestrator) RequestConnectorRollback(ctx context.Context, tenantID string, in ConnectorRollbackRequest) (ConnectorRollbackQueued, error) {
	req := ConnectorRollbackRequest{
		Connector:              strings.TrimSpace(in.Connector),
		Target:                 strings.TrimSpace(in.Target),
		TargetID:               strings.TrimSpace(in.TargetID),
		IdentityID:             strings.TrimSpace(in.IdentityID),
		TargetConfig:           in.TargetConfig,
		PredecessorFingerprint: strings.TrimSpace(in.PredecessorFingerprint),
		PredecessorSerial:      strings.TrimSpace(in.PredecessorSerial),
		Reason:                 strings.TrimSpace(in.Reason),
		RequestedBy:            strings.TrimSpace(in.RequestedBy),
	}
	if req.Connector == "" || req.Target == "" {
		return ConnectorRollbackQueued{}, errors.New("orchestrator: a connector rollback needs a connector and a target")
	}
	if req.PredecessorFingerprint == "" {
		// Refused here rather than queued and failed on a host. A first
		// deployment has no predecessor, and putting that on a relay's queue
		// only moves the discovery of a fact we already have.
		return ConnectorRollbackQueued{}, errors.New("orchestrator: a connector rollback needs a predecessor fingerprint")
	}
	if req.RequestedBy == "" {
		if actor, ok := events.ActorFromContext(ctx); ok {
			req.RequestedBy = actor.Subject
		}
	}
	// TWO payloads, deliberately.
	//
	// The event and the receipt want the whole request, including who asked and
	// why. The outbox row must not: EnqueueIfAbsent compares the durable
	// command byte-for-byte on an idempotency-key hit, so folding Reason and
	// RequestedBy into it means a second operator re-requesting the same
	// rollback — or the same operator typing a different reason — gets a hard
	// idempotency conflict in the middle of an incident. The COMMAND is "re-bind
	// this target to this predecessor"; who asked is not part of it.
	payload, err := json.Marshal(req)
	if err != nil {
		return ConnectorRollbackQueued{}, err
	}
	command := req
	command.Reason = ""
	command.RequestedBy = ""
	commandPayload, err := json.Marshal(command)
	if err != nil {
		return ConnectorRollbackQueued{}, err
	}
	// Idempotent on (target, predecessor): asking twice for the same rollback is
	// one rollback. Without this an operator hammering the button during an
	// incident would queue a job per click, and a relay would execute the same
	// re-bind repeatedly against an appliance already in the desired state.
	idemKey := "connector-rollback:" + req.TargetID + ":" + req.Target + ":" + req.PredecessorFingerprint

	var outboxID int64
	var queuedNow bool
	if err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// The request is recorded before it is queued, so the audit trail shows
		// who asked even when the relay never gets to it.
		if _, appendErr := o.log.Append(ctx, events.Event{
			Type: EventConnectorRollbackRequested, TenantID: tenantID, Data: payload,
		}); appendErr != nil {
			return appendErr
		}
		inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID:       tenantID,
			Destination:    DestinationConnectorRollback,
			IdempotencyKey: idemKey,
			Payload:        commandPayload,
			// Keyed on the CONTENDED OBJECT — the target — rather than on the
			// destination, so a deploy and a rollback for the same listener
			// share a lane.
			//
			// Stated honestly: this does NOT currently serialize anything on the
			// agent path. The lane limit is enforced by the control plane's own
			// dispatch claim; ClaimAgentJobs has no lane predicate, so a deploy
			// and a rollback for one listener can be held by two relays at once
			// and the last write wins. The lane is set correctly here so that
			// adding the predicate is a change in one place, and the race is
			// recorded in docs/limitations.md rather than left for an operator
			// to discover. Setting the lane and describing it as protection it
			// does not yet provide would be the worse option.
			EffectLane: "connector.bind:target:" + req.TargetID,
			// A rollback re-points an appliance listener, so only a relay can
			// perform it. Stamped at enqueue from the same vocabulary the deploy
			// path uses (epic A2).
			RequiredAgentRole: "network",
		})
		if err != nil {
			return err
		}
		queuedNow = inserted

		var status string
		if err := tx.QueryRow(ctx,
			`SELECT id, status FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
			tenantID, idemKey).Scan(&outboxID, &status); err != nil {
			return err
		}
		if inserted || status == "pending" {
			// Either freshly queued, or an honest replay of work still waiting
			// for a relay.
			queuedNow = true
			return nil
		}
		// The row exists in a TERMINAL state — it was delivered, or it
		// dead-lettered. Without re-arming, every later rollback of the same
		// target inserts nothing, finds this dead row, and the caller reports
		// "queued" for work that will never run. During an incident that is the
		// worst possible lie: the operator is told the rollback is under way and
		// walks away.
		//
		// Re-arming in place rather than inserting a second row keeps the
		// idempotency key meaning one command, which is what the claim path and
		// the receipt chain both key on.
		tag, err := tx.Exec(ctx,
			`UPDATE outbox
			    SET status = 'pending', attempts = 0, claim_attempts = 0,
			        claimed_by_agent_id = NULL, claim_expires_at = NULL,
			        claim_completed_at = NULL, delivered_at = NULL,
			        last_error = NULL, next_attempt_at = now()
			  WHERE tenant_id = $1 AND idempotency_key = $2`,
			tenantID, idemKey)
		if err != nil {
			return err
		}
		queuedNow = tag.RowsAffected() > 0
		return nil
	}); err != nil {
		return ConnectorRollbackQueued{}, fmt.Errorf("orchestrator: queue connector rollback: %w", err)
	}
	return ConnectorRollbackQueued{
		OutboxID: outboxID, IdempotencyKey: idemKey, Destination: DestinationConnectorRollback,
		Queued: queuedNow,
	}, nil
}
