// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/events"
)

// Queueing a rollback that actually executes (epic D4 + AUD32/G1).
//
// The route used to record the operator's intent and stop. That was honest
// about what it did and useless in the moment it was needed: an operator
// staring at a listener serving a wrong certificate does not want a receipt,
// they want the previous certificate serving again.
//
// Appliances execute a re-bind. Host targets restore the bounded predecessor
// held only by the exact enrolled host agent. Both travel through the outbox,
// share the deploy's target lane, and return a signed receipt.

// DestinationConnectorRollback is the outbox destination an enrolled agent claims.
const DestinationConnectorRollback = "connector.rollback"

// EventConnectorRollbackRequested records that an operator asked for a
// rollback, before anything is attempted.
const EventConnectorRollbackRequested = "connector.rollback.requested"

// ConnectorRollbackRequest is one queued appliance re-bind or host restore.
//
// It carries no certificate and no key. The predecessor is identified by
// fingerprint alone. An appliance relay selects an installed object; a host
// agent selects its encrypted local predecessor. The control plane holds no
// subject key after CSR-first issuance.
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
	// SuccessorFingerprint identifies the bundle being undone. Together with
	// the predecessor it makes the signed execution event a complete G1
	// before/after transcript rather than only a destination.
	SuccessorFingerprint string `json:"successor_fingerprint,omitempty"`
	Reason               string `json:"reason,omitempty"`
	RequestedBy          string `json:"requested_by,omitempty"`
	// RequiredAgentID binds a host restore to the exact enrolled agent whose
	// successful deploy retained the predecessor. Empty for appliance re-bind.
	RequiredAgentID string `json:"required_agent_id,omitempty"`
	// RequiredAgentRole is derived here and recorded in the request transcript;
	// callers cannot relocate the operation by choosing it.
	RequiredAgentRole string `json:"required_agent_role,omitempty"`
}

// ConnectorRollbackQueued describes the queued job.
type ConnectorRollbackQueued struct {
	OutboxID       int64
	IdempotencyKey string
	Destination    string
	// Queued reports whether the required agent can actually pick this up. It exists so a
	// caller cannot serve "queued" over a row that is not claimable — the
	// failure that turns an incident-time rollback into a lie the operator acts
	// on.
	Queued bool
}

// RequestConnectorRollback queues the appropriate executable inverse. Appliance
// rows demand network role; host rows demand host role plus the exact agent ID
// that retained the predecessor.
func (o *Orchestrator) RequestConnectorRollback(ctx context.Context, tenantID string, in ConnectorRollbackRequest) (ConnectorRollbackQueued, error) {
	req := ConnectorRollbackRequest{
		Connector:              strings.TrimSpace(in.Connector),
		Target:                 strings.TrimSpace(in.Target),
		TargetID:               strings.TrimSpace(in.TargetID),
		IdentityID:             strings.TrimSpace(in.IdentityID),
		TargetConfig:           in.TargetConfig,
		PredecessorFingerprint: strings.TrimSpace(in.PredecessorFingerprint),
		PredecessorSerial:      strings.TrimSpace(in.PredecessorSerial),
		SuccessorFingerprint:   strings.TrimSpace(in.SuccessorFingerprint),
		Reason:                 strings.TrimSpace(in.Reason),
		RequestedBy:            strings.TrimSpace(in.RequestedBy),
		RequiredAgentID:        strings.TrimSpace(in.RequiredAgentID),
	}
	if normalized, err := normalizeRollbackTargetConfig(req.TargetConfig); err != nil {
		return ConnectorRollbackQueued{}, fmt.Errorf("orchestrator: normalize connector rollback target config: %w", err)
	} else {
		req.TargetConfig = normalized
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
	switch {
	case connector.CanRollbackOnHost(req.Connector):
		req.RequiredAgentRole = "host"
		if req.TargetID == "" {
			return ConnectorRollbackQueued{}, errors.New("orchestrator: a host rollback needs a stable target id")
		}
		if _, err := uuid.Parse(req.RequiredAgentID); err != nil {
			return ConnectorRollbackQueued{}, errors.New("orchestrator: a host rollback needs the exact enrolled agent id that retained the predecessor")
		}
	case connector.CanRollback(req.Connector):
		req.RequiredAgentRole = "network"
		if req.RequiredAgentID != "" {
			return ConnectorRollbackQueued{}, errors.New("orchestrator: an appliance re-bind cannot be pinned to a host agent")
		}
	default:
		return ConnectorRollbackQueued{}, connector.ErrRollbackUnsupported
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
	// restore repeatedly against a target already in the desired state.
	idemKey := "connector-rollback:" + req.TargetID + ":" + req.Target + ":" + req.PredecessorFingerprint

	var outboxID int64
	var queuedNow bool
	if err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// The request is recorded before it is queued, so the audit trail shows
		// who asked even when the required agent never gets to it.
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
			// ClaimAgentJobs enforces one live holder and one batch row per
			// effective lane, so deploy and rollback cannot race this target.
			EffectLane: ConnectorTargetEffectLane(req.TargetID),
			// Role and exact-agent demand were derived above from the connector's
			// execution model, not chosen by the API caller.
			RequiredAgentRole: req.RequiredAgentRole,
			RequiredAgentID:   req.RequiredAgentID,
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
			// for the required agent.
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
		// the receipt chain both key on. claim_attempts is deliberately NOT
		// reset: the signed receipt includes that generation, so reuse would let
		// a recent receipt from the earlier execution close the re-armed job.
		tag, err := tx.Exec(ctx,
			`UPDATE outbox
			    SET status = 'pending', attempts = 0,
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

// normalizeRollbackTargetConfig removes control-plane policy that does not
// change the restore command. Toggling automatic rollback off before a manual
// retry must not turn the same (target, predecessor) idempotency key into a
// payload conflict; the agent neither reads nor needs this flag.
func normalizeRollbackTargetConfig(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	delete(fields, "auto_rollback_on_verify_failure")
	return json.Marshal(fields)
}
