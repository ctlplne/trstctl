// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const (
	DestinationEndpointContainment    = "endpoint.contain"
	EventEndpointContainmentRequested = "endpoint.containment.requested"
)

// EndpointContainmentRequest carries only public identifiers. The host's own
// profile, not this tenant request, decides which listener and stop command it
// may run. The receiver pins the exact agent in the outbox row.
type EndpointContainmentRequest struct {
	TargetID            string `json:"target_id"`
	TargetRevision      string `json:"target_revision"`
	IdentityID          string `json:"identity_id"`
	ExpectedFingerprint string `json:"expected_fingerprint"`
	RequiredAgentID     string `json:"required_agent_id"`
	Connector           string `json:"-"`
	Target              string `json:"-"`
	Reason              string `json:"-"`
	RequestedBy         string `json:"-"`
	IdempotencyKey      string `json:"-"`
}

// RequestEndpointContainment enqueues one exact host action and its pending
// receipt in the same tenant transaction as the immutable request event.
func (o *Orchestrator) RequestEndpointContainment(ctx context.Context, tenantID string,
	in EndpointContainmentRequest) (store.ConnectorDeliveryReceipt, error) {
	req := EndpointContainmentRequest{
		TargetID: strings.TrimSpace(in.TargetID), TargetRevision: strings.TrimSpace(in.TargetRevision),
		IdentityID: strings.TrimSpace(in.IdentityID), ExpectedFingerprint: strings.ToLower(strings.TrimSpace(in.ExpectedFingerprint)),
		RequiredAgentID: strings.TrimSpace(in.RequiredAgentID), Connector: strings.TrimSpace(in.Connector),
		Target: strings.TrimSpace(in.Target), Reason: strings.TrimSpace(in.Reason),
		RequestedBy: strings.TrimSpace(in.RequestedBy), IdempotencyKey: strings.TrimSpace(in.IdempotencyKey),
	}
	if _, err := uuid.Parse(req.TargetID); err != nil {
		return store.ConnectorDeliveryReceipt{}, errors.New("orchestrator: containment needs an exact target id")
	}
	if _, err := uuid.Parse(req.IdentityID); err != nil {
		return store.ConnectorDeliveryReceipt{}, errors.New("orchestrator: containment needs an exact identity id")
	}
	if _, err := uuid.Parse(req.RequiredAgentID); err != nil {
		return store.ConnectorDeliveryReceipt{}, errors.New("orchestrator: containment needs an exact enrolled host agent id")
	}
	if req.TargetRevision == "" || req.IdempotencyKey == "" || req.Target == "" ||
		!connector.CanRollbackOnHost(req.Connector) {
		return store.ConnectorDeliveryReceipt{}, errors.New("orchestrator: containment needs a reviewed host target, revision and idempotency key")
	}
	if decoded, err := hex.DecodeString(req.ExpectedFingerprint); err != nil || len(decoded) != 32 {
		return store.ConnectorDeliveryReceipt{}, errors.New("orchestrator: containment needs the exact SHA-256 leaf fingerprint")
	}
	if req.RequestedBy == "" {
		if actor, ok := events.ActorFromContext(ctx); ok {
			req.RequestedBy = actor.Subject
		}
	}
	command, err := json.Marshal(req)
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	outboxKey := "endpoint-contain:" + req.TargetID + ":" + req.IdempotencyKey
	var receipt store.ConnectorDeliveryReceipt
	err = o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var currentRevision, currentConnector string
		var currentConfig []byte
		if err := tx.QueryRow(ctx,
			`SELECT revision_id, type, config FROM deployment_targets
			  WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, req.TargetID).
			Scan(&currentRevision, &currentConnector, &currentConfig); err != nil {
			return err
		}
		if currentRevision != req.TargetRevision || currentConnector != req.Connector {
			return errors.New("orchestrator: target changed after containment review; preview again")
		}
		assignedAgent, err := connector.TargetHostAgentID(json.RawMessage(currentConfig))
		if err != nil || assignedAgent != req.RequiredAgentID {
			return errors.New("orchestrator: target no longer names the enrolled host that holds its last deploy")
		}
		var identityStatus string
		if err := tx.QueryRow(ctx,
			`SELECT status FROM identities WHERE tenant_id=$1 AND id=$2 FOR UPDATE`,
			tenantID, req.IdentityID).Scan(&identityStatus); err != nil {
			return err
		}
		if identityStatus == "retired" {
			return errors.New("orchestrator: retired identity cannot authorize a new target action")
		}
		owned, err := o.store.IdentityOwnsCertificateFingerprintTx(ctx, tx, tenantID,
			req.IdentityID, req.ExpectedFingerprint)
		if err != nil {
			return err
		}
		if !owned {
			return errors.New("orchestrator: the exact leaf does not belong to this identity")
		}
		inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID: tenantID, Destination: DestinationEndpointContainment,
			IdempotencyKey: outboxKey, Payload: command,
			EffectLane:        ConnectorTargetEffectLane(req.TargetID),
			RequiredAgentRole: "host", RequiredAgentID: req.RequiredAgentID,
		})
		if err != nil {
			return err
		}
		var outboxID int64
		if err := tx.QueryRow(ctx,
			`SELECT id FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE`,
			tenantID, outboxKey).Scan(&outboxID); err != nil {
			return err
		}
		if !inserted {
			receipt, err = o.store.GetConnectorDeliveryReceiptForOutboxTx(ctx, tx, tenantID, outboxID)
			return err
		}
		requestBody, err := json.Marshal(struct {
			EndpointContainmentRequest
			Reason      string `json:"reason"`
			RequestedBy string `json:"requested_by"`
			OutboxID    int64  `json:"outbox_id"`
		}{req, req.Reason, req.RequestedBy, outboxID})
		if err != nil {
			return err
		}
		if _, err := o.log.Append(ctx, events.Event{
			Type: EventEndpointContainmentRequested, TenantID: tenantID, Data: requestBody,
		}); err != nil {
			return err
		}
		identityID := req.IdentityID
		receiptPayload, err := json.Marshal(projections.ConnectorDeliveryRecorded{
			ID: uuid.NewString(), OutboxID: &outboxID, IdentityID: &identityID,
			Destination: DestinationEndpointContainment, Connector: req.Connector,
			Target: req.Target, Fingerprint: req.ExpectedFingerprint,
			Status: "containment_queued", Attempts: 0,
			Reason: "host containment queued", Detail: "Awaiting the exact enrolled host agent; no stop or listener verification has happened.",
			IdempotencyKey: req.IdempotencyKey,
		})
		if err != nil {
			return err
		}
		ev, err := o.log.Append(ctx, events.Event{Type: projections.EventConnectorDeliveryRecorded,
			TenantID: tenantID, Data: receiptPayload})
		if err != nil {
			return err
		}
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		receipt, err = o.store.GetConnectorDeliveryReceiptForOutboxTx(ctx, tx, tenantID, outboxID)
		return err
	})
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, fmt.Errorf("orchestrator: queue endpoint containment: %w", err)
	}
	return receipt, nil
}
