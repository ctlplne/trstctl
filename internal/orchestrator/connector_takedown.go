// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
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
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// Connector-side takedown of a rogue or compromised certificate (A43): one
// immutable request event, one outbox command for a network relay on the
// target's lane, one queued receipt, all in one tenant transaction, with the
// database-generated outbox id retained in the event so a retry after a
// rolled-back transaction restores the same job.

const (
	DestinationConnectorTakedown          = "connector.takedown"
	EventConnectorTakedownRequested       = "connector.takedown.requested"
	connectorTakedownRequestSchemaVersion = 1
)

// ConnectorTakedownRequest names the appliance object to remove. IdentityID
// may be empty: a rogue certificate found in inventory need not belong to a
// managed identity.
type ConnectorTakedownRequest struct {
	Connector      string          `json:"connector"`
	Target         string          `json:"target"`
	TargetID       string          `json:"target_id"`
	TargetRevision string          `json:"target_revision"`
	IdentityID     string          `json:"identity_id,omitempty"`
	Fingerprint    string          `json:"fingerprint"`
	TargetConfig   json.RawMessage `json:"target_config,omitempty"`
	Reason         string          `json:"-"`
	RequestedBy    string          `json:"-"`
	IdempotencyKey string          `json:"-"`
}

type connectorTakedownRequestedV1 struct {
	Connector      string          `json:"connector"`
	Target         string          `json:"target"`
	TargetID       string          `json:"target_id"`
	TargetRevision string          `json:"target_revision"`
	IdentityID     string          `json:"identity_id,omitempty"`
	Fingerprint    string          `json:"fingerprint"`
	TargetConfig   json.RawMessage `json:"target_config"`
	Reason         string          `json:"reason"`
	RequestedBy    string          `json:"requested_by"`
	IdempotencyKey string          `json:"idempotency_key"`
	OutboxID       int64           `json:"outbox_id"`
	ReceiptID      string          `json:"receipt_id"`
}

func newConnectorTakedownRequestedV1(req ConnectorTakedownRequest, outboxID int64, receiptID string) connectorTakedownRequestedV1 {
	return connectorTakedownRequestedV1{
		Connector: req.Connector, Target: req.Target, TargetID: req.TargetID, TargetRevision: req.TargetRevision,
		IdentityID: req.IdentityID, Fingerprint: req.Fingerprint, TargetConfig: req.TargetConfig,
		Reason: req.Reason, RequestedBy: req.RequestedBy, IdempotencyKey: req.IdempotencyKey,
		OutboxID: outboxID, ReceiptID: receiptID,
	}
}

func connectorTakedownEventID(tenantID, targetID, key string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID,
		[]byte("connector-takedown-request\x00"+tenantID+"\x00"+targetID+"\x00"+key)).String()
}

func connectorTakedownReceiptID(tenantID, targetID, key string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID,
		[]byte("connector-takedown-receipt\x00"+tenantID+"\x00"+targetID+"\x00"+key)).String()
}

// RequestConnectorTakedown enqueues one appliance object removal and its
// pending receipt in the same tenant transaction as the immutable request.
func (o *Orchestrator) RequestConnectorTakedown(ctx context.Context, tenantID string,
	in ConnectorTakedownRequest) (store.ConnectorDeliveryReceipt, error) {
	req := ConnectorTakedownRequest{
		Connector: strings.TrimSpace(in.Connector), Target: strings.TrimSpace(in.Target),
		TargetID: strings.TrimSpace(in.TargetID), TargetRevision: strings.TrimSpace(in.TargetRevision),
		IdentityID: strings.TrimSpace(in.IdentityID), Fingerprint: strings.ToLower(strings.TrimSpace(in.Fingerprint)),
		TargetConfig: in.TargetConfig, Reason: strings.TrimSpace(in.Reason),
		RequestedBy: strings.TrimSpace(in.RequestedBy), IdempotencyKey: strings.TrimSpace(in.IdempotencyKey),
	}
	if _, err := uuid.Parse(req.TargetID); err != nil {
		return store.ConnectorDeliveryReceipt{}, errors.New("orchestrator: takedown needs an exact target id")
	}
	if req.IdentityID != "" {
		if _, err := uuid.Parse(req.IdentityID); err != nil {
			return store.ConnectorDeliveryReceipt{}, errors.New("orchestrator: takedown needs an exact identity id when one is named")
		}
	}
	if req.TargetRevision == "" || req.IdempotencyKey == "" || req.Target == "" || len(req.TargetConfig) == 0 ||
		!connector.CanTakedown(req.Connector) {
		return store.ConnectorDeliveryReceipt{}, errors.New("orchestrator: takedown needs a reviewed appliance target of a family that can remove objects, its configuration, revision and idempotency key")
	}
	if decoded, err := hex.DecodeString(req.Fingerprint); err != nil || len(decoded) != 32 {
		return store.ConnectorDeliveryReceipt{}, errors.New("orchestrator: takedown needs the exact SHA-256 leaf fingerprint")
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
	outboxKey := "connector-takedown:" + req.TargetID + ":" + req.IdempotencyKey
	var receipt store.ConnectorDeliveryReceipt
	err = o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
			"outbox-enqueue-if-absent\x1f"+tenantID+"\x1f"+outboxKey); err != nil {
			return err
		}
		var currentRevision, currentConnector, currentName string
		var currentConfig []byte
		if err := tx.QueryRow(ctx,
			`SELECT revision_id, type, name, config FROM deployment_targets
			  WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, req.TargetID).
			Scan(&currentRevision, &currentConnector, &currentName, &currentConfig); err != nil {
			return err
		}
		// Target is the execution route (the profile, virtual service or
		// template the deploys named), which may differ from the display name.
		if currentRevision != req.TargetRevision || currentConnector != req.Connector || currentName == "" ||
			!bytes.Equal(bytes.TrimSpace(currentConfig), bytes.TrimSpace(req.TargetConfig)) {
			return errors.New("orchestrator: target changed after takedown review; review again")
		}
		requestID := connectorTakedownEventID(tenantID, req.TargetID, req.IdempotencyKey)
		receiptID := connectorTakedownReceiptID(tenantID, req.TargetID, req.IdempotencyKey)
		retained, found, err := o.log.EventByID(ctx, requestID)
		if err != nil {
			return err
		}
		var reservedID int64
		if found {
			if retained.TenantID != tenantID || retained.Type != EventConnectorTakedownRequested ||
				retained.SchemaVersion != connectorTakedownRequestSchemaVersion {
				return fmt.Errorf("%w: takedown request event identity differs", store.ErrIdempotencyConflict)
			}
			var prior connectorTakedownRequestedV1
			if err := json.Unmarshal(retained.Data, &prior); err != nil {
				return err
			}
			candidateBody, err := json.Marshal(newConnectorTakedownRequestedV1(req, prior.OutboxID, receiptID))
			if err != nil {
				return err
			}
			if prior.OutboxID <= 0 || !bytes.Equal(candidateBody, retained.Data) {
				return fmt.Errorf("%w: takedown request differs from retained event", store.ErrIdempotencyConflict)
			}
			reservedID = prior.OutboxID
		}
		inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			ReservedID: reservedID,
			TenantID:   tenantID, Destination: DestinationConnectorTakedown,
			IdempotencyKey: outboxKey, Payload: command,
			EffectLane:        ConnectorTargetEffectLane(req.TargetID),
			RequiredAgentRole: "network",
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
		if !inserted && !found {
			receipt, err = o.store.GetConnectorDeliveryReceiptForOutboxTx(ctx, tx, tenantID, outboxID)
			return err
		}
		if reservedID != 0 && outboxID != reservedID {
			return fmt.Errorf("%w: takedown outbox id differs from retained event", store.ErrIdempotencyConflict)
		}
		requested := newConnectorTakedownRequestedV1(req, outboxID, receiptID)
		requestBody, err := json.Marshal(requested)
		if err != nil {
			return err
		}
		if !found {
			retained, err = o.log.Append(ctx, events.Event{
				ID: requestID, Type: EventConnectorTakedownRequested,
				SchemaVersion: connectorTakedownRequestSchemaVersion,
				TenantID:      tenantID, Data: requestBody,
			})
			if err != nil {
				return err
			}
			if retained.ID != requestID || retained.TenantID != tenantID ||
				retained.Type != EventConnectorTakedownRequested ||
				retained.SchemaVersion != connectorTakedownRequestSchemaVersion ||
				!bytes.Equal(retained.Data, requestBody) {
				return fmt.Errorf("%w: appended takedown request differs", store.ErrIdempotencyConflict)
			}
		}
		receipt, err = o.recordQueuedTakedownReceiptTx(ctx, tx, tenantID, requested, found)
		return err
	})
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, fmt.Errorf("orchestrator: queue connector takedown: %w", err)
	}
	return receipt, nil
}

func (o *Orchestrator) recordQueuedTakedownReceiptTx(ctx context.Context, tx pgx.Tx,
	tenantID string, requested connectorTakedownRequestedV1, retry bool) (store.ConnectorDeliveryReceipt, error) {
	outboxID := requested.OutboxID
	pl := projections.ConnectorDeliveryRecorded{
		ID: requested.ReceiptID, OutboxID: &outboxID,
		Destination: DestinationConnectorTakedown, Connector: requested.Connector,
		Target: requested.Target, Fingerprint: requested.Fingerprint,
		Status: servedstatus.ConnectorTakedownQueued, Attempts: 0,
		Reason:         "appliance object removal queued",
		Detail:         "Awaiting an enrolled network relay; no object has been removed.",
		IdempotencyKey: requested.IdempotencyKey,
	}
	if requested.IdentityID != "" {
		identityID := requested.IdentityID
		pl.IdentityID = &identityID
	}
	receiptPayload, err := json.Marshal(pl)
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	receiptEventID := "connector-takedown-queued:" + requested.ReceiptID
	var ev events.Event
	if retry {
		var found bool
		ev, found, err = o.log.EventByID(ctx, receiptEventID)
		if err != nil {
			return store.ConnectorDeliveryReceipt{}, err
		}
		if !found {
			retry = false
		}
	}
	if !retry {
		ev, err = o.log.Append(ctx, events.Event{ID: receiptEventID,
			Type: projections.EventConnectorDeliveryRecorded, TenantID: tenantID, Data: receiptPayload})
		if err != nil {
			return store.ConnectorDeliveryReceipt{}, err
		}
	}
	if ev.ID != receiptEventID || ev.TenantID != tenantID || ev.SchemaVersion != events.DefaultSchemaVersion ||
		ev.Type != projections.EventConnectorDeliveryRecorded || !bytes.Equal(ev.Data, receiptPayload) {
		return store.ConnectorDeliveryReceipt{}, fmt.Errorf("%w: queued takedown receipt differs from retained event", store.ErrIdempotencyConflict)
	}
	if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	return o.store.GetConnectorDeliveryReceiptForOutboxTx(ctx, tx, tenantID, outboxID)
}
