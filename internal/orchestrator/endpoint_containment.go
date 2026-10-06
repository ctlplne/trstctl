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
	"trstctl.com/trstctl/internal/store"
)

const (
	DestinationEndpointContainment          = "endpoint.contain"
	EventEndpointContainmentRequested       = "endpoint.containment.requested"
	endpointContainmentRequestSchemaVersion = 2
)

// This event carries every byte needed to restore the exact tenant/host job
// after an event append wins but its PostgreSQL transaction rolls back. The
// database-generated outbox ID is retained so a queued receipt never points
// at an unrelated retry job.
type endpointContainmentRequestedV2 struct {
	TargetID            string `json:"target_id"`
	TargetRevision      string `json:"target_revision"`
	IdentityID          string `json:"identity_id"`
	ExpectedFingerprint string `json:"expected_fingerprint"`
	RequiredAgentID     string `json:"required_agent_id"`
	Connector           string `json:"connector"`
	Target              string `json:"target"`
	Reason              string `json:"reason"`
	RequestedBy         string `json:"requested_by"`
	IdempotencyKey      string `json:"idempotency_key"`
	OutboxID            int64  `json:"outbox_id"`
	ReceiptID           string `json:"receipt_id"`
}

func newEndpointContainmentRequestedV2(req EndpointContainmentRequest,
	outboxID int64, receiptID string) endpointContainmentRequestedV2 {
	return endpointContainmentRequestedV2{
		TargetID: req.TargetID, TargetRevision: req.TargetRevision,
		IdentityID: req.IdentityID, ExpectedFingerprint: req.ExpectedFingerprint,
		RequiredAgentID: req.RequiredAgentID, Connector: req.Connector, Target: req.Target,
		Reason: req.Reason, RequestedBy: req.RequestedBy, IdempotencyKey: req.IdempotencyKey,
		OutboxID: outboxID, ReceiptID: receiptID,
	}
}

func (v endpointContainmentRequestedV2) request() EndpointContainmentRequest {
	return EndpointContainmentRequest{
		TargetID: v.TargetID, TargetRevision: v.TargetRevision,
		IdentityID: v.IdentityID, ExpectedFingerprint: v.ExpectedFingerprint,
		RequiredAgentID: v.RequiredAgentID, Connector: v.Connector, Target: v.Target,
		Reason: v.Reason, RequestedBy: v.RequestedBy, IdempotencyKey: v.IdempotencyKey,
	}
}

func endpointContainmentEventID(tenantID, targetID, key string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID,
		[]byte("endpoint-containment-request\x00"+tenantID+"\x00"+targetID+"\x00"+key)).String()
}

func endpointContainmentReceiptID(tenantID, targetID, key string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID,
		[]byte("endpoint-containment-receipt\x00"+tenantID+"\x00"+targetID+"\x00"+key)).String()
}

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
		// Serialize the event lookup with the SQL idempotency key. A retained
		// event may outlive a rolled-back transaction, so an outbox-only lock
		// acquired after lookup would leave a duplicate-event race.
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
		if currentRevision != req.TargetRevision || currentConnector != req.Connector || currentName != req.Target {
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
		requestID := endpointContainmentEventID(tenantID, req.TargetID, req.IdempotencyKey)
		receiptID := endpointContainmentReceiptID(tenantID, req.TargetID, req.IdempotencyKey)
		retained, found, err := o.log.EventByID(ctx, requestID)
		if err != nil {
			return err
		}
		var reservedID int64
		if found {
			if retained.TenantID != tenantID || retained.Type != EventEndpointContainmentRequested ||
				retained.SchemaVersion != endpointContainmentRequestSchemaVersion {
				return fmt.Errorf("%w: containment request event identity differs", store.ErrIdempotencyConflict)
			}
			var prior endpointContainmentRequestedV2
			if err := json.Unmarshal(retained.Data, &prior); err != nil {
				return err
			}
			candidate := newEndpointContainmentRequestedV2(req, prior.OutboxID, receiptID)
			candidateBody, err := json.Marshal(candidate)
			if err != nil {
				return err
			}
			if prior.OutboxID <= 0 || !bytes.Equal(candidateBody, retained.Data) {
				return fmt.Errorf("%w: containment request differs from retained event", store.ErrIdempotencyConflict)
			}
			reservedID = prior.OutboxID
		}
		inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			ReservedID: reservedID,
			TenantID:   tenantID, Destination: DestinationEndpointContainment,
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
		if !inserted && !found {
			receipt, err = o.store.GetConnectorDeliveryReceiptForOutboxTx(ctx, tx, tenantID, outboxID)
			return err
		}
		if reservedID != 0 && outboxID != reservedID {
			return fmt.Errorf("%w: containment outbox id differs from retained event", store.ErrIdempotencyConflict)
		}
		requested := newEndpointContainmentRequestedV2(req, outboxID, receiptID)
		requestBody, err := json.Marshal(requested)
		if err != nil {
			return err
		}
		if !found {
			retained, err = o.log.Append(ctx, events.Event{
				ID: requestID, Type: EventEndpointContainmentRequested,
				SchemaVersion: endpointContainmentRequestSchemaVersion,
				TenantID:      tenantID, Data: requestBody,
			})
			if err != nil {
				return err
			}
			if retained.ID != requestID || retained.TenantID != tenantID ||
				retained.Type != EventEndpointContainmentRequested ||
				retained.SchemaVersion != endpointContainmentRequestSchemaVersion ||
				!bytes.Equal(retained.Data, requestBody) {
				return fmt.Errorf("%w: appended containment request differs", store.ErrIdempotencyConflict)
			}
		}
		receipt, err = o.recordQueuedContainmentReceiptTx(ctx, tx, tenantID, requested, found)
		return err
	})
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, fmt.Errorf("orchestrator: queue endpoint containment: %w", err)
	}
	return receipt, nil
}

func (o *Orchestrator) recordQueuedContainmentReceiptTx(ctx context.Context, tx pgx.Tx,
	tenantID string, requested endpointContainmentRequestedV2, retry bool) (store.ConnectorDeliveryReceipt, error) {
	identityID, outboxID := requested.IdentityID, requested.OutboxID
	receiptPayload, err := json.Marshal(projections.ConnectorDeliveryRecorded{
		ID: requested.ReceiptID, OutboxID: &outboxID, IdentityID: &identityID,
		Destination: DestinationEndpointContainment, Connector: requested.Connector,
		Target: requested.Target, Fingerprint: requested.ExpectedFingerprint,
		Status: "containment_queued", Attempts: 0,
		Reason: "host containment queued", Detail: "Awaiting the exact enrolled host agent; no stop or listener verification has happened.",
		IdempotencyKey: requested.IdempotencyKey,
	})
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	receiptEventID := "endpoint-containment-queued:" + requested.ReceiptID
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
		return store.ConnectorDeliveryReceipt{}, fmt.Errorf("%w: queued containment receipt differs from retained event", store.ErrIdempotencyConflict)
	}
	if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	return o.store.GetConnectorDeliveryReceiptForOutboxTx(ctx, tx, tenantID, outboxID)
}
