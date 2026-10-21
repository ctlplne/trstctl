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

// Removing compromised material from a host (A49) follows containment's
// shape exactly: one immutable request event, one outbox command pinned to the
// enrolled host agent, one queued receipt, all in the same tenant transaction,
// with the database-generated outbox id retained in the event so a retry after
// a rolled-back transaction restores the same job rather than a second one.

const (
	DestinationEndpointPurge          = "endpoint.purge"
	EventEndpointPurgeRequested       = "endpoint.purge.requested"
	endpointPurgeRequestSchemaVersion = 1
)

// EndpointPurgeRequest carries public identifiers plus the target's own
// configuration, from which the host derives the exact files to remove. The
// host profile's allowed roots, not this request, bound what may be touched.
type EndpointPurgeRequest struct {
	TargetID            string          `json:"target_id"`
	TargetRevision      string          `json:"target_revision"`
	IdentityID          string          `json:"identity_id"`
	ExpectedFingerprint string          `json:"expected_fingerprint"`
	RequiredAgentID     string          `json:"required_agent_id"`
	Connector           string          `json:"connector"`
	TargetConfig        json.RawMessage `json:"target_config,omitempty"`
	Target              string          `json:"-"`
	Reason              string          `json:"-"`
	RequestedBy         string          `json:"-"`
	IdempotencyKey      string          `json:"-"`
}

type endpointPurgeRequestedV1 struct {
	TargetID            string          `json:"target_id"`
	TargetRevision      string          `json:"target_revision"`
	IdentityID          string          `json:"identity_id"`
	ExpectedFingerprint string          `json:"expected_fingerprint"`
	RequiredAgentID     string          `json:"required_agent_id"`
	Connector           string          `json:"connector"`
	Target              string          `json:"target"`
	TargetConfig        json.RawMessage `json:"target_config"`
	Reason              string          `json:"reason"`
	RequestedBy         string          `json:"requested_by"`
	IdempotencyKey      string          `json:"idempotency_key"`
	OutboxID            int64           `json:"outbox_id"`
	ReceiptID           string          `json:"receipt_id"`
}

func newEndpointPurgeRequestedV1(req EndpointPurgeRequest, outboxID int64, receiptID string) endpointPurgeRequestedV1 {
	return endpointPurgeRequestedV1{
		TargetID: req.TargetID, TargetRevision: req.TargetRevision, IdentityID: req.IdentityID,
		ExpectedFingerprint: req.ExpectedFingerprint, RequiredAgentID: req.RequiredAgentID,
		Connector: req.Connector, Target: req.Target, TargetConfig: req.TargetConfig,
		Reason: req.Reason, RequestedBy: req.RequestedBy, IdempotencyKey: req.IdempotencyKey,
		OutboxID: outboxID, ReceiptID: receiptID,
	}
}

func endpointPurgeEventID(tenantID, targetID, key string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID,
		[]byte("endpoint-purge-request\x00"+tenantID+"\x00"+targetID+"\x00"+key)).String()
}

func endpointPurgeReceiptID(tenantID, targetID, key string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID,
		[]byte("endpoint-purge-receipt\x00"+tenantID+"\x00"+targetID+"\x00"+key)).String()
}

// RequestEndpointPurge enqueues one exact host material removal and its
// pending receipt in the same tenant transaction as the immutable request.
func (o *Orchestrator) RequestEndpointPurge(ctx context.Context, tenantID string,
	in EndpointPurgeRequest) (store.ConnectorDeliveryReceipt, error) {
	req := EndpointPurgeRequest{
		TargetID: strings.TrimSpace(in.TargetID), TargetRevision: strings.TrimSpace(in.TargetRevision),
		IdentityID: strings.TrimSpace(in.IdentityID), ExpectedFingerprint: strings.ToLower(strings.TrimSpace(in.ExpectedFingerprint)),
		RequiredAgentID: strings.TrimSpace(in.RequiredAgentID), Connector: strings.TrimSpace(in.Connector),
		TargetConfig: in.TargetConfig, Target: strings.TrimSpace(in.Target), Reason: strings.TrimSpace(in.Reason),
		RequestedBy: strings.TrimSpace(in.RequestedBy), IdempotencyKey: strings.TrimSpace(in.IdempotencyKey),
	}
	if _, err := uuid.Parse(req.TargetID); err != nil {
		return store.ConnectorDeliveryReceipt{}, errors.New("orchestrator: purge needs an exact target id")
	}
	if _, err := uuid.Parse(req.IdentityID); err != nil {
		return store.ConnectorDeliveryReceipt{}, errors.New("orchestrator: purge needs an exact identity id")
	}
	if _, err := uuid.Parse(req.RequiredAgentID); err != nil {
		return store.ConnectorDeliveryReceipt{}, errors.New("orchestrator: purge needs an exact enrolled host agent id")
	}
	if req.TargetRevision == "" || req.IdempotencyKey == "" || req.Target == "" || len(req.TargetConfig) == 0 ||
		!connector.CanRollbackOnHost(req.Connector) {
		return store.ConnectorDeliveryReceipt{}, errors.New("orchestrator: purge needs a reviewed host target, its configuration, revision and idempotency key")
	}
	if decoded, err := hex.DecodeString(req.ExpectedFingerprint); err != nil || len(decoded) != 32 {
		return store.ConnectorDeliveryReceipt{}, errors.New("orchestrator: purge needs the exact SHA-256 leaf fingerprint")
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
	outboxKey := "endpoint-purge:" + req.TargetID + ":" + req.IdempotencyKey
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
		if currentRevision != req.TargetRevision || currentConnector != req.Connector || currentName != req.Target {
			return errors.New("orchestrator: target changed after purge review; preview again")
		}
		if !bytes.Equal(bytes.TrimSpace(currentConfig), bytes.TrimSpace(req.TargetConfig)) {
			return errors.New("orchestrator: target configuration changed after purge review; preview again")
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
		owned, err := o.store.IdentityOwnsCertificateFingerprintTx(ctx, tx, tenantID,
			req.IdentityID, req.ExpectedFingerprint)
		if err != nil {
			return err
		}
		if !owned {
			return errors.New("orchestrator: the exact leaf does not belong to this identity")
		}
		requestID := endpointPurgeEventID(tenantID, req.TargetID, req.IdempotencyKey)
		receiptID := endpointPurgeReceiptID(tenantID, req.TargetID, req.IdempotencyKey)
		retained, found, err := o.log.EventByID(ctx, requestID)
		if err != nil {
			return err
		}
		var reservedID int64
		if found {
			if retained.TenantID != tenantID || retained.Type != EventEndpointPurgeRequested ||
				retained.SchemaVersion != endpointPurgeRequestSchemaVersion {
				return fmt.Errorf("%w: purge request event identity differs", store.ErrIdempotencyConflict)
			}
			var prior endpointPurgeRequestedV1
			if err := json.Unmarshal(retained.Data, &prior); err != nil {
				return err
			}
			candidateBody, err := json.Marshal(newEndpointPurgeRequestedV1(req, prior.OutboxID, receiptID))
			if err != nil {
				return err
			}
			if prior.OutboxID <= 0 || !bytes.Equal(candidateBody, retained.Data) {
				return fmt.Errorf("%w: purge request differs from retained event", store.ErrIdempotencyConflict)
			}
			reservedID = prior.OutboxID
		}
		inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			ReservedID: reservedID,
			TenantID:   tenantID, Destination: DestinationEndpointPurge,
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
			return fmt.Errorf("%w: purge outbox id differs from retained event", store.ErrIdempotencyConflict)
		}
		requested := newEndpointPurgeRequestedV1(req, outboxID, receiptID)
		requestBody, err := json.Marshal(requested)
		if err != nil {
			return err
		}
		if !found {
			retained, err = o.log.Append(ctx, events.Event{
				ID: requestID, Type: EventEndpointPurgeRequested,
				SchemaVersion: endpointPurgeRequestSchemaVersion,
				TenantID:      tenantID, Data: requestBody,
			})
			if err != nil {
				return err
			}
			if retained.ID != requestID || retained.TenantID != tenantID ||
				retained.Type != EventEndpointPurgeRequested ||
				retained.SchemaVersion != endpointPurgeRequestSchemaVersion ||
				!bytes.Equal(retained.Data, requestBody) {
				return fmt.Errorf("%w: appended purge request differs", store.ErrIdempotencyConflict)
			}
		}
		receipt, err = o.recordQueuedPurgeReceiptTx(ctx, tx, tenantID, requested, found)
		return err
	})
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, fmt.Errorf("orchestrator: queue endpoint purge: %w", err)
	}
	return receipt, nil
}

func (o *Orchestrator) recordQueuedPurgeReceiptTx(ctx context.Context, tx pgx.Tx,
	tenantID string, requested endpointPurgeRequestedV1, retry bool) (store.ConnectorDeliveryReceipt, error) {
	identityID, outboxID := requested.IdentityID, requested.OutboxID
	receiptPayload, err := json.Marshal(projections.ConnectorDeliveryRecorded{
		ID: requested.ReceiptID, OutboxID: &outboxID, IdentityID: &identityID,
		Destination: DestinationEndpointPurge, Connector: requested.Connector,
		Target: requested.Target, Fingerprint: requested.ExpectedFingerprint,
		Status: servedstatus.ConnectorPurgeQueued, Attempts: 0,
		Reason:         "host material removal queued",
		Detail:         "Awaiting the exact enrolled host agent; no file has been removed and no ledger snapshot wiped.",
		IdempotencyKey: requested.IdempotencyKey,
	})
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	receiptEventID := "endpoint-purge-queued:" + requested.ReceiptID
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
		return store.ConnectorDeliveryReceipt{}, fmt.Errorf("%w: queued purge receipt differs from retained event", store.ErrIdempotencyConflict)
	}
	if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	return o.store.GetConnectorDeliveryReceiptForOutboxTx(ctx, tx, tenantID, outboxID)
}
