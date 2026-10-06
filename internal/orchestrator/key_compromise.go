// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"

	"trstctl.com/trstctl/internal/store"
)

func keyCompromiseEventID(tenantID, identityID, key string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID,
		[]byte("identity-key-compromise\x00"+tenantID+"\x00"+identityID+"\x00"+key)).String()
}

func keyCompromiseContainmentKey(identityID, key string) string {
	return "compromise-contain:" + identityID + ":" + key
}

func validateKeyCompromiseContainment(identityID, key string, req EndpointContainmentRequest) error {
	if _, err := uuid.Parse(req.TargetID); err != nil {
		return fmt.Errorf("orchestrator: compromise needs an exact target id: %w", err)
	}
	if _, err := uuid.Parse(req.RequiredAgentID); err != nil {
		return fmt.Errorf("orchestrator: compromise needs an exact agent id: %w", err)
	}
	if req.IdentityID != identityID || req.IdempotencyKey != key || req.Reason != "keyCompromise" ||
		req.TargetRevision == "" || req.RequestedBy == "" || req.Target == "" ||
		!connector.CanRollbackOnHost(req.Connector) {
		return fmt.Errorf("orchestrator: compromise needs the reviewed host target and exact request binding")
	}
	if raw, err := hex.DecodeString(req.ExpectedFingerprint); err != nil || len(raw) != 32 ||
		strings.ToLower(req.ExpectedFingerprint) != req.ExpectedFingerprint {
		return fmt.Errorf("orchestrator: compromise needs the exact lowercase SHA-256 leaf fingerprint")
	}
	return nil
}

// TransitionKeyCompromise records one reviewed identity revocation with two
// durable, independently executable outbox intents: CA publication and exact
// host containment. Neither receiver's success is inferred from acceptance.
func (o *Orchestrator) TransitionKeyCompromise(ctx context.Context, tenantID, identityID,
	idempotencyKey string, expectedVersion *uint64, containment EndpointContainmentRequest,
) (store.ConnectorDeliveryReceipt, error) {
	return o.transitionKeyCompromise(ctx, tenantID, identityID, idempotencyKey,
		expectedVersion, containment, nil)
}

// TransitionKeyCompromiseWithApproval consumes the same exact dual-control
// authority as an ordinary lifecycle revoke, in the transaction that projects
// the compound event and enqueues both independent effects.
func (o *Orchestrator) TransitionKeyCompromiseWithApproval(ctx context.Context,
	tenantID, identityID, idempotencyKey string, expectedVersion *uint64,
	containment EndpointContainmentRequest, approval store.OperationApprovalUse,
) (store.ConnectorDeliveryReceipt, error) {
	return o.transitionKeyCompromise(ctx, tenantID, identityID, idempotencyKey,
		expectedVersion, containment, &approval)
}

func (o *Orchestrator) transitionKeyCompromise(ctx context.Context, tenantID, identityID,
	idempotencyKey string, expectedVersion *uint64, containment EndpointContainmentRequest,
	approval *store.OperationApprovalUse,
) (store.ConnectorDeliveryReceipt, error) {
	if strings.TrimSpace(idempotencyKey) == "" || containment.IdempotencyKey != idempotencyKey ||
		containment.IdentityID != identityID || containment.Reason != "keyCompromise" {
		return store.ConnectorDeliveryReceipt{}, fmt.Errorf("orchestrator: key compromise needs one exact identity, reason and request key")
	}
	if err := validateKeyCompromiseContainment(identityID, idempotencyKey, containment); err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	current, err := o.store.GetIdentity(ctx, tenantID, identityID)
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	if current.Status == string(StateRevoked) && approval == nil {
		return o.replayKeyCompromise(ctx, tenantID, identityID, idempotencyKey, containment)
	}
	if err := o.transition(ctx, tenantID, identityID, StateRevoked, "keyCompromise", nil,
		idempotencyKey, "", nil, approval, nil, expectedVersion, "",
		transitionOptions{compromise: &containment}); err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	return o.store.GetConnectorDeliveryReceipt(ctx, tenantID,
		endpointContainmentReceiptID(tenantID, containment.TargetID, idempotencyKey))
}

// A lost HTTP result or an event/SQL gap can reach a retry after the projector
// has already moved the identity to revoked. Prove the exact retained command
// before returning its receipt, and repair either missing outbox row in place.
func (o *Orchestrator) replayKeyCompromise(ctx context.Context, tenantID, identityID, key string,
	request EndpointContainmentRequest) (store.ConnectorDeliveryReceipt, error) {
	ev, retained, err := o.retainedKeyCompromise(ctx, tenantID, identityID, key)
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	if retained.CompromiseContainment.request() != request {
		return store.ConnectorDeliveryReceipt{}, store.ErrIdempotencyConflict
	}
	caKey, caPayload, err := lifecycleOutboxIntentFromEvent(ev, retained, "revocation.publish")
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	c := retained.CompromiseContainment
	hostCommand, err := json.Marshal(c.request())
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	if err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID: tenantID, Destination: "revocation.publish",
			IdempotencyKey: caKey, Payload: caPayload,
			EffectLane: lifecycleEffectLane("revocation.publish", identityID, caPayload),
		}); err != nil {
			return err
		}
		_, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			ReservedID: c.OutboxID, TenantID: tenantID,
			Destination:    DestinationEndpointContainment,
			IdempotencyKey: keyCompromiseContainmentKey(identityID, key),
			Payload:        hostCommand, EffectLane: ConnectorTargetEffectLane(c.TargetID),
			RequiredAgentRole: "host", RequiredAgentID: c.RequiredAgentID,
		})
		return err
	}); err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	receipt, err := o.store.GetConnectorDeliveryReceipt(ctx, tenantID, c.ReceiptID)
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, fmt.Errorf("orchestrator: compromise receipt has not projected from retained event: %w", err)
	}
	if receipt.OutboxID == nil || *receipt.OutboxID != c.OutboxID {
		return store.ConnectorDeliveryReceipt{}, fmt.Errorf("orchestrator: compromise receipt outbox does not match retained event: %w", store.ErrIdempotencyConflict)
	}
	return receipt, nil
}

func (o *Orchestrator) retainedKeyCompromise(ctx context.Context, tenantID, identityID, key string) (events.Event, transitionPayload, error) {
	ev, found, err := o.log.EventByID(ctx, keyCompromiseEventID(tenantID, identityID, key))
	if err != nil {
		return events.Event{}, transitionPayload{}, err
	}
	if !found || ev.TenantID != tenantID || ev.Type != projections.EventIdentityRevoked ||
		ev.SchemaVersion != projections.LifecycleKeyCompromiseEventSchemaVersion {
		return events.Event{}, transitionPayload{}, store.ErrIdempotencyConflict
	}
	if err := projections.ValidateLifecycleApprovalEvent(ev); err != nil {
		return events.Event{}, transitionPayload{}, err
	}
	var retained transitionPayload
	if err := json.Unmarshal(ev.Data, &retained); err != nil {
		return events.Event{}, transitionPayload{}, err
	}
	if retained.IdentityID != identityID || retained.IdempotencyKey != key ||
		retained.CompromiseContainment == nil {
		return events.Event{}, transitionPayload{}, store.ErrIdempotencyConflict
	}
	return ev, retained, nil
}

// KeyCompromiseStatus reads both independently advancing effects of one
// retained command. It never creates or retries work; missing projected state
// remains an error instead of being reported as completed.
func (o *Orchestrator) KeyCompromiseStatus(ctx context.Context, tenantID, identityID, key string) (store.OutboxAttempt, store.ConnectorDeliveryReceipt, error) {
	ev, retained, err := o.retainedKeyCompromise(ctx, tenantID, identityID, key)
	if err != nil {
		return store.OutboxAttempt{}, store.ConnectorDeliveryReceipt{}, err
	}
	caKey, _, err := lifecycleOutboxIntentFromEvent(ev, retained, "revocation.publish")
	if err != nil {
		return store.OutboxAttempt{}, store.ConnectorDeliveryReceipt{}, err
	}
	ca, err := o.store.GetOutboxAttemptByKey(ctx, tenantID, "revocation.publish", caKey)
	if err != nil {
		return store.OutboxAttempt{}, store.ConnectorDeliveryReceipt{}, err
	}
	c := retained.CompromiseContainment
	host, err := o.store.GetConnectorDeliveryReceipt(ctx, tenantID, c.ReceiptID)
	if err != nil {
		return store.OutboxAttempt{}, store.ConnectorDeliveryReceipt{}, err
	}
	if host.OutboxID == nil || *host.OutboxID != c.OutboxID || host.IdentityID == nil ||
		*host.IdentityID != identityID || host.Fingerprint != c.ExpectedFingerprint {
		return store.OutboxAttempt{}, store.ConnectorDeliveryReceipt{}, store.ErrIdempotencyConflict
	}
	return ca, host, nil
}
