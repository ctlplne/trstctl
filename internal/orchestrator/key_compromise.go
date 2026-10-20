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

// ErrKeyCompromiseContainmentRequired means CA publication alone cannot be
// reported as a complete response for an X.509 identity that may be serving a
// compromised leaf. The reviewed compound command retains both effects.
var ErrKeyCompromiseContainmentRequired = errors.New("serving X.509 key compromise requires reviewed CA revocation and host containment; use the key-compromise command")

// KeyCompromiseNeedsContainment is shared by operator previews and the command
// boundary. A failed renewal still leaves the previous certificate serving.
// Status, not optional target metadata, is the conservative serving signal.
func KeyCompromiseNeedsContainment(identity store.Identity, to State, reason string) bool {
	if to != StateRevoked || reason != "keyCompromise" ||
		(identity.Kind != store.KindX509Certificate && identity.Kind != "x509") {
		return false
	}
	switch State(identity.Status) {
	case StateDeployed, StateRenewing, StateRenewalFailed:
		return true
	default:
		return false
	}
}

func keyCompromiseEventID(tenantID, identityID, key string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID,
		[]byte("identity-key-compromise\x00"+tenantID+"\x00"+identityID+"\x00"+key)).String()
}

func keyCompromiseCAEffectEventID(sourceEventID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("key-compromise-ca-effect\x00"+sourceEventID)).String()
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
	_, hostExistsErr := o.store.GetConnectorDeliveryReceipt(ctx, tenantID, c.ReceiptID)
	if hostExistsErr != nil && !errors.Is(hostExistsErr, pgx.ErrNoRows) {
		return store.ConnectorDeliveryReceipt{}, hostExistsErr
	}
	_, caExistsErr := o.store.GetOutboxAttemptByKey(ctx, tenantID, "revocation.publish", caKey)
	if caExistsErr != nil && !errors.Is(caExistsErr, pgx.ErrNoRows) {
		return store.ConnectorDeliveryReceipt{}, caExistsErr
	}
	enqueueCA := true
	if errors.Is(caExistsErr, pgx.ErrNoRows) && hostExistsErr == nil {
		_, completed, err := o.retainedKeyCompromiseCAEffect(ctx, tenantID, ev)
		if err != nil {
			return store.ConnectorDeliveryReceipt{}, err
		}
		if !completed {
			return store.ConnectorDeliveryReceipt{}, fmt.Errorf("orchestrator: historical CA outcome has no durable receipt; verify exact revocation before retry: %w", store.ErrIdempotencyConflict)
		}
		enqueueCA = false
	}
	hostCommand, err := json.Marshal(c.request())
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	if err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if enqueueCA {
			if _, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
				TenantID: tenantID, Destination: "revocation.publish",
				IdempotencyKey: caKey, Payload: caPayload,
				EffectLane: lifecycleEffectLane("revocation.publish", identityID, caPayload),
			}); err != nil {
				return err
			}
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
	expectedOutbox, err := o.expectedKeyCompromiseHostOutboxID(ctx, tenantID, ev, c)
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	if receipt.OutboxID == nil || *receipt.OutboxID != expectedOutbox {
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

// RecordKeyCompromiseCAEffectCompleted is called only after the CA worker has
// returned success. The retained receipt survives delivered-outbox GC; it is
// bound to the original reviewed event and the exact outbox command. Ordinary
// non-compound revocations have no matching v8 event and need no such receipt.
func (o *Orchestrator) RecordKeyCompromiseCAEffectCompleted(ctx context.Context,
	tenantID, identityID, key string, outboxID int64, attempts int) error {
	if outboxID <= 0 || key == "" {
		return store.ErrIdempotencyConflict
	}
	sourceID := keyCompromiseEventID(tenantID, identityID, key)
	_, found, err := o.log.EventByID(ctx, sourceID)
	if err != nil || !found {
		return err
	}
	source, retained, err := o.retainedKeyCompromise(ctx, tenantID, identityID, key)
	if err != nil {
		return err
	}
	caKey, _, err := lifecycleOutboxIntentFromEvent(source, retained, "revocation.publish")
	if err != nil {
		return err
	}
	row, err := o.store.GetOutboxAttemptByKey(ctx, tenantID, "revocation.publish", caKey)
	if err != nil || row.ID != outboxID {
		if err != nil {
			return err
		}
		return store.ErrIdempotencyConflict
	}
	if attempts < 1 {
		attempts = 1
	}
	value := projections.KeyCompromiseCAEffectCompleted{
		SourceEventID: source.ID, OutboxID: outboxID,
		Destination: "revocation.publish", Status: "delivered", Attempts: attempts,
	}
	if err := projections.ValidateKeyCompromiseCAEffectCompleted(value); err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	receiptID := keyCompromiseCAEffectEventID(source.ID)
	if prior, found, err := o.log.EventByID(ctx, receiptID); err != nil {
		return err
	} else if found {
		if prior.TenantID != tenantID || prior.Type != projections.EventKeyCompromiseCAEffectCompleted ||
			prior.SchemaVersion != 1 || !json.Valid(prior.Data) {
			return store.ErrIdempotencyConflict
		}
		var priorValue projections.KeyCompromiseCAEffectCompleted
		if json.Unmarshal(prior.Data, &priorValue) != nil ||
			projections.ValidateKeyCompromiseCAEffectCompleted(priorValue) != nil ||
			priorValue.SourceEventID != value.SourceEventID ||
			priorValue.OutboxID != value.OutboxID ||
			priorValue.Destination != value.Destination || priorValue.Status != value.Status {
			return store.ErrIdempotencyConflict
		}
		// The worker can complete and append this receipt, then lose its ACK.
		// A retry of the same command has a later attempt count; the first
		// terminal receipt stays authoritative and the retry may ACK.
		return nil
	}
	appended, err := o.log.Append(ctx, events.Event{
		ID: receiptID, TenantID: tenantID, Type: projections.EventKeyCompromiseCAEffectCompleted,
		SchemaVersion: 1, Data: data,
	})
	if err != nil {
		return err
	}
	// A second worker may have won the deterministic event ID between the
	// indexed read and append. JetStream returns that canonical first receipt.
	var canonical projections.KeyCompromiseCAEffectCompleted
	if appended.TenantID != tenantID || appended.Type != projections.EventKeyCompromiseCAEffectCompleted ||
		appended.SchemaVersion != 1 || json.Unmarshal(appended.Data, &canonical) != nil ||
		projections.ValidateKeyCompromiseCAEffectCompleted(canonical) != nil ||
		canonical.SourceEventID != value.SourceEventID || canonical.OutboxID != value.OutboxID ||
		canonical.Destination != value.Destination || canonical.Status != value.Status {
		return store.ErrIdempotencyConflict
	}
	return nil
}

func (o *Orchestrator) retainedKeyCompromiseCAEffect(ctx context.Context,
	tenantID string, source events.Event) (store.OutboxAttempt, bool, error) {
	receipt, found, err := o.log.EventByID(ctx, keyCompromiseCAEffectEventID(source.ID))
	if err != nil || !found {
		return store.OutboxAttempt{}, found, err
	}
	if receipt.TenantID != tenantID || receipt.Type != projections.EventKeyCompromiseCAEffectCompleted ||
		receipt.SchemaVersion != 1 {
		return store.OutboxAttempt{}, false, store.ErrIdempotencyConflict
	}
	var value projections.KeyCompromiseCAEffectCompleted
	if json.Unmarshal(receipt.Data, &value) != nil ||
		projections.ValidateKeyCompromiseCAEffectCompleted(value) != nil ||
		value.SourceEventID != source.ID {
		return store.OutboxAttempt{}, false, store.ErrIdempotencyConflict
	}
	at := receipt.Time
	return store.OutboxAttempt{
		ID: value.OutboxID, Destination: value.Destination, Status: value.Status,
		Attempts: value.Attempts, DeliveredAt: &at,
	}, true, nil
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
	if errors.Is(err, pgx.ErrNoRows) {
		if retainedCA, found, receiptErr := o.retainedKeyCompromiseCAEffect(ctx, tenantID, ev); receiptErr != nil {
			return store.OutboxAttempt{}, store.ConnectorDeliveryReceipt{}, receiptErr
		} else if found {
			ca = retainedCA
		} else {
			ca = store.OutboxAttempt{
				Destination: "revocation.publish", Status: "evidence_unavailable",
				LastError: "historical CA delivery evidence expired; verify exact serials against the issuing CA and signed CRL or OCSP",
			}
		}
	} else if err != nil {
		return store.OutboxAttempt{}, store.ConnectorDeliveryReceipt{}, err
	}
	c := retained.CompromiseContainment
	host, err := o.store.GetConnectorDeliveryReceipt(ctx, tenantID, c.ReceiptID)
	if err != nil {
		return store.OutboxAttempt{}, store.ConnectorDeliveryReceipt{}, err
	}
	// An operator retry moves the same receipt onto a fresh host job; the newest
	// retained retry, not the original reservation, is then the exact row.
	expectedOutbox, err := o.expectedKeyCompromiseHostOutboxID(ctx, tenantID, ev, c)
	if err != nil {
		return store.OutboxAttempt{}, store.ConnectorDeliveryReceipt{}, err
	}
	if host.OutboxID == nil || *host.OutboxID != expectedOutbox || host.IdentityID == nil ||
		*host.IdentityID != identityID || host.Fingerprint != c.ExpectedFingerprint {
		return store.OutboxAttempt{}, store.ConnectorDeliveryReceipt{}, store.ErrIdempotencyConflict
	}
	return ca, host, nil
}
