// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// KeyCompromiseEffect names one of the two independent receivers of a retained
// compound key-compromise command.
type KeyCompromiseEffect string

const (
	KeyCompromiseEffectHost KeyCompromiseEffect = projections.KeyCompromiseEffectHost
	KeyCompromiseEffectCA   KeyCompromiseEffect = projections.KeyCompromiseEffectCA
)

// maxKeyCompromiseEffectRetries bounds the deterministic retry chain one status
// read walks. Fifty operator-driven retries of one incident command is already
// far beyond anything a working host or CA needs.
const maxKeyCompromiseEffectRetries = 50

// ErrKeyCompromiseEffectNotRetryable means the named effect is queued, in
// flight, already complete, or has no durable evidence to retry from.
var ErrKeyCompromiseEffectNotRetryable = errors.New("key compromise effect is not in a retryable terminal failure state")

func keyCompromiseEffectRetryEventID(sourceEventID string, effect KeyCompromiseEffect, attempt int) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("key-compromise-effect-retry\x00"+sourceEventID+
		"\x00"+string(effect)+"\x00"+strconv.Itoa(attempt))).String()
}

func keyCompromiseContainmentRetryKey(identityID, key string, attempt int) string {
	return keyCompromiseContainmentKey(identityID, key) + ":retry:" + strconv.Itoa(attempt)
}

// latestKeyCompromiseEffectRetry walks the retained retry chain of one effect.
// It returns the newest valid retry and its ordinal, or zero when none exists.
func (o *Orchestrator) latestKeyCompromiseEffectRetry(ctx context.Context, tenantID string,
	source events.Event, effect KeyCompromiseEffect) (projections.KeyCompromiseEffectRetried, int, error) {
	var latest projections.KeyCompromiseEffectRetried
	n := 0
	for attempt := 1; attempt <= maxKeyCompromiseEffectRetries; attempt++ {
		ev, found, err := o.log.EventByID(ctx, keyCompromiseEffectRetryEventID(source.ID, effect, attempt))
		if err != nil {
			return projections.KeyCompromiseEffectRetried{}, 0, err
		}
		if !found {
			break
		}
		value, err := decodeKeyCompromiseEffectRetry(ev, tenantID, source.ID, effect, attempt)
		if err != nil {
			return projections.KeyCompromiseEffectRetried{}, 0, err
		}
		latest, n = value, attempt
	}
	return latest, n, nil
}

func decodeKeyCompromiseEffectRetry(ev events.Event, tenantID, sourceEventID string,
	effect KeyCompromiseEffect, attempt int) (projections.KeyCompromiseEffectRetried, error) {
	var value projections.KeyCompromiseEffectRetried
	if ev.TenantID != tenantID || ev.Type != projections.EventKeyCompromiseEffectRetried ||
		ev.SchemaVersion != 1 || json.Unmarshal(ev.Data, &value) != nil ||
		projections.ValidateKeyCompromiseEffectRetried(value) != nil ||
		value.SourceEventID != sourceEventID || value.Effect != string(effect) || value.Attempt != attempt {
		return projections.KeyCompromiseEffectRetried{}, fmt.Errorf("%w: retained key-compromise retry does not match its command", store.ErrIdempotencyConflict)
	}
	return value, nil
}

// expectedKeyCompromiseHostOutboxID is the outbox row the retained host receipt
// must name: the original reserved row, or the newest retained host retry.
func (o *Orchestrator) expectedKeyCompromiseHostOutboxID(ctx context.Context, tenantID string,
	source events.Event, c *endpointContainmentRequestedV2) (int64, error) {
	latest, n, err := o.latestKeyCompromiseEffectRetry(ctx, tenantID, source, KeyCompromiseEffectHost)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return c.OutboxID, nil
	}
	if latest.ReceiptID != c.ReceiptID || latest.IdentityID != c.IdentityID {
		return 0, fmt.Errorf("%w: retained host retry names a different receipt", store.ErrIdempotencyConflict)
	}
	return latest.OutboxID, nil
}

// RetryKeyCompromiseEffect re-queues one failed effect of a retained compound
// command without a new review: a fresh endpoint.contain job for the same
// reviewed host command on the same receipt, or a re-armed dead-lettered
// revocation.publish row. Each retry is its own retained event; replaying the
// same retry queues nothing more. The identity's later lifecycle state
// (including retirement) does not matter: the compromised leaf is what counts.
func (o *Orchestrator) RetryKeyCompromiseEffect(ctx context.Context, tenantID, identityID, key string,
	effect KeyCompromiseEffect, requestedBy string) (store.OutboxAttempt, store.ConnectorDeliveryReceipt, error) {
	requestedBy = strings.TrimSpace(requestedBy)
	if requestedBy == "" {
		if actor, ok := events.ActorFromContext(ctx); ok {
			requestedBy = actor.Subject
		}
	}
	if requestedBy == "" {
		return store.OutboxAttempt{}, store.ConnectorDeliveryReceipt{}, errors.New("orchestrator: key compromise retry needs the requesting operator")
	}
	if o.outbox == nil || o.proj == nil {
		return store.OutboxAttempt{}, store.ConnectorDeliveryReceipt{}, errors.New("orchestrator: key compromise retry outbox or projector is unavailable")
	}
	source, retained, err := o.retainedKeyCompromise(ctx, tenantID, identityID, key)
	if err != nil {
		return store.OutboxAttempt{}, store.ConnectorDeliveryReceipt{}, err
	}
	ca, host, err := o.KeyCompromiseStatus(ctx, tenantID, identityID, key)
	if err != nil {
		return store.OutboxAttempt{}, store.ConnectorDeliveryReceipt{}, err
	}
	switch effect {
	case KeyCompromiseEffectHost:
		err = o.retryKeyCompromiseHost(ctx, tenantID, identityID, key, requestedBy, source, retained, host)
	case KeyCompromiseEffectCA:
		err = o.retryKeyCompromiseCA(ctx, tenantID, identityID, key, requestedBy, source, retained, ca)
	default:
		err = fmt.Errorf("orchestrator: unknown key compromise effect %q", effect)
	}
	if err != nil {
		return store.OutboxAttempt{}, store.ConnectorDeliveryReceipt{}, err
	}
	return o.KeyCompromiseStatus(ctx, tenantID, identityID, key)
}

func (o *Orchestrator) retryKeyCompromiseHost(ctx context.Context, tenantID, identityID, key, requestedBy string,
	source events.Event, retained transitionPayload, host store.ConnectorDeliveryReceipt) error {
	latest, n, err := o.latestKeyCompromiseEffectRetry(ctx, tenantID, source, KeyCompromiseEffectHost)
	if err != nil {
		return err
	}
	c := retained.CompromiseContainment
	// A replay after the retried job was queued returns the same queued state:
	// the exact agent still owns that job and must report before another retry.
	if n > 0 && host.OutboxID != nil && *host.OutboxID == latest.OutboxID && host.Status == "containment_queued" {
		return nil
	}
	switch host.Status {
	case "containment_failed", "containment_unverified":
	default:
		return fmt.Errorf("%w: host receipt is %s", ErrKeyCompromiseEffectNotRetryable, host.Status)
	}
	attempt := n + 1
	if attempt > maxKeyCompromiseEffectRetries {
		return fmt.Errorf("%w: host containment retry limit reached", ErrKeyCompromiseEffectNotRetryable)
	}
	eventID := keyCompromiseEffectRetryEventID(source.ID, KeyCompromiseEffectHost, attempt)
	command, err := json.Marshal(c.request())
	if err != nil {
		return err
	}
	hostKey := keyCompromiseContainmentRetryKey(identityID, key, attempt)
	return o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		// A prior attempt may have appended this exact retry and lost its SQL
		// transaction. Reuse the outbox identity its evidence already names.
		prior, found, err := o.log.EventByID(ctx, eventID)
		if err != nil {
			return err
		}
		var reservedID int64
		if found {
			value, err := decodeKeyCompromiseEffectRetry(prior, tenantID, source.ID, KeyCompromiseEffectHost, attempt)
			if err != nil {
				return err
			}
			reservedID = value.OutboxID
		}
		if _, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			ReservedID: reservedID, TenantID: tenantID,
			Destination:    DestinationEndpointContainment,
			IdempotencyKey: hostKey, Payload: command, EffectLane: ConnectorTargetEffectLane(c.TargetID),
			RequiredAgentRole: "host", RequiredAgentID: c.RequiredAgentID,
		}); err != nil {
			return err
		}
		var outboxID int64
		if err := tx.QueryRow(ctx,
			`SELECT id FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE`,
			tenantID, hostKey).Scan(&outboxID); err != nil {
			return err
		}
		if reservedID != 0 && outboxID != reservedID {
			return store.ErrIdempotencyConflict
		}
		if !found {
			value := projections.KeyCompromiseEffectRetried{
				SourceEventID: source.ID, IdentityID: identityID, RequestKey: key,
				Effect: projections.KeyCompromiseEffectHost, Attempt: attempt,
				OutboxID: outboxID, ReceiptID: c.ReceiptID, RequestedBy: requestedBy,
			}
			if err := projections.ValidateKeyCompromiseEffectRetried(value); err != nil {
				return err
			}
			data, err := json.Marshal(value)
			if err != nil {
				return err
			}
			prior, err = o.log.Append(ctx, events.Event{
				ID: eventID, TenantID: tenantID, Type: projections.EventKeyCompromiseEffectRetried,
				SchemaVersion: 1, Data: data,
			})
			if err != nil {
				return err
			}
			if _, err := decodeKeyCompromiseEffectRetry(prior, tenantID, source.ID, KeyCompromiseEffectHost, attempt); err != nil {
				return err
			}
		}
		return o.proj.ApplyTx(ctx, tx, prior)
	})
}

func (o *Orchestrator) retryKeyCompromiseCA(ctx context.Context, tenantID, identityID, key, requestedBy string,
	source events.Event, retained transitionPayload, ca store.OutboxAttempt) error {
	latest, n, err := o.latestKeyCompromiseEffectRetry(ctx, tenantID, source, KeyCompromiseEffectCA)
	if err != nil {
		return err
	}
	// A replay after the row was re-armed returns the same pending state: the
	// CA dispatcher owns the command until it delivers or dead-letters again.
	if n > 0 && latest.OutboxID == ca.ID && (ca.Status == "pending" || ca.Status == "processing") {
		return nil
	}
	if ca.Status != "failed" || ca.ID <= 0 {
		return fmt.Errorf("%w: CA publication is %s", ErrKeyCompromiseEffectNotRetryable, ca.Status)
	}
	caKey, _, err := lifecycleOutboxIntentFromEvent(source, retained, "revocation.publish")
	if err != nil {
		return err
	}
	attempt := n + 1
	if attempt > maxKeyCompromiseEffectRetries {
		return fmt.Errorf("%w: CA publication retry limit reached", ErrKeyCompromiseEffectNotRetryable)
	}
	eventID := keyCompromiseEffectRetryEventID(source.ID, KeyCompromiseEffectCA, attempt)
	return o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := o.store.RequeueDeadLetteredOutboxTx(ctx, tx, tenantID, ca.ID, "revocation.publish", caKey); err != nil {
			return err
		}
		value := projections.KeyCompromiseEffectRetried{
			SourceEventID: source.ID, IdentityID: identityID, RequestKey: key,
			Effect: projections.KeyCompromiseEffectCA, Attempt: attempt,
			OutboxID: ca.ID, RequestedBy: requestedBy,
		}
		if err := projections.ValidateKeyCompromiseEffectRetried(value); err != nil {
			return err
		}
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		appended, err := o.log.Append(ctx, events.Event{
			ID: eventID, TenantID: tenantID, Type: projections.EventKeyCompromiseEffectRetried,
			SchemaVersion: 1, Data: data,
		})
		if err != nil {
			return err
		}
		if _, err := decodeKeyCompromiseEffectRetry(appended, tenantID, source.ID, KeyCompromiseEffectCA, attempt); err != nil {
			return err
		}
		return o.proj.ApplyTx(ctx, tx, appended)
	})
}
