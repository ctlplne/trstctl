// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const notificationTestDestination = "notification.test"

// NotificationTestOperation is the durable, tenant-scoped authority for one
// operator-requested channel test. It retains only the authenticated command
// digest and public response metadata; channel credentials and alert bodies stay
// out of the read model.
type NotificationTestOperation struct {
	TenantID             string
	ID                   string
	RequestBinding       string
	ChannelID            string
	Destination          string
	OutboxID             int64
	CredentialConfigured bool
	QueuedAt             time.Time
}

// NotificationDeliveryReceipt is one event-sourced successful receiver effect.
// The raw outbox idempotency key and alert body are represented only by digests.
type NotificationDeliveryReceipt struct {
	TenantID              string
	ID                    string
	Destination           string
	NotificationKeyDigest string
	PayloadDigest         string
	Channel               string
	OutboxID              *int64
	Attempts              int
	DeliveredAt           time.Time
	RoutingSource         string
	RoutingPolicyID       string
	RoutingPolicyScope    string
	RoutingPolicyDigest   string
}

// GetNotificationTestOperation loads the durable operation for a deterministic
// tenant + raw Idempotency-Key operation id.
func (s *Store) GetNotificationTestOperation(ctx context.Context, tenantID, id string) (NotificationTestOperation, error) {
	var op NotificationTestOperation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanNotificationTestOperation(tx.QueryRow(ctx,
			`SELECT tenant_id::text, id, request_binding, channel_id, destination,
			        outbox_id, credential_configured, queued_at
			   FROM notification_test_operations
			  WHERE tenant_id = $1 AND id = $2`, tenantID, id), &op)
	})
	return op, err
}

func scanNotificationTestOperation(row pgx.Row, op *NotificationTestOperation) error {
	return row.Scan(&op.TenantID, &op.ID, &op.RequestBinding, &op.ChannelID,
		&op.Destination, &op.OutboxID, &op.CredentialConfigured, &op.QueuedAt)
}

// ApplyNotificationTestQueuedTx projects an immutable test command and its
// external-call intent in one tenant transaction. Replaying the event converges
// on the same operation. Once the operation exists, later replay never recreates
// a retention-GC'd delivered outbox row.
func (s *Store) ApplyNotificationTestQueuedTx(
	ctx context.Context,
	tx pgx.Tx,
	op NotificationTestOperation,
	effectLane string,
	payload []byte,
) error {
	if op.TenantID == "" || op.ID == "" || op.RequestBinding == "" ||
		op.ChannelID == "" || op.Destination != notificationTestDestination ||
		effectLane != notificationTestDestination+":channel:"+op.ChannelID ||
		len(payload) == 0 || op.QueuedAt.IsZero() {
		return errors.New("store: notification test operation is incomplete")
	}
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"notification-test-operation\x1f"+op.TenantID+"\x1f"+op.ID); err != nil {
		return fmt.Errorf("store: lock notification test operation: %w", err)
	}

	var existing NotificationTestOperation
	err := scanNotificationTestOperation(tx.QueryRow(ctx,
		`SELECT tenant_id::text, id, request_binding, channel_id, destination,
		        outbox_id, credential_configured, queued_at
		   FROM notification_test_operations
		  WHERE tenant_id = $1 AND id = $2`, op.TenantID, op.ID), &existing)
	if err == nil {
		if !sameNotificationTestOperation(existing, op) {
			return fmt.Errorf("%w: notification test key belongs to another authenticated command", ErrIdempotencyConflict)
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	outboxID, err := ensureNotificationTestOutboxTx(ctx, tx, op.TenantID, op.ID, effectLane, payload)
	if err != nil {
		return err
	}
	op.OutboxID = outboxID
	_, err = tx.Exec(ctx,
		`INSERT INTO notification_test_operations
		        (tenant_id, id, request_binding, channel_id, destination, outbox_id,
		         credential_configured, queued_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		op.TenantID, op.ID, op.RequestBinding, op.ChannelID, op.Destination,
		op.OutboxID, op.CredentialConfigured, op.QueuedAt.UTC())
	return err
}

func sameNotificationTestOperation(a, b NotificationTestOperation) bool {
	return a.TenantID == b.TenantID && a.ID == b.ID &&
		a.RequestBinding == b.RequestBinding && a.ChannelID == b.ChannelID &&
		a.Destination == b.Destination &&
		a.CredentialConfigured == b.CredentialConfigured &&
		// PostgreSQL timestamps retain microseconds while the event envelope can
		// carry nanoseconds. That precision difference is not command drift.
		a.QueuedAt.UTC().Truncate(time.Microsecond).Equal(
			b.QueuedAt.UTC().Truncate(time.Microsecond))
}

func ensureNotificationTestOutboxTx(ctx context.Context, tx pgx.Tx, tenantID, key, effectLane string, payload []byte) (int64, error) {
	var (
		id                  int64
		existingDestination string
		existingLane        string
		existingPayload     []byte
	)
	err := tx.QueryRow(ctx,
		`SELECT id, destination, COALESCE(NULLIF(effect_lane, ''), destination), payload
		   FROM outbox
		  WHERE tenant_id = $1 AND idempotency_key = $2
		  ORDER BY id LIMIT 1`, tenantID, key).
		Scan(&id, &existingDestination, &existingLane, &existingPayload)
	if err == nil {
		if existingDestination != notificationTestDestination || existingLane != effectLane || !bytes.Equal(existingPayload, payload) {
			return 0, fmt.Errorf("%w: notification test outbox command differs", ErrIdempotencyConflict)
		}
		return id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	if err := tx.QueryRow(ctx,
		`INSERT INTO outbox (tenant_id, destination, effect_lane, payload, idempotency_key)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id`, tenantID, notificationTestDestination, effectLane, payload, key).Scan(&id); err != nil {
		return 0, fmt.Errorf("store: enqueue notification test: %w", err)
	}
	return id, nil
}

// GetNotificationDeliveryReceipt loads one deterministic per-channel delivery
// receipt in the tenant's RLS context.
func (s *Store) GetNotificationDeliveryReceipt(ctx context.Context, tenantID, id string) (NotificationDeliveryReceipt, error) {
	var rec NotificationDeliveryReceipt
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanNotificationDeliveryReceipt(tx.QueryRow(ctx,
			`SELECT tenant_id::text, id, destination, notification_key_digest,
			        payload_digest, channel, outbox_id, attempts, delivered_at,
			        routing_source, routing_policy_id, routing_policy_scope, routing_policy_digest
			   FROM notification_delivery_receipts
			  WHERE tenant_id = $1 AND id = $2`, tenantID, id), &rec)
	})
	return rec, err
}

func scanNotificationDeliveryReceipt(row pgx.Row, rec *NotificationDeliveryReceipt) error {
	return row.Scan(&rec.TenantID, &rec.ID, &rec.Destination,
		&rec.NotificationKeyDigest, &rec.PayloadDigest, &rec.Channel,
		&rec.OutboxID, &rec.Attempts, &rec.DeliveredAt, &rec.RoutingSource,
		&rec.RoutingPolicyID, &rec.RoutingPolicyScope, &rec.RoutingPolicyDigest)
}

// ListNotificationDeliveryReceipts loads the exact command's successful channel
// receipts. The binding survives outbox retention/rebuild and never joins a new
// command that happens to reuse a database sequence number.
func (s *Store) ListNotificationDeliveryReceipts(ctx context.Context, tenantID, destination, keyDigest, payloadDigest string) ([]NotificationDeliveryReceipt, error) {
	out := make([]NotificationDeliveryReceipt, 0)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id::text, id, destination, notification_key_digest,
			payload_digest, channel, outbox_id, attempts, delivered_at,
			routing_source, routing_policy_id, routing_policy_scope, routing_policy_digest
			FROM notification_delivery_receipts
			WHERE tenant_id = $1 AND destination = $2 AND notification_key_digest = $3 AND payload_digest = $4
			ORDER BY delivered_at, channel, id`, tenantID, destination, keyDigest, payloadDigest)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rec NotificationDeliveryReceipt
			if err := scanNotificationDeliveryReceipt(rows, &rec); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	return out, err
}

// ApplyNotificationDeliveryRecordedTx projects a successful receiver effect.
// The first binding is authoritative; a hash collision or altered event fails
// closed instead of treating another command as proof of delivery.
func (s *Store) ApplyNotificationDeliveryRecordedTx(ctx context.Context, tx pgx.Tx, rec NotificationDeliveryReceipt) error {
	rec.Channel = strings.ToLower(strings.TrimSpace(rec.Channel))
	if rec.TenantID == "" || rec.ID == "" || rec.Destination == "" ||
		rec.NotificationKeyDigest == "" || rec.PayloadDigest == "" ||
		rec.Channel == "" || rec.DeliveredAt.IsZero() {
		return errors.New("store: notification delivery receipt is incomplete")
	}
	if err := validateNotificationDeliveryRouting(rec); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO notification_delivery_receipts
		        (tenant_id, id, destination, notification_key_digest, payload_digest,
		         channel, outbox_id, attempts, delivered_at,
		         routing_source, routing_policy_id, routing_policy_scope, routing_policy_digest)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		 ON CONFLICT (tenant_id, id) DO NOTHING`,
		rec.TenantID, rec.ID, rec.Destination, rec.NotificationKeyDigest,
		rec.PayloadDigest, rec.Channel, rec.OutboxID, rec.Attempts, rec.DeliveredAt.UTC(),
		rec.RoutingSource, rec.RoutingPolicyID, rec.RoutingPolicyScope, rec.RoutingPolicyDigest)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var existing NotificationDeliveryReceipt
	if err := scanNotificationDeliveryReceipt(tx.QueryRow(ctx,
		`SELECT tenant_id::text, id, destination, notification_key_digest,
		        payload_digest, channel, outbox_id, attempts, delivered_at,
		        routing_source, routing_policy_id, routing_policy_scope, routing_policy_digest
		   FROM notification_delivery_receipts
		  WHERE tenant_id = $1 AND id = $2`, rec.TenantID, rec.ID), &existing); err != nil {
		return err
	}
	if existing.Destination != rec.Destination ||
		existing.NotificationKeyDigest != rec.NotificationKeyDigest ||
		existing.PayloadDigest != rec.PayloadDigest || existing.Channel != rec.Channel ||
		existing.RoutingSource != rec.RoutingSource || existing.RoutingPolicyID != rec.RoutingPolicyID ||
		existing.RoutingPolicyScope != rec.RoutingPolicyScope || existing.RoutingPolicyDigest != rec.RoutingPolicyDigest {
		return fmt.Errorf("%w: notification delivery receipt belongs to another receiver command", ErrIdempotencyConflict)
	}
	return nil
}

func validateNotificationDeliveryRouting(rec NotificationDeliveryReceipt) error {
	switch rec.RoutingSource {
	case "", "all_channels", "channel_test":
		if rec.RoutingPolicyID == "" && rec.RoutingPolicyScope == "" && rec.RoutingPolicyDigest == "" {
			return nil
		}
	case "explicit_policy", "inherited_policy", "default_policy":
		if rec.RoutingSource != "default_policy" && rec.RoutingPolicyID == "" {
			break
		}
		if len(rec.RoutingPolicyDigest) == 64 && strings.Trim(rec.RoutingPolicyDigest, "0123456789abcdef") == "" {
			return nil
		}
	}
	return errors.New("store: notification delivery routing evidence is invalid")
}
