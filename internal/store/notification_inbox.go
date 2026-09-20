// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Notification inbox conflict sentinels are mapped by the REST layer to 409.
var (
	ErrNotificationNotDead           = errors.New("store: notification is not dead")
	ErrNotificationAlreadyProcessing = errors.New("store: notification is already processing")
)

// NotificationOutboxRecord is the tenant-visible notification inbox projection.
// The delivery attempt state is read from outbox (AN-6); ReadAt is the
// event-sourced operator read receipt projection.
type NotificationOutboxRecord struct {
	ID             int64
	TenantID       string
	Destination    string
	Payload        []byte
	IdempotencyKey string
	Status         string
	OutboxStatus   string
	Attempts       int
	LastError      string
	CreatedAt      time.Time
	DeliveredAt    *time.Time
	ReadAt         *time.Time
}

// NotificationReadReceipt is the payload projected from notification.read.
type NotificationReadReceipt struct {
	TenantID string
	OutboxID int64
	ReadAt   time.Time
}

// ListNotificationOutboxPage returns notification.* outbox rows for one tenant,
// decorated with their read receipt projection. status is the REST status
// vocabulary: pending, sent, dead, read, or empty for all.
func (s *Store) ListNotificationOutboxPage(ctx context.Context, tenantID string, afterID int64, limit int, status string) ([]NotificationOutboxRecord, error) {
	return s.ListNotificationOutboxPageWithOrder(ctx, tenantID, afterID, limit, status, false)
}

// ListNotificationOutboxPageWithOrder uses the same stable ID cursor in either
// direction. Newest-first starts at zero and continues strictly below the last ID.
func (s *Store) ListNotificationOutboxPageWithOrder(ctx context.Context, tenantID string, afterID int64, limit int, status string, newestFirst bool) ([]NotificationOutboxRecord, error) {
	comparison, direction := "o.id > $2", "ASC"
	if newestFirst {
		comparison, direction = "($2 = 0 OR o.id < $2)", "DESC"
	}
	var out []NotificationOutboxRecord
	status = normalizeNotificationInboxStatus(status)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, notificationOutboxSelectSQL(`
			  WHERE o.tenant_id = $1
			    AND o.destination LIKE 'notification.%'
			    AND `+comparison+`
			    AND ($3 = '' OR `+notificationStatusExpr()+` = $3)
			  ORDER BY o.id `+direction+`
			  LIMIT $4`),
			tenantID, afterID, status, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanNotificationOutbox(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// GetNotificationOutbox returns one tenant-scoped notification.* outbox row.
func (s *Store) GetNotificationOutbox(ctx context.Context, tenantID string, id int64) (NotificationOutboxRecord, error) {
	var out NotificationOutboxRecord
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		r, err := getNotificationOutboxTx(ctx, tx, tenantID, id)
		if err != nil {
			return err
		}
		out = r
		return nil
	})
	return out, err
}

// RequeueNotificationOutbox moves a dead notification outbox row back to the
// pending queue. A row already pending is returned as-is so repeated operator
// clicks with a new idempotency key are harmless; delivered rows conflict.
func (s *Store) RequeueNotificationOutbox(ctx context.Context, tenantID string, id int64) (NotificationOutboxRecord, error) {
	var out NotificationOutboxRecord
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var current string
		if err := tx.QueryRow(ctx,
			`SELECT status
			   FROM outbox
			  WHERE tenant_id = $1
			    AND id = $2
			    AND destination LIKE 'notification.%'
			  FOR UPDATE`,
			tenantID, id).Scan(&current); err != nil {
			return err
		}
		switch current {
		case "failed":
			if _, err := tx.Exec(ctx,
				`UPDATE outbox
				    SET status = 'pending',
				        attempts = 0,
				        next_attempt_at = now(),
				        worker_id = NULL,
				        lease_until = NULL
				  WHERE tenant_id = $1
				    AND id = $2
				    AND destination LIKE 'notification.%'
				    AND status = 'failed'`,
				tenantID, id); err != nil {
				return err
			}
		case "pending":
		case "processing":
			return fmt.Errorf("%w: %d", ErrNotificationAlreadyProcessing, id)
		default:
			return fmt.Errorf("%w: %d status %s", ErrNotificationNotDead, id, current)
		}
		r, err := getNotificationOutboxTx(ctx, tx, tenantID, id)
		if err != nil {
			return err
		}
		out = r
		return nil
	})
	return out, err
}

// ApplyNotificationReadTx projects a notification.read event. Replays are
// idempotent and keep the latest read timestamp.
func (s *Store) ApplyNotificationReadTx(ctx context.Context, tx pgx.Tx, rec NotificationReadReceipt) error {
	if rec.TenantID == "" || rec.OutboxID <= 0 {
		return fmt.Errorf("store: notification read receipt requires tenant and outbox id")
	}
	if rec.ReadAt.IsZero() {
		rec.ReadAt = time.Now().UTC()
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO notification_reads (tenant_id, outbox_id, read_at)
		      VALUES ($1, $2, $3)
		 ON CONFLICT (tenant_id, outbox_id) DO UPDATE
		      SET read_at = GREATEST(notification_reads.read_at, EXCLUDED.read_at)`,
		rec.TenantID, rec.OutboxID, rec.ReadAt.UTC())
	return err
}

func getNotificationOutboxTx(ctx context.Context, tx pgx.Tx, tenantID string, id int64) (NotificationOutboxRecord, error) {
	row := tx.QueryRow(ctx, notificationOutboxSelectSQL(`
		  WHERE o.tenant_id = $1
		    AND o.id = $2
		    AND o.destination LIKE 'notification.%'`),
		tenantID, id)
	return scanNotificationOutbox(row)
}

type notificationOutboxScanner interface {
	Scan(dest ...any) error
}

func scanNotificationOutbox(row notificationOutboxScanner) (NotificationOutboxRecord, error) {
	var r NotificationOutboxRecord
	err := row.Scan(&r.ID, &r.TenantID, &r.Destination, &r.Payload, &r.IdempotencyKey,
		&r.Status, &r.OutboxStatus, &r.Attempts, &r.LastError, &r.CreatedAt, &r.DeliveredAt, &r.ReadAt)
	return r, err
}

func notificationOutboxSelectSQL(where string) string {
	return `SELECT o.id,
	              o.tenant_id::text,
	              o.destination,
	              o.payload,
	              o.idempotency_key,
	              ` + notificationStatusExpr() + ` AS notification_status,
	              o.status,
	              o.attempts,
	              COALESCE(o.last_error, ''),
	              o.created_at,
	              o.delivered_at,
	              nr.read_at
	         FROM outbox o
	    LEFT JOIN notification_reads nr
	           ON nr.tenant_id = o.tenant_id
	          AND nr.outbox_id = o.id` + where
}

func notificationStatusExpr() string {
	return `CASE
	           WHEN nr.read_at IS NOT NULL THEN 'read'
	           WHEN o.status = 'failed' THEN 'dead'
	           WHEN o.status = 'delivered' THEN 'sent'
	           WHEN o.status = 'processing' THEN 'pending'
	           ELSE o.status
	       END`
}

func normalizeNotificationInboxStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "pending", "sent", "dead", "read":
		return strings.ToLower(strings.TrimSpace(status))
	default:
		return ""
	}
}
