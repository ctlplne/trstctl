package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// NotificationChannel is the tenant-scoped read model for notification channel
// configuration. It stores only endpoint metadata and credential references,
// never credential values.
type NotificationChannel struct {
	TenantID      string
	ID            string
	ChannelType   string
	Label         string
	EndpointURL   string
	CredentialRef string
	Enabled       bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// ListNotificationChannels returns one tenant's authored notification channels.
// The tenant_id predicate is intentionally in SQL and RLS enforces isolation.
func (s *Store) ListNotificationChannels(ctx context.Context, tenantID string) ([]NotificationChannel, error) {
	var out []NotificationChannel
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, id, channel_type, label, endpoint_url, credential_ref, enabled, created_at, updated_at
			   FROM notification_channels
			  WHERE tenant_id = $1
			  ORDER BY label, id`,
			tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var ch NotificationChannel
			if err := scanNotificationChannel(rows, &ch); err != nil {
				return err
			}
			out = append(out, ch)
		}
		return rows.Err()
	})
	return out, err
}

// GetNotificationChannel loads one tenant-scoped notification channel.
func (s *Store) GetNotificationChannel(ctx context.Context, tenantID, id string) (NotificationChannel, error) {
	var out NotificationChannel
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanNotificationChannel(tx.QueryRow(ctx,
			`SELECT tenant_id::text, id, channel_type, label, endpoint_url, credential_ref, enabled, created_at, updated_at
			   FROM notification_channels
			  WHERE tenant_id = $1 AND id = $2`,
			tenantID, id), &out)
	})
	return out, err
}

// ApplyNotificationChannelUpsertedTx projects a notification.channel.upserted
// event. Replays are idempotent.
func (s *Store) ApplyNotificationChannelUpsertedTx(ctx context.Context, tx pgx.Tx, ch NotificationChannel) error {
	if ch.TenantID == "" || ch.ID == "" || ch.ChannelType == "" || ch.Label == "" {
		return errors.New("store: notification channel requires tenant, id, type, and label")
	}
	if ch.CreatedAt.IsZero() {
		ch.CreatedAt = time.Now().UTC()
	}
	if ch.UpdatedAt.IsZero() {
		ch.UpdatedAt = ch.CreatedAt
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO notification_channels (
		     tenant_id, id, channel_type, label, endpoint_url, credential_ref, enabled, created_at, updated_at
		 )
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (tenant_id, id) DO UPDATE
		      SET channel_type = EXCLUDED.channel_type,
		          label = EXCLUDED.label,
		          endpoint_url = EXCLUDED.endpoint_url,
		          credential_ref = EXCLUDED.credential_ref,
		          enabled = EXCLUDED.enabled,
		          updated_at = EXCLUDED.updated_at`,
		ch.TenantID, ch.ID, ch.ChannelType, ch.Label, ch.EndpointURL, ch.CredentialRef, ch.Enabled, ch.CreatedAt.UTC(), ch.UpdatedAt.UTC())
	return err
}

// DeleteNotificationChannelTx projects a notification.channel.deleted event.
// Deleting an already-missing channel is replay-safe.
func (s *Store) DeleteNotificationChannelTx(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	if tenantID == "" || id == "" {
		return errors.New("store: notification channel delete requires tenant and id")
	}
	_, err := tx.Exec(ctx,
		`DELETE FROM notification_channels
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, id)
	return err
}

func scanNotificationChannel(row rowScanner, ch *NotificationChannel) error {
	return row.Scan(
		&ch.TenantID,
		&ch.ID,
		&ch.ChannelType,
		&ch.Label,
		&ch.EndpointURL,
		&ch.CredentialRef,
		&ch.Enabled,
		&ch.CreatedAt,
		&ch.UpdatedAt,
	)
}
