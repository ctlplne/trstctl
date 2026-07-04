// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// NotificationRoutingPolicy is the tenant-scoped read model for notification
// channel routing. It stores only channel names, never channel credentials.
type NotificationRoutingPolicy struct {
	ID                 string
	TenantID           string
	Name               string
	ChannelsBySeverity map[string][]string
	DefaultChannels    []string
	OwnerRef           string
	OwnerEmail         string
	DigestInterval     int
	DigestTimezone     string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// ListNotificationRoutingPolicies returns one tenant's routing policies ordered
// by operator-facing name. The tenant predicate is in SQL and RLS enforces it.
func (s *Store) ListNotificationRoutingPolicies(ctx context.Context, tenantID string) ([]NotificationRoutingPolicy, error) {
	var out []NotificationRoutingPolicy
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, name, channels_by_severity, default_channels,
			        owner_ref, owner_email, digest_interval_seconds, digest_timezone, created_at, updated_at
			   FROM notification_routing_policies
			  WHERE tenant_id = $1
			  ORDER BY name, id`,
			tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p NotificationRoutingPolicy
			if err := scanNotificationRoutingPolicy(rows, &p); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

// GetNotificationRoutingPolicy loads one tenant-scoped notification routing
// policy. The tenant_id predicate is intentionally in SQL and RLS enforces it.
func (s *Store) GetNotificationRoutingPolicy(ctx context.Context, tenantID, id string) (NotificationRoutingPolicy, error) {
	var out NotificationRoutingPolicy
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanNotificationRoutingPolicy(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, name, channels_by_severity, default_channels,
			        owner_ref, owner_email, digest_interval_seconds, digest_timezone, created_at, updated_at
			   FROM notification_routing_policies
			  WHERE tenant_id = $1 AND id = $2`,
			tenantID, id), &out)
	})
	return out, err
}

// ApplyNotificationRoutingPolicyUpsertedTx projects a
// notification.routing_policy.upserted event. Replays are idempotent.
func (s *Store) ApplyNotificationRoutingPolicyUpsertedTx(ctx context.Context, tx pgx.Tx, p NotificationRoutingPolicy) error {
	if p.TenantID == "" || p.ID == "" || p.Name == "" {
		return errors.New("store: notification routing policy requires tenant, id, and name")
	}
	matrix, err := json.Marshal(p.ChannelsBySeverity)
	if err != nil {
		return err
	}
	defaults, err := json.Marshal(p.DefaultChannels)
	if err != nil {
		return err
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = p.CreatedAt
	}
	if p.DigestInterval <= 0 {
		p.DigestInterval = 86400
	}
	if p.DigestTimezone == "" {
		p.DigestTimezone = "UTC"
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO notification_routing_policies (
		     id, tenant_id, name, channels_by_severity, default_channels,
		     owner_ref, owner_email, digest_interval_seconds, digest_timezone, created_at, updated_at
		 )
		 VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7, $8, $9, $10, $11)
		 ON CONFLICT (tenant_id, id) DO UPDATE
		      SET name = EXCLUDED.name,
		          channels_by_severity = EXCLUDED.channels_by_severity,
		          default_channels = EXCLUDED.default_channels,
		          owner_ref = EXCLUDED.owner_ref,
		          owner_email = EXCLUDED.owner_email,
		          digest_interval_seconds = EXCLUDED.digest_interval_seconds,
		          digest_timezone = EXCLUDED.digest_timezone,
		          updated_at = EXCLUDED.updated_at`,
		p.ID, p.TenantID, p.Name, matrix, defaults,
		p.OwnerRef, p.OwnerEmail, p.DigestInterval, p.DigestTimezone, p.CreatedAt.UTC(), p.UpdatedAt.UTC())
	return err
}

// DeleteNotificationRoutingPolicyTx projects a notification.routing_policy.deleted
// event. Deleting an already-missing policy is replay-safe.
func (s *Store) DeleteNotificationRoutingPolicyTx(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	if tenantID == "" || id == "" {
		return errors.New("store: notification routing policy delete requires tenant and id")
	}
	_, err := tx.Exec(ctx,
		`DELETE FROM notification_routing_policies
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, id)
	return err
}

func scanNotificationRoutingPolicy(row rowScanner, p *NotificationRoutingPolicy) error {
	var matrix []byte
	var defaults []byte
	if err := row.Scan(
		&p.ID, &p.TenantID, &p.Name, &matrix, &defaults,
		&p.OwnerRef, &p.OwnerEmail, &p.DigestInterval, &p.DigestTimezone,
		&p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		return err
	}
	if len(matrix) > 0 {
		if err := json.Unmarshal(matrix, &p.ChannelsBySeverity); err != nil {
			return err
		}
	}
	if len(defaults) > 0 {
		if err := json.Unmarshal(defaults, &p.DefaultChannels); err != nil {
			return err
		}
	}
	return nil
}
