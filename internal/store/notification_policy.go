// SPDX-License-Identifier: BUSL-1.1

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
	ScopeKind          string
	ScopeRef           string
	ChannelsBySeverity map[string][]string
	DefaultChannels    []string
	OwnerRef           string
	OwnerEmail         string
	DigestInterval     int
	DigestTimezone     string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// NotificationRoutingSelector describes one alert's position in the routing
// hierarchy. Empty values mean that level is not known for this alert.
type NotificationRoutingSelector struct {
	Workspace string
	OwnerRef  string
	AssetRef  string
}

// ListNotificationRoutingPolicies returns one tenant's routing policies ordered
// by operator-facing name. The tenant predicate is in SQL and RLS enforces it.
func (s *Store) ListNotificationRoutingPolicies(ctx context.Context, tenantID string) ([]NotificationRoutingPolicy, error) {
	var out []NotificationRoutingPolicy
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, name, scope_kind, scope_ref, channels_by_severity, default_channels,
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
			`SELECT id::text, tenant_id::text, name, scope_kind, scope_ref, channels_by_severity, default_channels,
			        owner_ref, owner_email, digest_interval_seconds, digest_timezone, created_at, updated_at
			   FROM notification_routing_policies
			  WHERE tenant_id = $1 AND id = $2`,
			tenantID, id), &out)
	})
	return out, err
}

// ResolveEffectiveNotificationRoutingPolicy resolves one tenant's most-specific
// applicable rule: asset, then owner, then workspace, then global. Manual rules
// are never selected implicitly.
func (s *Store) ResolveEffectiveNotificationRoutingPolicy(ctx context.Context, tenantID string, selector NotificationRoutingSelector) (NotificationRoutingPolicy, bool, error) {
	var out NotificationRoutingPolicy
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, name, scope_kind, scope_ref, channels_by_severity, default_channels,
			        owner_ref, owner_email, digest_interval_seconds, digest_timezone, created_at, updated_at
			   FROM notification_routing_policies
			  WHERE tenant_id = $1
			    AND ((scope_kind = 'asset' AND scope_ref = $2)
			      OR (scope_kind = 'owner' AND scope_ref = $3)
			      OR (scope_kind = 'workspace' AND scope_ref = $4)
			      OR (scope_kind = 'global' AND scope_ref = ''))
			  ORDER BY CASE scope_kind
			             WHEN 'asset' THEN 1 WHEN 'owner' THEN 2
			             WHEN 'workspace' THEN 3 ELSE 4 END
			  LIMIT 1`,
			tenantID, selector.AssetRef, selector.OwnerRef, selector.Workspace)
		if err := scanNotificationRoutingPolicy(row, &out); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		found = true
		return nil
	})
	return out, found, err
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
	if p.ScopeKind == "" {
		p.ScopeKind = "manual"
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO notification_routing_policies (
		     id, tenant_id, name, scope_kind, scope_ref, channels_by_severity, default_channels,
		     owner_ref, owner_email, digest_interval_seconds, digest_timezone, created_at, updated_at
		 )
		 VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, $9, $10, $11, $12, $13)
		 ON CONFLICT DO NOTHING`,
		p.ID, p.TenantID, p.Name, p.ScopeKind, p.ScopeRef, matrix, defaults,
		p.OwnerRef, p.OwnerEmail, p.DigestInterval, p.DigestTimezone, p.CreatedAt.UTC(), p.UpdatedAt.UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}

	// The event stream can race the command-side projector: both may try to
	// install the same event at once. PostgreSQL is free to report either the
	// global id primary key or the tenant/id unique key first, so targeting one
	// constraint with ON CONFLICT leaves the other race unhandled. After any
	// conflict, update only the exact tenant-owned identity. A name/scope clash
	// with a different identity, or a globally colliding id owned by another
	// tenant, changes zero rows and fails closed.
	tag, err = tx.Exec(ctx,
		`UPDATE notification_routing_policies
		    SET name = $3,
		        scope_kind = $4,
		        scope_ref = $5,
		        channels_by_severity = $6::jsonb,
		        default_channels = $7::jsonb,
		        owner_ref = $8,
		        owner_email = $9,
		        digest_interval_seconds = $10,
		        digest_timezone = $11,
		        updated_at = $12
		  WHERE tenant_id = $2 AND id = $1`,
		p.ID, p.TenantID, p.Name, p.ScopeKind, p.ScopeRef, matrix, defaults,
		p.OwnerRef, p.OwnerEmail, p.DigestInterval, p.DigestTimezone, p.UpdatedAt.UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("store: notification routing policy conflict does not match the tenant-owned identity")
	}
	return nil
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
		&p.ID, &p.TenantID, &p.Name, &p.ScopeKind, &p.ScopeRef, &matrix, &defaults,
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
