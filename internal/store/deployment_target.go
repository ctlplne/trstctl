// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// DeploymentTarget is a place credentials get deployed (a connector target),
// such as a Kubernetes cluster, a file path, a load balancer, or an SSH host.
type DeploymentTarget struct {
	ID         string
	TenantID   string
	Name       string
	Type       string          // connector name/kind, kept as "type" for the existing table.
	Config     json.RawMessage // connector configuration; non-secret
	RevisionID string
	Enabled    bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// ApplyDeploymentTargetUpsertedTx projects a deployment_target.upserted event.
// createdAt is the event timestamp; updates keep the original created_at so a
// replay preserves when the target first appeared.
func (s *Store) ApplyDeploymentTargetUpsertedTx(ctx context.Context, tx pgx.Tx, d DeploymentTarget, revisionID string, createdAt time.Time) error {
	if revisionID == "" {
		return fmt.Errorf("store: deployment target revision id is required")
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO deployment_target_revisions
		        (tenant_id, target_id, revision_id, name, type, config, enabled, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6::jsonb, true, $7)
		 ON CONFLICT (tenant_id, target_id, revision_id) DO NOTHING`,
		d.TenantID, d.ID, revisionID, d.Name, d.Type, jsonbOrEmpty(d.Config), createdAt); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO deployment_targets
		        (id, tenant_id, name, type, config, revision_id, enabled, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5::jsonb, $6, true, $7, $7)
		 ON CONFLICT (id) DO UPDATE
		    SET name = EXCLUDED.name, type = EXCLUDED.type, config = EXCLUDED.config,
		        revision_id = EXCLUDED.revision_id, enabled = true, updated_at = EXCLUDED.updated_at
		  WHERE deployment_targets.tenant_id = EXCLUDED.tenant_id`,
		d.ID, d.TenantID, d.Name, d.Type, jsonbOrEmpty(d.Config), revisionID, createdAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("store: deployment target id is already owned by another tenant")
	}
	return nil
}

// ApplyDeploymentTargetDeletedTx projects deployment_target.deleted.
func (s *Store) ApplyDeploymentTargetDeletedTx(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	_, err := tx.Exec(ctx, `DELETE FROM deployment_targets WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	return err
}

// UpsertDeploymentTarget inserts or updates a target in its tenant context.
func (s *Store) UpsertDeploymentTarget(ctx context.Context, d DeploymentTarget) error {
	revisionID := "direct:" + uuid.NewString()
	createdAt := time.Now().UTC()
	return s.WithTenant(ctx, d.TenantID, func(tx pgx.Tx) error {
		return s.ApplyDeploymentTargetUpsertedTx(ctx, tx, d, revisionID, createdAt)
	})
}

// DeleteDeploymentTarget deletes a target in its tenant context.
func (s *Store) DeleteDeploymentTarget(ctx context.Context, tenantID, id string) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM deployment_targets WHERE tenant_id = $1 AND id = $2`, tenantID, id)
		return err
	})
}

// GetDeploymentTarget loads a target in its tenant context.
func (s *Store) GetDeploymentTarget(ctx context.Context, tenantID, id string) (DeploymentTarget, error) {
	var (
		d   DeploymentTarget
		cfg []byte
	)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, name, type, config, revision_id, enabled, created_at, updated_at
			   FROM deployment_targets WHERE tenant_id = $1 AND id = $2`, tenantID, id).
			Scan(&d.ID, &d.TenantID, &d.Name, &d.Type, &cfg, &d.RevisionID, &d.Enabled, &d.CreatedAt, &d.UpdatedAt)
	})
	d.Config = cfg
	return d, err
}

// ListDeploymentTargets returns all targets for a tenant.
func (s *Store) ListDeploymentTargets(ctx context.Context, tenantID string) ([]DeploymentTarget, error) {
	var out []DeploymentTarget
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, name, type, config, revision_id, enabled, created_at, updated_at
			   FROM deployment_targets WHERE tenant_id = $1 ORDER BY created_at, id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				d   DeploymentTarget
				cfg []byte
			)
			if err := rows.Scan(&d.ID, &d.TenantID, &d.Name, &d.Type, &cfg, &d.RevisionID, &d.Enabled, &d.CreatedAt, &d.UpdatedAt); err != nil {
				return err
			}
			d.Config = cfg
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}

// GetDeploymentTargetRevision loads immutable target metadata by the event ID
// pinned into an outbox intent. Ordinary edits can therefore never redirect a
// retry to a different endpoint or credential reference.
func (s *Store) GetDeploymentTargetRevision(ctx context.Context, tenantID, targetID, revisionID string) (DeploymentTarget, error) {
	var (
		d   DeploymentTarget
		cfg []byte
	)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT target_id::text, tenant_id::text, name, type, config, revision_id, enabled, created_at
			   FROM deployment_target_revisions
			  WHERE tenant_id = $1 AND target_id = $2 AND revision_id = $3`,
			tenantID, targetID, revisionID).
			Scan(&d.ID, &d.TenantID, &d.Name, &d.Type, &cfg, &d.RevisionID, &d.Enabled, &d.CreatedAt)
	})
	d.Config = cfg
	d.UpdatedAt = d.CreatedAt
	return d, err
}
