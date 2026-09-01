// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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
	// EnabledSet distinguishes an explicit disabled target from legacy callers
	// that predate execution readiness. Omitted legacy state defaults to enabled;
	// new API and event paths always set this marker explicitly.
	EnabledSet bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func deploymentTargetEnabled(d DeploymentTarget) bool {
	if !d.EnabledSet {
		return true
	}
	return d.Enabled
}

// ApplyDeploymentTargetUpsertedTx projects a deployment_target.upserted event.
// createdAt is the event timestamp; updates keep the original created_at so a
// replay preserves when the target first appeared.
func (s *Store) ApplyDeploymentTargetUpsertedTx(ctx context.Context, tx pgx.Tx, d DeploymentTarget, revisionID string, createdAt time.Time) error {
	if revisionID == "" {
		return fmt.Errorf("store: deployment target revision id is required")
	}
	enabled := deploymentTargetEnabled(d)
	if _, err := tx.Exec(ctx,
		`INSERT INTO deployment_target_revisions
		        (tenant_id, target_id, revision_id, name, type, config, enabled, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)
		 ON CONFLICT (tenant_id, target_id, revision_id) DO NOTHING`,
		d.TenantID, d.ID, revisionID, d.Name, d.Type, jsonbOrEmpty(d.Config), enabled, createdAt); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO deployment_targets
		        (id, tenant_id, name, type, config, revision_id, enabled, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $8)
		 ON CONFLICT (id) DO UPDATE
		    SET name = EXCLUDED.name, type = EXCLUDED.type, config = EXCLUDED.config,
		        revision_id = EXCLUDED.revision_id, enabled = EXCLUDED.enabled, updated_at = EXCLUDED.updated_at
		  WHERE deployment_targets.tenant_id = EXCLUDED.tenant_id`,
		d.ID, d.TenantID, d.Name, d.Type, jsonbOrEmpty(d.Config), revisionID, enabled, createdAt)
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
	d.EnabledSet = err == nil
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
			d.EnabledSet = true
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
	d.EnabledSet = err == nil
	d.UpdatedAt = d.CreatedAt
	return d, err
}

// PredecessorCertificate is the certificate the current one replaced.
type PredecessorCertificate struct {
	Serial      string
	Fingerprint string
}

// ResolvePredecessorCertificate walks an identity's replacement chain to the
// certificate the current one replaced.
//
// Lives here rather than in one caller because two callers need it and for
// opposite reasons: the API resolves it when an OPERATOR asks for a rollback,
// and the agent channel resolves it when VERIFICATION decides one is warranted
// (D2). Two copies of a chain walk would drift, and the one that drifts is the
// automatic path — the one nobody watches.
//
// An empty value rather than an error when there is no predecessor: "this is
// the first credential on this target" is an ordinary state, and a 500 for a
// target that has simply never been renewed would be wrong.
func (s *Store) ResolvePredecessorCertificate(ctx context.Context, tenantID, identityID string) PredecessorCertificate {
	if strings.TrimSpace(identityID) == "" {
		return PredecessorCertificate{}
	}
	identity, err := s.GetIdentity(ctx, tenantID, identityID)
	if err != nil {
		return PredecessorCertificate{}
	}
	certs, err := s.ListActiveIssuedCertificatesForIdentity(ctx, tenantID, identity.OwnerID, identity.Name)
	if err != nil || len(certs) == 0 {
		return PredecessorCertificate{}
	}
	current := certs[len(certs)-1]
	if current.ReplacesID == nil || strings.TrimSpace(*current.ReplacesID) == "" {
		return PredecessorCertificate{}
	}
	previous, err := s.GetCertificate(ctx, tenantID, *current.ReplacesID)
	if err != nil {
		return PredecessorCertificate{}
	}
	return PredecessorCertificate{Serial: previous.Serial, Fingerprint: previous.Fingerprint}
}

// ResolvePredecessorCertificateForFingerprint follows the replacement edge
// from the exact certificate a deploy attempted. The automatic wrong-SAN path
// must use this form: a malformed successor whose SAN omits the identity name
// is intentionally absent from ListActiveIssuedCertificatesForIdentity, and
// that is precisely the certificate whose predecessor must be recoverable.
func (s *Store) ResolvePredecessorCertificateForFingerprint(ctx context.Context, tenantID, currentFingerprint string) PredecessorCertificate {
	currentFingerprint = strings.TrimSpace(currentFingerprint)
	if currentFingerprint == "" {
		return PredecessorCertificate{}
	}
	current, err := s.GetCertificateByFingerprint(ctx, tenantID, currentFingerprint)
	if err != nil || current.ReplacesID == nil || strings.TrimSpace(*current.ReplacesID) == "" {
		return PredecessorCertificate{}
	}
	previous, err := s.GetCertificate(ctx, tenantID, *current.ReplacesID)
	if err != nil {
		return PredecessorCertificate{}
	}
	return PredecessorCertificate{Serial: previous.Serial, Fingerprint: previous.Fingerprint}
}
