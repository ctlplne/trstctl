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

// The secrets workspace (A235): projects (applications) with environments and
// members. A secret belongs to a project environment by its name,
// "<project>/<environment>/<folder…>/<key>", and stays a row of the one native
// store. A restricted environment is open only to the members granted it.

// SecretProject is one project.
type SecretProject struct {
	Slug      string
	Name      string
	OwnerID   string
	CreatedBy string
	CreatedAt time.Time
}

// SecretProjectEnvironment is one environment of a project.
type SecretProjectEnvironment struct {
	Project    string
	Slug       string
	Name       string
	Restricted bool
	Position   int
	CreatedAt  time.Time
}

// SecretProjectMember is one subject's access to a project.
type SecretProjectMember struct {
	Project      string
	Subject      string
	Role         string
	Environments []string // empty: every environment
	GrantedBy    string
	GrantedAt    time.Time
}

// Member roles.
const (
	SecretProjectRoleViewer    = "viewer"
	SecretProjectRoleDeveloper = "developer"
	SecretProjectRoleAdmin     = "admin"
)

// SecretScope is what a secret name means to the workspace, for one subject.
type SecretScope struct {
	// InProject is true when the name's first two segments are a project and
	// one of its environments.
	InProject   bool
	Project     string
	Environment string
	Restricted  bool
	// Member, CanRead and CanWrite describe the subject's membership.
	Member   bool
	CanRead  bool
	CanWrite bool
}

func secretProjectSequence(sequence uint64) (int64, error) {
	if sequence == 0 || sequence > uint64(1<<63-1) {
		return 0, errors.New("store: a secret project event needs a positive int64 sequence")
	}
	return int64(sequence), nil // #nosec G115 -- bounded to int64 above (CWE-190)
}

// ApplySecretProjectCreatedTx projects a project and its first environments.
func (s *Store) ApplySecretProjectCreatedTx(ctx context.Context, tx pgx.Tx, tenantID string, p SecretProject, envs []SecretProjectEnvironment, sequence uint64) error {
	seq, err := secretProjectSequence(sequence)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO secret_projects (tenant_id, slug, name, owner_id, created_by, created_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, slug) DO NOTHING`,
		tenantID, p.Slug, p.Name, p.OwnerID, p.CreatedBy, p.CreatedAt.UTC(), seq); err != nil {
		return err
	}
	for _, env := range envs {
		env.Project = p.Slug
		if env.CreatedAt.IsZero() {
			env.CreatedAt = p.CreatedAt
		}
		if err := s.ApplySecretProjectEnvironmentTx(ctx, tx, tenantID, env, sequence); err != nil {
			return err
		}
	}
	return nil
}

// ApplySecretProjectEnvironmentTx projects one environment.
func (s *Store) ApplySecretProjectEnvironmentTx(ctx context.Context, tx pgx.Tx, tenantID string, env SecretProjectEnvironment, sequence uint64) error {
	seq, err := secretProjectSequence(sequence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO secret_project_environments (tenant_id, project, slug, name, restricted, position, created_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, project, slug) DO NOTHING`,
		tenantID, env.Project, env.Slug, env.Name, env.Restricted, env.Position, env.CreatedAt.UTC(), seq)
	return err
}

// ApplySecretProjectMemberGrantedTx projects a grant; a later grant replaces it.
func (s *Store) ApplySecretProjectMemberGrantedTx(ctx context.Context, tx pgx.Tx, tenantID string, m SecretProjectMember, sequence uint64) error {
	seq, err := secretProjectSequence(sequence)
	if err != nil {
		return err
	}
	envs := m.Environments
	if envs == nil {
		envs = []string{}
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO secret_project_members (tenant_id, project, subject, role, environments, granted_by, granted_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, project, subject) DO UPDATE
		   SET role = EXCLUDED.role, environments = EXCLUDED.environments, granted_by = EXCLUDED.granted_by,
		       granted_at = EXCLUDED.granted_at, event_sequence = EXCLUDED.event_sequence
		 WHERE secret_project_members.event_sequence < EXCLUDED.event_sequence`,
		tenantID, m.Project, m.Subject, m.Role, envs, m.GrantedBy, m.GrantedAt.UTC(), seq)
	return err
}

// ApplySecretProjectMemberRevokedTx projects a revocation.
func (s *Store) ApplySecretProjectMemberRevokedTx(ctx context.Context, tx pgx.Tx, tenantID, project, subject string, sequence uint64) error {
	seq, err := secretProjectSequence(sequence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		DELETE FROM secret_project_members
		 WHERE tenant_id = $1 AND project = $2 AND subject = $3 AND event_sequence < $4`,
		tenantID, project, subject, seq)
	return err
}

// ErrSecretProjectNotFound means no such project in the tenant.
var ErrSecretProjectNotFound = errors.New("store: no such secret project")

// GetSecretProject returns a project with its environments and members.
func (s *Store) GetSecretProject(ctx context.Context, tenantID, slug string) (SecretProject, []SecretProjectEnvironment, []SecretProjectMember, error) {
	var (
		p       SecretProject
		envs    []SecretProjectEnvironment
		members []SecretProjectMember
	)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT slug, name, owner_id, created_by, created_at FROM secret_projects WHERE tenant_id = $1 AND slug = $2`,
			tenantID, slug).Scan(&p.Slug, &p.Name, &p.OwnerID, &p.CreatedBy, &p.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSecretProjectNotFound
		}
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT project, slug, name, restricted, position, created_at FROM secret_project_environments
			WHERE tenant_id = $1 AND project = $2 ORDER BY position, slug`, tenantID, slug)
		if err != nil {
			return err
		}
		for rows.Next() {
			var e SecretProjectEnvironment
			if err := rows.Scan(&e.Project, &e.Slug, &e.Name, &e.Restricted, &e.Position, &e.CreatedAt); err != nil {
				rows.Close()
				return err
			}
			envs = append(envs, e)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT project, subject, role, environments, granted_by, granted_at FROM secret_project_members
			WHERE tenant_id = $1 AND project = $2 ORDER BY subject`, tenantID, slug)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m SecretProjectMember
			if err := rows.Scan(&m.Project, &m.Subject, &m.Role, &m.Environments, &m.GrantedBy, &m.GrantedAt); err != nil {
				return err
			}
			members = append(members, m)
		}
		return rows.Err()
	})
	return p, envs, members, err
}

// ListSecretProjects returns the tenant's projects.
func (s *Store) ListSecretProjects(ctx context.Context, tenantID string, limit int) ([]SecretProject, error) {
	if limit <= 0 || limit > 500 {
		return nil, fmt.Errorf("store: ListSecretProjects limit must be 1-500")
	}
	var out []SecretProject
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT slug, name, owner_id, created_by, created_at FROM secret_projects
			WHERE tenant_id = $1 ORDER BY slug LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p SecretProject
			if err := rows.Scan(&p.Slug, &p.Name, &p.OwnerID, &p.CreatedBy, &p.CreatedAt); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

// SecretScopeFor says what a secret name means to subject: whether its first two
// segments are a project and one of its environments, whether that environment
// is restricted, and what the subject's membership allows there.
func (s *Store) SecretScopeFor(ctx context.Context, tenantID, name, subject string) (SecretScope, error) {
	parts := strings.SplitN(name, "/", 3)
	if len(parts) < 3 || parts[0] == "" || parts[1] == "" {
		return SecretScope{}, nil
	}
	scope := SecretScope{Project: parts[0], Environment: parts[1]}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var role *string
		var envs []string
		err := tx.QueryRow(ctx, `
			SELECT e.restricted, m.role, coalesce(m.environments, '{}')
			  FROM secret_project_environments e
			  LEFT JOIN secret_project_members m
			    ON m.tenant_id = e.tenant_id AND m.project = e.project AND m.subject = $4
			 WHERE e.tenant_id = $1 AND e.project = $2 AND e.slug = $3`,
			tenantID, scope.Project, scope.Environment, subject).Scan(&scope.Restricted, &role, &envs)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		scope.InProject = true
		if role == nil {
			return nil
		}
		granted := len(envs) == 0
		for _, e := range envs {
			granted = granted || e == scope.Environment
		}
		if granted {
			scope.Member = true
			scope.CanRead = true
			scope.CanWrite = *role == SecretProjectRoleDeveloper || *role == SecretProjectRoleAdmin
		}
		return nil
	})
	return scope, err
}

// RestrictedSecretPrefixes lists "<project>/<environment>/" for every restricted
// environment subject is not granted, so a listing can leave those names out.
func (s *Store) RestrictedSecretPrefixes(ctx context.Context, tenantID, subject string) ([]string, error) {
	var out []string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT e.project || '/' || e.slug || '/'
			  FROM secret_project_environments e
			  LEFT JOIN secret_project_members m
			    ON m.tenant_id = e.tenant_id AND m.project = e.project AND m.subject = $2
			 WHERE e.tenant_id = $1 AND e.restricted
			   AND (m.subject IS NULL OR (cardinality(m.environments) > 0 AND NOT e.slug = ANY(m.environments)))
			 ORDER BY 1`, tenantID, subject)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var prefix string
			if err := rows.Scan(&prefix); err != nil {
				return err
			}
			out = append(out, prefix)
		}
		return rows.Err()
	})
	return out, err
}

// ListSecretNamesUnder returns the names (no values) under one of prefixes
// and not under any of hidden, ordered by name. With no prefixes it lists the
// whole tenant. Prefixes are workspace paths ("<project>/<environment>/"), whose
// slugs hold no LIKE wildcards.
func (s *Store) ListSecretNamesUnder(ctx context.Context, tenantID string, prefixes, hidden []string, limit int) ([]Secret, error) {
	like := func(in []string) []string {
		out := make([]string, 0, len(in))
		for _, p := range in {
			out = append(out, strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(p)+"%")
		}
		return out
	}
	include, exclude := like(prefixes), like(hidden)
	var out []Secret
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, name, coalesce(owner_id::text, ''), version, created_at, updated_at
			   FROM secret_store
			  WHERE tenant_id = $1
			    AND (cardinality($2::text[]) = 0 OR name LIKE ANY($2::text[]))
			    AND NOT (name LIKE ANY($3::text[]))
			  ORDER BY name
			  LIMIT $4`,
			tenantID, include, exclude, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m Secret
			if err := rows.Scan(&m.ID, &m.TenantID, &m.Name, &m.OwnerID, &m.Version, &m.CreatedAt, &m.UpdatedAt); err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

// OwnerInventoryItem is one certificate or identity an owner holds.
type OwnerInventoryItem struct {
	ID       string
	Kind     string
	Name     string
	Status   string
	NotAfter *time.Time
}

// OwnerInventory is what an owner holds besides secrets (A235's application
// view): how many certificates and identities, and the soonest-expiring few.
type OwnerInventory struct {
	Certificates       int
	Identities         int
	SoonestCertificate []OwnerInventoryItem
	SoonestIdentities  []OwnerInventoryItem
}

// OwnerApplicationInventory returns the certificates and identities owned by
// ownerID, counted, with up to limit of each, soonest-expiring first.
func (s *Store) OwnerApplicationInventory(ctx context.Context, tenantID, ownerID string, limit int) (OwnerInventory, error) {
	var inv OwnerInventory
	if ownerID == "" || limit <= 0 {
		return inv, nil
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT
			  (SELECT count(*) FROM certificates WHERE tenant_id = $1 AND owner_id::text = $2),
			  (SELECT count(*) FROM identities WHERE tenant_id = $1 AND owner_id::text = $2)`,
			tenantID, ownerID).Scan(&inv.Certificates, &inv.Identities); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id::text, 'certificate', subject, '', not_after FROM certificates
			WHERE tenant_id = $1 AND owner_id::text = $2 ORDER BY not_after NULLS LAST, id LIMIT $3`, tenantID, ownerID, limit)
		if err != nil {
			return err
		}
		inv.SoonestCertificate, err = scanOwnerInventory(rows)
		if err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT id::text, kind, name, status, not_after FROM identities
			WHERE tenant_id = $1 AND owner_id::text = $2 ORDER BY not_after NULLS LAST, id LIMIT $3`, tenantID, ownerID, limit)
		if err != nil {
			return err
		}
		inv.SoonestIdentities, err = scanOwnerInventory(rows)
		return err
	})
	return inv, err
}

func scanOwnerInventory(rows pgx.Rows) ([]OwnerInventoryItem, error) {
	defer rows.Close()
	var out []OwnerInventoryItem
	for rows.Next() {
		var item OwnerInventoryItem
		if err := rows.Scan(&item.ID, &item.Kind, &item.Name, &item.Status, &item.NotAfter); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
