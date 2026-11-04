// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Agent access bundles (A251): bundles, their grants to users and machines,
// and the runs minted under the grants — the projections of the
// access.bundle.* events. A run's authority is never stored as granted: it
// is derived from the live grants each time it is read. Every applied event
// also leaves one metadata row in access_bundle_activity.

// ErrAccessBundleNotFound is a bundle, grant or run this tenant does not have
// (a deleted bundle reads as not found).
var ErrAccessBundleNotFound = errors.New("store: access bundle not found")

// AccessBundle is one bundle at its latest revision.
type AccessBundle struct {
	ID               string
	Name             string
	Description      string
	Permissions      []string
	Audiences        []string
	MaxRunTTLSeconds int
	Revision         int64
	CreatedBy        string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	DeletedAt        *time.Time
	DeletedBy        string
}

// AccessBundleGrant gives a bundle to a user or a machine, optionally until a
// time.
type AccessBundleGrant struct {
	ID            string
	BundleID      string
	PrincipalType string
	Principal     string
	ExpiresAt     *time.Time
	GrantedBy     string
	GrantedAt     time.Time
	RemovedAt     *time.Time
	RemovedBy     string
	RemovedReason string
}

// AccessBundleRun is one run's credential: an API token (same ID) minted
// under some of a principal's grants.
type AccessBundleRun struct {
	ID          string
	Principal   string
	BundleIDs   []string
	GrantIDs    []string
	Permissions []string
	Label       string
	ExpiresAt   time.Time
	IssuedBy    string
	IssuedAt    time.Time
	RevokedAt   *time.Time
	RevokedBy   string
}

// AuthoritySource is one live grant that gives a permission.
type AuthoritySource struct {
	GrantID    string
	BundleID   string
	BundleName string
	ExpiresAt  *time.Time
}

// AccessBundleActivity is one recorded change (a bundle saved or deleted, a
// grant given or removed, a run issued or revoked) or, for action run_used, a
// run token's recorded use from one network in one hour. Metadata only: no
// credential and no request body is ever recorded.
type AccessBundleActivity struct {
	Sequence    int64
	At          time.Time
	Action      string
	BundleIDs   []string
	BundleNames []string
	GrantID     string
	RunID       string
	Principal   string
	Actor       string
	Detail      string
}

// AccessBundleActivityFilter narrows ListAccessBundleActivity. Query matches
// any part of the action, bundle names, principal, actor or detail, ignoring
// case. A page ends before (BeforeAt, BeforeSequence) when BeforeAt is set.
type AccessBundleActivityFilter struct {
	BundleID       string
	Principal      string
	Query          string
	BeforeAt       *time.Time
	BeforeSequence int64
	Limit          int
}

// AccessBundleStats counts a bundle's live grants and unrevoked, unexpired runs.
type AccessBundleStats struct {
	LiveGrants int
	ActiveRuns int
}

// accessBundleLiveGrant is the predicate a grant g of bundle b must meet to give
// anything at time $3: not removed, not expired, its bundle not deleted, and a
// user grant's member still active, so offboarding someone stops their runs on
// the next request.
const accessBundleLiveGrant = `g.removed_at IS NULL AND (g.expires_at IS NULL OR g.expires_at > $3) AND b.deleted_at IS NULL
	AND (g.principal_type <> 'user' OR EXISTS (SELECT 1 FROM tenant_members m
	     WHERE m.tenant_id = g.tenant_id AND m.subject = g.principal AND m.status = 'active'))`

func accessBundleSequence(sequence uint64) (int64, error) {
	if sequence == 0 || sequence > math.MaxInt64 {
		return 0, fmt.Errorf("store: access bundle event sequence %d is out of range", sequence)
	}
	return int64(sequence), nil // #nosec G115 -- bounded above (CWE-190)
}

// insertAccessBundleActivityTx records one applied event, keyed by its event
// ID: a sequence orders rows but is not trusted to be unique for ever (a
// rebuilt stream starts again from one).
func insertAccessBundleActivityTx(ctx context.Context, tx pgx.Tx, tenantID, eventID string, seq int64, at time.Time, a AccessBundleActivity) error {
	ids, names := a.BundleIDs, a.BundleNames
	if ids == nil {
		ids = []string{}
	}
	if names == nil {
		names = []string{}
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO access_bundle_activity
		  (tenant_id, event_id, event_sequence, at, action, bundle_ids, bundle_names, grant_id, run_id, principal, actor, detail)
		VALUES ($1, $2, $3, $4, $5, $6::uuid[], $7, nullif($8, '')::uuid, nullif($9, '')::uuid, $10, $11, $12)
		ON CONFLICT (tenant_id, event_id) DO NOTHING`,
		tenantID, eventID, seq, at.UTC(), a.Action, ids, names, a.GrantID, a.RunID, a.Principal, a.Actor, a.Detail)
	return err
}

func accessBundleNamesTx(ctx context.Context, tx pgx.Tx, tenantID string, ids []string) ([]string, error) {
	var names []string
	err := tx.QueryRow(ctx, `SELECT coalesce(array_agg(name ORDER BY lower(name), id), '{}') FROM access_bundles
		WHERE tenant_id = $1 AND id = ANY($2::uuid[])`, tenantID, ids).Scan(&names)
	return names, err
}

// ApplyAccessBundleSavedTx projects a saved bundle. A later revision replaces
// an earlier one; a deleted bundle stays deleted, whatever arrives after.
func (s *Store) ApplyAccessBundleSavedTx(ctx context.Context, tx pgx.Tx, tenantID string, b AccessBundle, eventID string, sequence uint64) error {
	seq, err := accessBundleSequence(sequence)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO access_bundles
		  (tenant_id, id, name, description, permissions, audiences, max_run_ttl_seconds, revision, created_by,
		   created_at, updated_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10, $11)
		ON CONFLICT (tenant_id, id) DO UPDATE SET
		  name = EXCLUDED.name, description = EXCLUDED.description, permissions = EXCLUDED.permissions,
		  audiences = EXCLUDED.audiences, max_run_ttl_seconds = EXCLUDED.max_run_ttl_seconds,
		  revision = EXCLUDED.revision, updated_at = EXCLUDED.updated_at, event_sequence = EXCLUDED.event_sequence
		WHERE access_bundles.tenant_id = EXCLUDED.tenant_id AND access_bundles.revision < EXCLUDED.revision
		  AND access_bundles.deleted_at IS NULL`,
		tenantID, b.ID, b.Name, b.Description, b.Permissions, b.Audiences, b.MaxRunTTLSeconds, b.Revision,
		b.CreatedBy, b.CreatedAt.UTC(), seq)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	return insertAccessBundleActivityTx(ctx, tx, tenantID, eventID, seq, b.CreatedAt, AccessBundleActivity{
		Action: "saved", BundleIDs: []string{b.ID}, BundleNames: []string{b.Name}, Actor: b.CreatedBy,
		Detail: fmt.Sprintf("revision %d: %s; runs up to %d s", b.Revision, strings.Join(b.Permissions, ", "), b.MaxRunTTLSeconds),
	})
}

// ApplyAccessBundleDeletedTx marks a bundle deleted; its grants and runs stop
// giving anything at once, because authority is derived from live rows.
func (s *Store) ApplyAccessBundleDeletedTx(ctx context.Context, tx pgx.Tx, tenantID, id, by string, at time.Time, eventID string, sequence uint64) error {
	seq, err := accessBundleSequence(sequence)
	if err != nil {
		return err
	}
	var name string
	err = tx.QueryRow(ctx, `
		UPDATE access_bundles SET deleted_at = $3, deleted_by = $4, event_sequence = $5
		 WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL RETURNING name`, tenantID, id, at.UTC(), by, seq).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return insertAccessBundleActivityTx(ctx, tx, tenantID, eventID, seq, at, AccessBundleActivity{
		Action: "deleted", BundleIDs: []string{id}, BundleNames: []string{name}, Actor: by,
		Detail: "every grant and run of this bundle stops giving its permissions",
	})
}

// ApplyAccessBundleGrantedTx projects a grant.
func (s *Store) ApplyAccessBundleGrantedTx(ctx context.Context, tx pgx.Tx, tenantID string, g AccessBundleGrant, eventID string, sequence uint64) error {
	seq, err := accessBundleSequence(sequence)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO access_bundle_grants
		  (tenant_id, id, bundle_id, principal_type, principal, expires_at, granted_by, granted_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (tenant_id, id) DO NOTHING`,
		tenantID, g.ID, g.BundleID, g.PrincipalType, g.Principal, g.ExpiresAt, g.GrantedBy, g.GrantedAt.UTC(), seq)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	names, err := accessBundleNamesTx(ctx, tx, tenantID, []string{g.BundleID})
	if err != nil {
		return err
	}
	detail := g.PrincipalType + " grant"
	if g.ExpiresAt != nil {
		detail += " until " + g.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return insertAccessBundleActivityTx(ctx, tx, tenantID, eventID, seq, g.GrantedAt, AccessBundleActivity{
		Action: "granted", BundleIDs: []string{g.BundleID}, BundleNames: names, GrantID: g.ID,
		Principal: g.Principal, Actor: g.GrantedBy, Detail: detail,
	})
}

// ApplyAccessBundleUngrantedTx removes a grant. A grant is removed once.
func (s *Store) ApplyAccessBundleUngrantedTx(ctx context.Context, tx pgx.Tx, tenantID, id, by, reason string, at time.Time, eventID string, sequence uint64) error {
	seq, err := accessBundleSequence(sequence)
	if err != nil {
		return err
	}
	var bundleID, principal string
	err = tx.QueryRow(ctx, `
		UPDATE access_bundle_grants SET removed_at = $3, removed_by = $4, removed_reason = $5, event_sequence = $6
		 WHERE tenant_id = $1 AND id = $2 AND removed_at IS NULL RETURNING bundle_id::text, principal`,
		tenantID, id, at.UTC(), by, reason, seq).Scan(&bundleID, &principal)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	names, err := accessBundleNamesTx(ctx, tx, tenantID, []string{bundleID})
	if err != nil {
		return err
	}
	return insertAccessBundleActivityTx(ctx, tx, tenantID, eventID, seq, at, AccessBundleActivity{
		Action: "ungranted", BundleIDs: []string{bundleID}, BundleNames: names, GrantID: id,
		Principal: principal, Actor: by, Detail: reason,
	})
}

// ApplyAccessBundleRunIssuedTx projects a run.
func (s *Store) ApplyAccessBundleRunIssuedTx(ctx context.Context, tx pgx.Tx, tenantID string, r AccessBundleRun, eventID string, sequence uint64) error {
	seq, err := accessBundleSequence(sequence)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO access_bundle_runs
		  (tenant_id, id, principal, bundle_ids, grant_ids, permissions, label, expires_at, issued_by, issued_at, event_sequence)
		VALUES ($1, $2, $3, $4::uuid[], $5::uuid[], $6, $7, $8, $9, $10, $11)
		ON CONFLICT (tenant_id, id) DO NOTHING`,
		tenantID, r.ID, r.Principal, r.BundleIDs, r.GrantIDs, r.Permissions, r.Label, r.ExpiresAt.UTC(), r.IssuedBy,
		r.IssuedAt.UTC(), seq)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	names, err := accessBundleNamesTx(ctx, tx, tenantID, r.BundleIDs)
	if err != nil {
		return err
	}
	detail := fmt.Sprintf("%s until %s", strings.Join(r.Permissions, ", "), r.ExpiresAt.UTC().Format(time.RFC3339))
	if r.Label != "" {
		detail = r.Label + ": " + detail
	}
	return insertAccessBundleActivityTx(ctx, tx, tenantID, eventID, seq, r.IssuedAt, AccessBundleActivity{
		Action: "run_issued", BundleIDs: r.BundleIDs, BundleNames: names, RunID: r.ID,
		Principal: r.Principal, Actor: r.IssuedBy, Detail: detail,
	})
}

// ApplyAccessBundleRunRevokedTx marks a run revoked. A run is revoked once.
func (s *Store) ApplyAccessBundleRunRevokedTx(ctx context.Context, tx pgx.Tx, tenantID, id, by string, at time.Time, eventID string, sequence uint64) error {
	seq, err := accessBundleSequence(sequence)
	if err != nil {
		return err
	}
	var principal string
	var bundleIDs []string
	err = tx.QueryRow(ctx, `
		UPDATE access_bundle_runs SET revoked_at = $3, revoked_by = $4, event_sequence = $5
		 WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL RETURNING principal, bundle_ids::text[]`,
		tenantID, id, at.UTC(), by, seq).Scan(&principal, &bundleIDs)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	names, err := accessBundleNamesTx(ctx, tx, tenantID, bundleIDs)
	if err != nil {
		return err
	}
	return insertAccessBundleActivityTx(ctx, tx, tenantID, eventID, seq, at, AccessBundleActivity{
		Action: "run_revoked", BundleIDs: bundleIDs, BundleNames: names, RunID: id, Principal: principal, Actor: by,
		Detail: "the run's credential is refused from the next request",
	})
}

const accessBundleColumns = `id::text, name, description, permissions, audiences, max_run_ttl_seconds, revision,
	created_by, created_at, updated_at, deleted_at, deleted_by`

func scanAccessBundle(row pgx.Row) (AccessBundle, error) {
	var b AccessBundle
	err := row.Scan(&b.ID, &b.Name, &b.Description, &b.Permissions, &b.Audiences, &b.MaxRunTTLSeconds, &b.Revision,
		&b.CreatedBy, &b.CreatedAt, &b.UpdatedAt, &b.DeletedAt, &b.DeletedBy)
	return b, err
}

// GetAccessBundle reads one live bundle; a deleted bundle is not found.
func (s *Store) GetAccessBundle(ctx context.Context, tenantID, id string) (AccessBundle, error) {
	var b AccessBundle
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		b, err = scanAccessBundle(tx.QueryRow(ctx, `SELECT `+accessBundleColumns+` FROM access_bundles
			WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`, tenantID, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return AccessBundle{}, ErrAccessBundleNotFound
	}
	return b, err
}

// GetAccessBundleByName reads the live bundle with name, ignoring case.
func (s *Store) GetAccessBundleByName(ctx context.Context, tenantID, name string) (AccessBundle, error) {
	var b AccessBundle
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		b, err = scanAccessBundle(tx.QueryRow(ctx, `SELECT `+accessBundleColumns+` FROM access_bundles
			WHERE tenant_id = $1 AND lower(name) = lower($2) AND deleted_at IS NULL ORDER BY created_at, id LIMIT 1`, tenantID, name))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return AccessBundle{}, ErrAccessBundleNotFound
	}
	return b, err
}

// ListAccessBundles lists the live bundles by name.
func (s *Store) ListAccessBundles(ctx context.Context, tenantID string, limit int) ([]AccessBundle, error) {
	out := []AccessBundle{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+accessBundleColumns+` FROM access_bundles
			WHERE tenant_id = $1 AND deleted_at IS NULL ORDER BY lower(name), id LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			b, err := scanAccessBundle(rows)
			if err != nil {
				return err
			}
			out = append(out, b)
		}
		return rows.Err()
	})
	return out, err
}

// accessBundleStatsLimit bounds AccessBundleStatsFor; a tenant's bundle list
// is bounded the same way by the API.
const accessBundleStatsLimit = 500

// AccessBundleStatsFor counts each live bundle's live grants and active runs.
func (s *Store) AccessBundleStatsFor(ctx context.Context, tenantID string, now time.Time) (map[string]AccessBundleStats, error) {
	out := map[string]AccessBundleStats{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT b.id::text,
			       (SELECT count(*) FROM access_bundle_grants g WHERE g.tenant_id = b.tenant_id AND g.bundle_id = b.id
			          AND `+accessBundleLiveGrant+`),
			       (SELECT count(*) FROM access_bundle_runs r WHERE r.tenant_id = b.tenant_id AND b.id = ANY(r.bundle_ids)
			          AND r.revoked_at IS NULL AND r.expires_at > $3)
			  FROM access_bundles b WHERE b.tenant_id = $1 AND b.deleted_at IS NULL ORDER BY b.id LIMIT $2`,
			tenantID, accessBundleStatsLimit, now.UTC())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			var st AccessBundleStats
			if err := rows.Scan(&id, &st.LiveGrants, &st.ActiveRuns); err != nil {
				return err
			}
			out[id] = st
		}
		return rows.Err()
	})
	return out, err
}

const accessBundleGrantColumns = `id::text, bundle_id::text, principal_type, principal, expires_at, granted_by, granted_at,
	removed_at, removed_by, removed_reason`

func scanAccessBundleGrant(row pgx.Row) (AccessBundleGrant, error) {
	var g AccessBundleGrant
	err := row.Scan(&g.ID, &g.BundleID, &g.PrincipalType, &g.Principal, &g.ExpiresAt, &g.GrantedBy, &g.GrantedAt,
		&g.RemovedAt, &g.RemovedBy, &g.RemovedReason)
	return g, err
}

// GetAccessBundleGrant reads one grant, removed or not.
func (s *Store) GetAccessBundleGrant(ctx context.Context, tenantID, id string) (AccessBundleGrant, error) {
	var g AccessBundleGrant
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		g, err = scanAccessBundleGrant(tx.QueryRow(ctx, `SELECT `+accessBundleGrantColumns+` FROM access_bundle_grants
			WHERE tenant_id = $1 AND id = $2`, tenantID, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return AccessBundleGrant{}, ErrAccessBundleNotFound
	}
	return g, err
}

// ListAccessBundleGrants lists a bundle's grants (removed ones too, newest
// first), or with an empty bundleID a principal's.
func (s *Store) ListAccessBundleGrants(ctx context.Context, tenantID, bundleID, principal string, limit int) ([]AccessBundleGrant, error) {
	out := []AccessBundleGrant{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+accessBundleGrantColumns+` FROM access_bundle_grants
			WHERE tenant_id = $1 AND ($2 = '' OR bundle_id::text = $2) AND ($3 = '' OR principal = $3)
			ORDER BY granted_at DESC, id LIMIT $4`, tenantID, bundleID, principal, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			g, err := scanAccessBundleGrant(rows)
			if err != nil {
				return err
			}
			out = append(out, g)
		}
		return rows.Err()
	})
	return out, err
}

// LiveAccessBundleGrants lists a principal's grants that give something now,
// oldest first.
func (s *Store) LiveAccessBundleGrants(ctx context.Context, tenantID, principal string, now time.Time) ([]AccessBundleGrant, error) {
	out := []AccessBundleGrant{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT g.id::text, g.bundle_id::text, g.principal_type, g.principal, g.expires_at,
			       g.granted_by, g.granted_at, g.removed_at, g.removed_by, g.removed_reason
			  FROM access_bundle_grants g
			  JOIN access_bundles b ON b.tenant_id = g.tenant_id AND b.id = g.bundle_id
			 WHERE g.tenant_id = $1 AND g.principal = $2 AND `+accessBundleLiveGrant+`
			 ORDER BY g.granted_at, g.id`, tenantID, principal, now.UTC())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			g, err := scanAccessBundleGrant(rows)
			if err != nil {
				return err
			}
			out = append(out, g)
		}
		return rows.Err()
	})
	return out, err
}

// EffectiveAuthority is what a principal holds now through its live grants
// (not removed, not expired, of a bundle not deleted): each permission with
// every grant that gives it. A permission two grants give survives the
// removal of one.
func (s *Store) EffectiveAuthority(ctx context.Context, tenantID, principal string, now time.Time) (map[string][]AuthoritySource, error) {
	var out map[string][]AuthoritySource
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = authorityTx(ctx, tx, tenantID, principal, nil, now)
		return err
	})
	return out, err
}

// authorityTx is EffectiveAuthority limited, when onlyGrants is not nil, to
// those grants.
func authorityTx(ctx context.Context, tx pgx.Tx, tenantID, principal string, onlyGrants []string, now time.Time) (map[string][]AuthoritySource, error) {
	out := map[string][]AuthoritySource{}
	rows, err := tx.Query(ctx, `
		SELECT g.id::text, b.id::text, b.name, g.expires_at, b.permissions
		  FROM access_bundle_grants g
		  JOIN access_bundles b ON b.tenant_id = g.tenant_id AND b.id = g.bundle_id
		 WHERE g.tenant_id = $1 AND g.principal = $2 AND `+accessBundleLiveGrant+`
		   AND ($4::text[] IS NULL OR g.id::text = ANY($4::text[]))
		 ORDER BY g.granted_at, g.id`, tenantID, principal, now.UTC(), onlyGrants)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var src AuthoritySource
		var permissions []string
		if err := rows.Scan(&src.GrantID, &src.BundleID, &src.BundleName, &src.ExpiresAt, &permissions); err != nil {
			return nil, err
		}
		for _, p := range permissions {
			out[p] = append(out[p], src)
		}
	}
	return out, rows.Err()
}

// RunAuthority is what a run may do now: the permissions it was issued that
// its grants still give, read with the run in one transaction. A revoked,
// expired or unknown run may do nothing.
func (s *Store) RunAuthority(ctx context.Context, tenantID, runID string, now time.Time) (AccessBundleRun, []string, error) {
	var run AccessBundleRun
	var allowed []string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		run, err = scanAccessBundleRun(tx.QueryRow(ctx, `SELECT `+accessBundleRunColumns+` FROM access_bundle_runs
			WHERE tenant_id = $1 AND id = $2`, tenantID, runID))
		if err != nil {
			return err
		}
		if run.RevokedAt != nil || !run.ExpiresAt.After(now) {
			return nil
		}
		live, err := authorityTx(ctx, tx, tenantID, run.Principal, run.GrantIDs, now)
		if err != nil {
			return err
		}
		for _, p := range run.Permissions {
			if len(live[p]) > 0 {
				allowed = append(allowed, p)
			}
		}
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return AccessBundleRun{}, nil, ErrAccessBundleNotFound
	}
	sort.Strings(allowed)
	return run, allowed, err
}

const accessBundleRunColumns = `id::text, principal, bundle_ids::text[], grant_ids::text[], permissions, label, expires_at,
	issued_by, issued_at, revoked_at, revoked_by`

func scanAccessBundleRun(row pgx.Row) (AccessBundleRun, error) {
	var r AccessBundleRun
	err := row.Scan(&r.ID, &r.Principal, &r.BundleIDs, &r.GrantIDs, &r.Permissions, &r.Label, &r.ExpiresAt,
		&r.IssuedBy, &r.IssuedAt, &r.RevokedAt, &r.RevokedBy)
	return r, err
}

// GetAccessBundleRun reads one run.
func (s *Store) GetAccessBundleRun(ctx context.Context, tenantID, id string) (AccessBundleRun, error) {
	var r AccessBundleRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		r, err = scanAccessBundleRun(tx.QueryRow(ctx, `SELECT `+accessBundleRunColumns+` FROM access_bundle_runs
			WHERE tenant_id = $1 AND id = $2`, tenantID, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return AccessBundleRun{}, ErrAccessBundleNotFound
	}
	return r, err
}

// ListAccessBundleRuns lists runs, newest first, optionally one principal's
// or those minted under one bundle.
func (s *Store) ListAccessBundleRuns(ctx context.Context, tenantID, principal, bundleID string, limit int) ([]AccessBundleRun, error) {
	out := []AccessBundleRun{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+accessBundleRunColumns+` FROM access_bundle_runs
			WHERE tenant_id = $1 AND ($2 = '' OR principal = $2) AND ($3 = '' OR $3 = ANY(bundle_ids::text[]))
			ORDER BY issued_at DESC, id LIMIT $4`, tenantID, principal, bundleID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanAccessBundleRun(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// ListAccessBundleActivity pages the tenant's access bundle activity, newest
// first: the recorded changes, and each run token's recorded uses (one row per
// network, action class and hour, from credential usage).
func (s *Store) ListAccessBundleActivity(ctx context.Context, tenantID string, f AccessBundleActivityFilter) ([]AccessBundleActivity, error) {
	if f.Limit <= 0 {
		return nil, fmt.Errorf("store: ListAccessBundleActivity requires a positive limit")
	}
	var before *time.Time
	if f.BeforeAt != nil {
		t := f.BeforeAt.UTC()
		before = &t
	}
	out := []AccessBundleActivity{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT x.seq, x.at, x.action, x.bundle_ids, x.bundle_names, x.grant_id, x.run_id, x.principal, x.actor, x.detail
			  FROM (
			    SELECT a.event_sequence AS seq, a.at, a.action, a.bundle_ids::text[] AS bundle_ids, a.bundle_names,
			           coalesce(a.grant_id::text, '') AS grant_id, coalesce(a.run_id::text, '') AS run_id,
			           a.principal, a.actor, a.detail
			      FROM access_bundle_activity a WHERE a.tenant_id = $1
			    UNION ALL
			    SELECT w.event_sequence, w.window_start, 'run_used', r.bundle_ids::text[],
			           (SELECT coalesce(array_agg(b.name ORDER BY lower(b.name), b.id), '{}') FROM access_bundles b
			             WHERE b.tenant_id = r.tenant_id AND b.id = ANY(r.bundle_ids)),
			           '', r.id::text, r.principal, r.principal,
			           w.action || ' from ' || w.source || ', up to ' || w.max_count || ' in the hour'
			      FROM credential_usage_windows w
			      JOIN access_bundle_runs r ON r.tenant_id = w.tenant_id AND r.id::text = w.credential_id
			     WHERE w.tenant_id = $1 AND w.kind = 'api_token'
			  ) x
			 WHERE ($2 = '' OR $2 = ANY(x.bundle_ids)) AND ($3 = '' OR x.principal = $3)
			   AND ($4 = '' OR strpos(lower(x.action || ' ' || array_to_string(x.bundle_names, ' ') || ' ' || x.principal
			        || ' ' || x.actor || ' ' || x.detail), lower($4)) > 0)
			   AND ($5::timestamptz IS NULL OR (x.at, x.seq) < ($5::timestamptz, $6::bigint))
			 ORDER BY x.at DESC, x.seq DESC LIMIT $7`,
			tenantID, f.BundleID, f.Principal, f.Query, before, f.BeforeSequence, f.Limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a AccessBundleActivity
			if err := rows.Scan(&a.Sequence, &a.At, &a.Action, &a.BundleIDs, &a.BundleNames, &a.GrantID, &a.RunID,
				&a.Principal, &a.Actor, &a.Detail); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// AccessBundleActivityCursor encodes a page position for
// ListAccessBundleActivity; ParseAccessBundleActivityCursor reads it back.
func AccessBundleActivityCursor(a AccessBundleActivity) string {
	return a.At.UTC().Format(time.RFC3339Nano) + "|" + strconv.FormatInt(a.Sequence, 10)
}

// ParseAccessBundleActivityCursor reads a cursor from AccessBundleActivityCursor.
func ParseAccessBundleActivityCursor(cursor string) (time.Time, int64, error) {
	at, seq, ok := strings.Cut(cursor, "|")
	if !ok {
		return time.Time{}, 0, errors.New("store: malformed access bundle activity cursor")
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("store: malformed access bundle activity cursor: %w", err)
	}
	n, err := strconv.ParseInt(seq, 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}, 0, errors.New("store: malformed access bundle activity cursor")
	}
	return t, n, nil
}
