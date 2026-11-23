// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/buildinfo"
)

// RewrapFleetCutover names the two database login roles and the owner's
// maintenance attestation. It contains no password or other credential.
type RewrapFleetCutover struct {
	OldLoginRole           string
	NewLoginRole           string
	MaintenanceAttestation string
}

var ErrRewrapFleetCutoverUnavailable = errors.New("store: upgraded fleet cutover is unverified")

// RequireRewrapFleetCutover checks the live PostgreSQL authority that excludes
// old binaries before a key-domain history rewrite. The owner must keep the old
// role NOLOGIN throughout the cutover; a snapshot session check alone cannot
// prevent that role from reconnecting later.
func (s *Store) RequireRewrapFleetCutover(ctx context.Context, cutover RewrapFleetCutover) error {
	if s == nil {
		return ErrRewrapFleetCutoverUnavailable
	}
	return s.WithGlobalKeyStateAdmission(ctx, KeyStateExclusive, func(admitted context.Context) error {
		return s.requireRewrapFleetCutoverAdmitted(admitted, cutover)
	})
}

func (s *Store) requireRewrapFleetCutoverAdmitted(ctx context.Context, cutover RewrapFleetCutover) error {
	if s == nil || strings.TrimSpace(cutover.OldLoginRole) == "" ||
		strings.TrimSpace(cutover.NewLoginRole) == "" ||
		strings.TrimSpace(cutover.MaintenanceAttestation) == "" ||
		cutover.OldLoginRole == cutover.NewLoginRole {
		return ErrRewrapFleetCutoverUnavailable
	}
	admitted := ctx
	var currentRole string
	if err := s.pool.QueryRow(admitted, `SELECT session_user`).Scan(&currentRole); err != nil {
		return fmt.Errorf("%w: inspect current login: %v", ErrRewrapFleetCutoverUnavailable, err)
	}
	if currentRole != cutover.NewLoginRole {
		return fmt.Errorf("%w: configured new login is not the active store login", ErrRewrapFleetCutoverUnavailable)
	}
	var oldCanLogin, newCanLogin bool
	//trstctl:system-query — cross-tenant system cutover reads only pg_catalog login capability for the exact configured role; no tenant table is accessed.
	if err := s.pool.QueryRow(admitted, `SELECT rolcanlogin FROM pg_catalog.pg_roles WHERE rolname=$1`,
		cutover.OldLoginRole).Scan(&oldCanLogin); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: named old login role is missing", ErrRewrapFleetCutoverUnavailable)
		}
		return err
	}
	if oldCanLogin {
		return fmt.Errorf("%w: named old login role still permits LOGIN", ErrRewrapFleetCutoverUnavailable)
	}
	//trstctl:system-query — cross-tenant system cutover reads only pg_catalog login capability for the exact configured role; no tenant table is accessed.
	if err := s.pool.QueryRow(admitted, `SELECT rolcanlogin FROM pg_catalog.pg_roles WHERE rolname=$1`,
		cutover.NewLoginRole).Scan(&newCanLogin); err != nil || !newCanLogin {
		return fmt.Errorf("%w: configured new login is unavailable", ErrRewrapFleetCutoverUnavailable)
	}
	for _, role := range []string{cutover.OldLoginRole, cutover.NewLoginRole} {
		var member bool
		//trstctl:system-query — cross-tenant system cutover reads only pg_catalog membership for this configured login and trstctl_app; no tenant table is accessed.
		if err := s.pool.QueryRow(admitted, `SELECT EXISTS(
				SELECT 1 FROM pg_catalog.pg_auth_members AS membership
				JOIN pg_catalog.pg_roles AS login ON login.oid=membership.member
				JOIN pg_catalog.pg_roles AS app ON app.oid=membership.roleid
				WHERE login.rolname=$1 AND app.rolname='trstctl_app')`, role).Scan(&member); err != nil {
			return fmt.Errorf("%w: inspect application-role membership: %v", ErrRewrapFleetCutoverUnavailable, err)
		}
		if !member {
			return fmt.Errorf("%w: old and new logins must be application-role members", ErrRewrapFleetCutoverUnavailable)
		}
	}
	var oldSessions, unknownSessions int
	//trstctl:system-query — cross-tenant system session inventory is required before key-domain cutover; only direct or inherited trstctl_app login members on this database count, and the old login must have none while every remaining application session identifies the exact upgraded build. A distinct DBA maintenance role is excluded.
	if err := s.pool.QueryRow(admitted, `WITH RECURSIVE app_members(member) AS (
			SELECT membership.member FROM pg_catalog.pg_auth_members AS membership
			JOIN pg_catalog.pg_roles AS app ON app.oid=membership.roleid
			WHERE app.rolname='trstctl_app'
			UNION
			SELECT membership.member FROM pg_catalog.pg_auth_members AS membership
			JOIN app_members ON app_members.member=membership.roleid
		)
		SELECT
			count(*) FILTER (WHERE usename=$1),
			count(*) FILTER (WHERE usename IS DISTINCT FROM $2 OR application_name IS DISTINCT FROM $3)
			FROM pg_catalog.pg_stat_activity AS activity
			JOIN pg_catalog.pg_roles AS login ON login.rolname=activity.usename
			JOIN app_members ON app_members.member=login.oid
			WHERE datname=current_database()`,
		cutover.OldLoginRole, cutover.NewLoginRole,
		storeBuildApplicationName(buildinfo.Version(), buildinfo.Commit())).Scan(&oldSessions, &unknownSessions); err != nil {
		return fmt.Errorf("%w: inspect active database sessions: %v", ErrRewrapFleetCutoverUnavailable, err)
	}
	if oldSessions != 0 || unknownSessions != 0 {
		return fmt.Errorf("%w: old or unknown database sessions remain (old=%d unknown=%d)",
			ErrRewrapFleetCutoverUnavailable, oldSessions, unknownSessions)
	}
	return nil
}
