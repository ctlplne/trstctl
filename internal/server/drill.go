// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// Restoring into a database that exists only for the drill (epic J2).
//
// The ephemeral target is a real PostgreSQL database created for this run and
// dropped afterwards. It has to be real: a drill against an in-memory double
// would prove the double accepts the backup, and the failures worth catching are
// exactly the ones a double cannot have — a migration the artifacts predate, a
// column the restore path expects, a constraint the replayed events violate.
//
// It also has to be SEPARATE. A drill that restored into the live database would
// be a disaster recovery exercise that caused a disaster, which is a failure
// mode with real precedent, so the target name is generated per run and the code
// refuses to proceed if it cannot create a fresh one.

// ErrDrillTargetUnavailable is returned when no ephemeral target can be created.
var ErrDrillTargetUnavailable = errors.New("server: no ephemeral database is available for a restore drill")

// RunRestoreDrill restores the configured backup into a throwaway database and
// returns the attestation.
//
// The restore goes through the SAME path production recovery uses. A drill with
// its own simplified restore would prove the simplified one works, which is the
// one nobody will be running at 3am.
func RunRestoreDrill(ctx context.Context, cfg *config.Config, backupDir string) (backup.DrillAttestation, error) {
	if cfg == nil || cfg.Postgres.Mode != config.PostgresExternal || cfg.Postgres.DSN == "" {
		// Without an external Postgres there is nowhere to make a throwaway
		// database. Reported as skipped rather than failed: nothing is broken,
		// this deployment simply cannot drill.
		return backup.RunDrill(ctx, backupDir, nil, nil)
	}

	return backup.RunDrill(ctx, backupDir, func(ctx context.Context) (int, error) {
		target, drop, err := createEphemeralDatabase(ctx, cfg.Postgres.DSN)
		if err != nil {
			return 0, err
		}
		// Dropped on every path out, including a panic inside the restore. A
		// drill that left its database behind would fill the server with them,
		// one per night, until somebody noticed the disk.
		defer drop()

		drillCfg := *cfg
		drillCfg.Postgres.DSN = target
		return restoreEventLog(ctx, &drillCfg, latestBackupArtifact(backupDir), false)
	}, nil)
}

// createEphemeralDatabase makes a throwaway database and returns its DSN plus a
// drop function.
func createEphemeralDatabase(ctx context.Context, adminDSN string) (string, func(), error) {
	admin, err := store.Open(ctx, adminDSN)
	if err != nil {
		return "", nil, fmt.Errorf("server: connect for drill target: %w", err)
	}
	// A name nobody would mistake for production, carrying the timestamp so an
	// orphan left by a killed process says when it was abandoned.
	name := fmt.Sprintf("trstctl_restore_drill_%d", time.Now().UTC().UnixNano())
	ident := pgx.Identifier{name}.Sanitize()
	if _, err := admin.SystemPool().Exec(ctx, "CREATE DATABASE "+ident); err != nil {
		admin.Close()
		return "", nil, fmt.Errorf("server: create drill database: %w", err)
	}
	drop := func() {
		// A fresh context: the drill's own may already be cancelled by the
		// failure being drilled, and the database still has to go.
		dropCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = admin.SystemPool().Exec(dropCtx, "DROP DATABASE IF EXISTS "+ident+" WITH (FORCE)")
		admin.Close()
	}
	return replaceDatabaseInDSN(adminDSN, name), drop, nil
}

// replaceDatabaseInDSN points a DSN at a different database, leaving everything
// else — host, credentials, TLS mode — as configured.
//
// The drill must reach the same server with the same credentials, because the
// point is to exercise the real restore against the real engine. Only the
// database name changes.
func replaceDatabaseInDSN(dsn, database string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		// A DSN this cannot parse is one the drill should not be guessing at.
		// Returning it unchanged makes the restore target the configured
		// database, which createEphemeralDatabase's caller must never allow —
		// so return empty and let the restore fail loudly instead.
		return ""
	}
	u.Path = "/" + database
	return u.String()
}

// latestBackupArtifact names the event-log artifact a drill restores.
//
// The event log is what a restore replays; the other artifacts are configuration
// and key material that a drill deliberately does not touch. Restoring an
// operator's signer keystore into a throwaway database would be copying key
// material somewhere new to prove a point.
func latestBackupArtifact(dir string) string {
	m, err := backup.ReadFullManifest(filepath.Join(dir, backup.FullManifestName))
	if err != nil {
		return ""
	}
	for _, artifact := range m.Artifacts {
		if artifact.Role == "event-log" && artifact.Captured {
			return filepath.Join(dir, artifact.Path)
		}
	}
	return ""
}
