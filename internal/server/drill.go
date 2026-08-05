// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
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

// RunRestoreDrillScheduler runs the restore drill on its interval (epic J2).
//
// This exists because the first cut of J2 did not have it, and that omission is
// worth recording rather than quietly fixing: the drill, the attestation, the
// ephemeral target and the DR posture endpoint were all built and all tested,
// and NOTHING in the running binary ever called RunRestoreDrill. The capability
// was unreachable in production — the same defect class as D2's VerifyAddress
// with no producer, B2's endpoint.renew with no enqueue, and B5's custody
// projection that was never written. Three previous instances, and it happened
// again inside the change that was supposed to prove backups are real.
//
// The failure mode it would have shipped is specific and bad: the DR surface
// would have reported "never drilled" on every deployment forever, which reads
// as "nobody has got around to configuring it" rather than "this product cannot
// do it", so no operator would ever have asked why.
func (s *Server) RunRestoreDrillScheduler(ctx context.Context) {
	if s.restoreDrill == nil || s.restoreDrillInterval < 0 {
		// No drill configured, or explicitly disabled. Block until shutdown so
		// the worker's lifecycle matches its siblings.
		<-ctx.Done()
		return
	}
	interval := s.restoreDrillInterval
	if interval == 0 {
		interval = defaultRestoreDrillInterval
	}
	// Not at startup. A restore drill replays the whole event log into a fresh
	// database, and doing that while the process is still opening its listeners
	// would make every cold start slower and every crash-loop restart heavier at
	// exactly the moment the deployment is least healthy.
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = s.RunRestoreDrillOnce(ctx)
		}
	}
}

// defaultRestoreDrillInterval is how often the drill runs when unconfigured.
const defaultRestoreDrillInterval = 24 * time.Hour

// RunRestoreDrillOnce runs one drill and records its attestation.
//
// Exported so a served-path test can run exactly one drill on demand rather than
// waiting an interval — the acceptance criterion is that a drill produces a
// signed attestation, and a test has to be able to make one happen.
//
// A FAILED drill is recorded, not discarded. The attestation whose outcome is
// "failed" is the single most valuable thing this surface can hold: it means the
// backup exists and cannot be restored, which is the state every other signal in
// the system reports as healthy.
func (s *Server) RunRestoreDrillOnce(ctx context.Context) (backup.DrillAttestation, error) {
	if s.restoreDrill == nil {
		return backup.DrillAttestation{}, ErrDrillTargetUnavailable
	}
	attestation, err := s.restoreDrill(ctx)
	// An attestation that names an outcome is recorded even when an error came
	// back with it, and the case that matters is the SKIPPED one: RunDrill
	// returns a populated "no ephemeral target" attestation alongside a sentinel
	// error. Treating that as a plain failure and dropping the attestation would
	// leave a deployment that CANNOT drill reporting that it has NEVER drilled —
	// the two states this surface exists to tell apart, collapsed by the code
	// that serves it.
	//
	// An empty outcome is different: the drill did not get far enough to say
	// anything, so the previous attestation stands rather than being replaced by
	// a blank that would read as a clean run.
	if attestation.Outcome == "" {
		return backup.DrillAttestation{}, err
	}
	s.restoreDrillMu.Lock()
	s.lastRestoreDrill = &attestation
	s.restoreDrillMu.Unlock()
	return attestation, err
}

// LastRestoreDrill returns the most recent attestation, or nil if none has run.
//
// Nil is the honest answer and the API depends on it being distinguishable: a
// zero-valued DrillAttestation would present as a drill that restored zero
// events in zero time and found nothing wrong, which is precisely how a
// never-drilled deployment would come to look like a perfectly drilled one.
func (s *Server) LastRestoreDrill() *backup.DrillAttestation {
	s.restoreDrillMu.Lock()
	defer s.restoreDrillMu.Unlock()
	return s.lastRestoreDrill
}

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

// restoreDrillRunner builds the drill closure for a configuration, or nil when
// this deployment has nothing to drill (epic J2).
//
// Nil rather than a closure that always fails. The difference reaches an
// operator: a nil runner leaves the DR surface reporting that no drill is
// configured, which is a true statement about a deployment that backs up
// elsewhere and not a fault. A closure that ran nightly and failed nightly
// would manufacture an alert out of a choice somebody made deliberately.
func restoreDrillRunner(cfg *config.Config) func(context.Context) (backup.DrillAttestation, error) {
	if cfg == nil || strings.TrimSpace(cfg.Backup.Directory) == "" {
		return nil
	}
	dir := cfg.Backup.Directory
	// The config is captured by value at assembly, so a later mutation of the
	// caller's struct cannot redirect a drill at a different database.
	snapshot := *cfg
	return func(ctx context.Context) (backup.DrillAttestation, error) {
		return RunRestoreDrill(ctx, &snapshot, dir)
	}
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
