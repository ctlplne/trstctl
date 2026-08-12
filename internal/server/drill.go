// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
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
	interval, enabled := restoreDrillSchedule(s.restoreDrill != nil, s.restoreDrillInterval)
	if !enabled {
		// Block until shutdown so the worker's lifecycle matches its siblings.
		<-ctx.Done()
		return
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
			if _, err := s.RunRestoreDrillOnce(ctx); err != nil && s.logger != nil {
				s.logger.Error("scheduled restore drill failed", "error", err)
			}
		}
	}
}

// restoreDrillSchedule decides whether the drill runs, and how often.
//
// A pure function because the decision is what needs testing and a timing test
// cannot see it: a scheduler wrongly turning a zero interval into the daily
// default looks EXACTLY like a correctly disabled one for any window shorter
// than a day. My first test here asserted no drill fired within 150ms and
// passed against the bug it was written to catch, which is the same
// passes-for-the-wrong-reason failure this programme keeps finding elsewhere.
//
// The config layer resolves an unset interval to DefaultBackupDrillInterval, so
// a zero arriving here can only mean the operator wrote "0" — documented as the
// way to switch the drill off. Non-positive is therefore disabled, full stop;
// no default is applied at this layer, because applying one here is precisely
// how "0" came to mean "daily".
func restoreDrillSchedule(haveRunner bool, configured time.Duration) (time.Duration, bool) {
	if !haveRunner || configured <= 0 {
		return 0, false
	}
	return configured, true
}

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
	// Small embedded compositions that wire only the old callback retain the
	// compatibility behavior. Once any durable dependency is present, all four
	// are required: partial assembly must fail instead of silently falling back
	// to the volatile result that this remediation removes from production.
	if s.store == nil && s.log == nil && s.proj == nil && s.restoreDrillSigner == nil {
		return s.runVolatileRestoreDrill(ctx)
	}
	if s.store == nil || s.log == nil || s.proj == nil || s.restoreDrillSigner == nil {
		return backup.DrillAttestation{}, errors.New("server: restore-drill durable evidence dependencies are incomplete")
	}
	s.restoreDrillRunMu.Lock()
	defer s.restoreDrillRunMu.Unlock()

	attestation, err := s.restoreDrill(ctx)
	if attestation.Outcome == "" {
		now := time.Now().UTC()
		attestation = backup.DrillAttestation{
			Outcome: backup.DrillFailed, StartedAt: now, CompletedAt: now,
			Detail: "The scheduled restore drill could not start far enough to inspect a backup. " +
				"This failed outcome is recorded and alerted rather than leaving the previous green result visible.",
			Limitations: []string{"No recovery evidence was produced because the drill could not start."},
		}
	}
	drillID := events.NewID()
	evidence, signErr := backup.SignDrillEvidence(
		ctx, s.restoreDrillSigner, drillID, attestation, s.restoreDrillRPO, s.restoreDrillRTO,
	)
	if signErr != nil {
		return backup.DrillAttestation{}, errors.Join(err, signErr)
	}
	tenants, listErr := s.store.ListTenants(ctx)
	if listErr != nil {
		return backup.DrillAttestation{}, errors.Join(err, fmt.Errorf("server: list restore-drill tenants: %w", listErr))
	}
	if len(tenants) == 0 {
		return backup.DrillAttestation{}, errors.Join(err, errors.New("server: restore drill has no tenant history to record"))
	}
	var recordErr error
	for _, tenant := range tenants {
		attestationID := projections.RestoreDrillAttestationID(tenant.TenantID, drillID)
		payload, marshalErr := json.Marshal(projections.RestoreDrillRecorded{
			AttestationID: attestationID, Evidence: evidence,
		})
		if marshalErr != nil {
			recordErr = errors.Join(recordErr, marshalErr)
			continue
		}
		eventID := uuid.NewSHA1(restoreDrillEventNamespace, []byte(tenant.TenantID+"\x1f"+drillID)).String()
		stored, appendErr := s.log.Append(ctx, events.Event{
			ID: eventID, Type: projections.EventRestoreDrillRecorded,
			TenantID: tenant.TenantID, Time: attestation.CompletedAt.UTC(),
			SchemaVersion: 1, Data: payload,
		})
		if appendErr != nil {
			recordErr = errors.Join(recordErr, fmt.Errorf("server: append restore-drill evidence for tenant %s: %w", tenant.TenantID, appendErr))
			continue
		}
		if projectErr := s.proj.Apply(ctx, stored); projectErr != nil {
			recordErr = errors.Join(recordErr, fmt.Errorf("server: project restore-drill evidence for tenant %s: %w", tenant.TenantID, projectErr))
		}
	}
	if recordErr == nil {
		s.restoreDrillMu.Lock()
		s.lastRestoreDrill = &attestation
		s.restoreDrillMu.Unlock()
	}
	return attestation, errors.Join(err, recordErr)
}

var (
	restoreDrillEventNamespace = uuid.MustParse("9d52bb3c-b404-5a6d-b857-ac3d5259470c")
)

func restoreDrillAlertReason(att backup.DrillAttestation, rpo, rto time.Duration) projections.RestoreDrillAlertReason {
	return backup.DrillAlertReasonFor(att, rpo, rto)
}

func (s *Server) runVolatileRestoreDrill(ctx context.Context) (backup.DrillAttestation, error) {
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
func RunRestoreDrill(
	ctx context.Context,
	cfg *config.Config,
	backupDir string,
	factories ...EditionProjectionOptionsFactory,
) (backup.DrillAttestation, error) {
	if cfg == nil || cfg.Postgres.Mode != config.PostgresExternal || cfg.Postgres.DSN == "" {
		// Without an external Postgres there is nowhere to make a throwaway
		// database. Reported as skipped rather than failed: nothing is broken,
		// this deployment simply cannot drill.
		return backup.RunDrill(ctx, backupDir, nil, nil)
	}

	return backup.RunDrill(ctx, backupDir, func(ctx context.Context) (backup.RestoreResult, error) {
		target, drop, err := createEphemeralDatabase(ctx, cfg.Postgres.DSN)
		if err != nil {
			return backup.RestoreResult{}, err
		}
		// Dropped on every path out, including a panic inside the restore. A
		// drill that left its database behind would fill the server with them,
		// one per night, until somebody noticed the disk.
		defer drop()

		root, err := os.MkdirTemp("", "trstctl-full-restore-drill-")
		if err != nil {
			return backup.RestoreResult{}, fmt.Errorf("server: create isolated drill target: %w", err)
		}
		defer func() { _ = os.RemoveAll(root) }()

		drillCfg, err := isolatedRestoreConfig(cfg, target, root)
		if err != nil {
			return backup.RestoreResult{}, err
		}
		restored, err := runFullRestore(ctx, &drillCfg, backupDir, true, true, factories...)
		if err != nil {
			return backup.RestoreResult{
				EventsRestored:          restored.EventsRestored,
				PostgresRecordsRestored: restored.Postgres.Records,
				PostgresTablesRestored:  restored.Postgres.Tables,
				ArtifactsRestored:       restored.ArtifactsRestored,
				StoreHealthy:            restored.StoreHealthy,
				EventLogHealthy:         restored.EventLogHealthy,
				SignerHealthy:           restored.SignerHealthy,
				ServerHealthy:           restored.ServerHealthy,
			}, err
		}
		return backup.RestoreResult{
			EventsRestored:          restored.EventsRestored,
			PostgresRecordsRestored: restored.Postgres.Records,
			PostgresTablesRestored:  restored.Postgres.Tables,
			ArtifactsRestored:       restored.ArtifactsRestored,
			FullSetRestored:         true,
			StoreHealthy:            restored.StoreHealthy,
			EventLogHealthy:         restored.EventLogHealthy,
			SignerHealthy:           restored.SignerHealthy,
			ServerHealthy:           restored.ServerHealthy,
		}, nil
	}, nil)
}

// isolatedRestoreConfig redirects every mutable restore destination away from
// the running deployment. The deployment KEK and optional backup-decryption key
// are copied in as read-only inputs because neither belongs in the backup set;
// all restored key, certificate, signer, event, archive, and socket state lands
// beneath root and is destroyed with the drill target.
func isolatedRestoreConfig(source *config.Config, postgresDSN, root string) (config.Config, error) {
	cfg := *source
	if err := os.MkdirAll(filepath.Join(root, "run"), 0o700); err != nil {
		return config.Config{}, fmt.Errorf("server: create isolated signer runtime directory: %w", err)
	}
	cfg.Postgres.Mode = config.PostgresExternal
	cfg.Postgres.DSN = postgresDSN
	cfg.NATS = config.NATS{
		Mode: config.NATSEmbedded, StoreDir: filepath.Join(root, "nats"),
		Replicas: 1,
	}
	cfg.Signer.Mode = config.SignerChild
	cfg.Signer.Socket = filepath.Join(root, "run", "signer.sock")
	cfg.Signer.KeyStoreDir = filepath.Join(root, "files", "signer-keystore")
	cfg.Signer.AuthSecretFile = filepath.Join(root, "files", "signer-auth-secret.bin")
	cfg.Audit.SigningKeyFile = filepath.Join(root, "files", "legacy-audit-signing-key.pem")
	cfg.Audit.ArchiveDir = filepath.Join(root, "audit-archive")
	cfg.CA.CertFile = filepath.Join(root, "files", "issuing-ca.crt")

	if source.Secrets.KEKFile == "" {
		return config.Config{}, errors.New("server: restore drill requires the separately-custodied deployment KEK")
	}
	cfg.Secrets.KEKFile = filepath.Join(root, "references", "deployment-kek.bin")
	if err := backup.CopyFile(source.Secrets.KEKFile, cfg.Secrets.KEKFile, 0o400); err != nil {
		return config.Config{}, fmt.Errorf("server: copy deployment KEK into isolated drill target: %w", err)
	}
	if source.Backup.EncryptionKeyFile != "" {
		cfg.Backup.EncryptionKeyFile = filepath.Join(root, "references", "backup-encryption-key.bin")
		if err := backup.CopyFile(source.Backup.EncryptionKeyFile, cfg.Backup.EncryptionKeyFile, 0o400); err != nil {
			return config.Config{}, fmt.Errorf("server: copy backup decryption key into isolated drill target: %w", err)
		}
	}
	return cfg, nil
}

// restoreDrillRunner builds the drill closure for a configuration, or nil when
// this deployment has nothing to drill (epic J2).
//
// Nil rather than a closure that always fails. The difference reaches an
// operator: a nil runner leaves the DR surface reporting that no drill is
// configured, which is a true statement about a deployment that backs up
// elsewhere and not a fault. A closure that ran nightly and failed nightly
// would manufacture an alert out of a choice somebody made deliberately.
func restoreDrillRunner(
	cfg *config.Config,
	factories ...EditionProjectionOptionsFactory,
) func(context.Context) (backup.DrillAttestation, error) {
	if cfg == nil || strings.TrimSpace(cfg.Backup.Directory) == "" {
		return nil
	}
	dir := cfg.Backup.Directory
	// The config is captured by value at assembly, so a later mutation of the
	// caller's struct cannot redirect a drill at a different database.
	snapshot := *cfg
	return func(ctx context.Context) (backup.DrillAttestation, error) {
		return RunRestoreDrill(ctx, &snapshot, dir, factories...)
	}
}

// RestoreDrillRunner exposes the same scheduler closure to the tagged edition
// attach seam so licensed projections participate in the isolated drill.
func RestoreDrillRunner(
	cfg *config.Config,
	factories ...EditionProjectionOptionsFactory,
) func(context.Context) (backup.DrillAttestation, error) {
	return restoreDrillRunner(cfg, factories...)
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
