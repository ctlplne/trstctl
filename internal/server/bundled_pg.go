package server

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"trstctl.com/trstctl/internal/config"
)

// defaultBundledPGPort is the loopback port the bundled evaluation Postgres
// listens on when none is configured. Bundled mode is single-node eval, so a
// predictable default is friendly; TRSTCTL_POSTGRES_PORT overrides it (e.g. when
// 5432 is already taken). Production runs TRSTCTL_POSTGRES_MODE=external.
const defaultBundledPGPort = 5432

// bundledPort returns the configured bundled Postgres port, or the default.
func bundledPort(cfg config.Postgres) int {
	if cfg.Port > 0 {
		return cfg.Port
	}
	return defaultBundledPGPort
}

// startBundledPostgres delivers the PRD "bundled single-node Postgres for eval"
// (R4.5): it starts a managed PostgreSQL using the SAME pinned binary the tests and
// the supply-chain manifest record (V16 = 16.4.0, see
// deploy/supply-chain/embedded-postgres.json), and returns a loopback DSN plus a
// stop function. The control plane connects as the bootstrap superuser, but the
// store drops to the non-superuser `trstctl_app` role per transaction (SET LOCAL
// ROLE), so row-level security still applies (AN-1) exactly as in external mode.
//
// Evaluation state persists under cfg.DataDir/db so it survives restarts; the
// pinned Postgres binary is cached in a shared path. Provenance is ENFORCED
// (SUPPLY-003): before starting, a cached binary archive is verified against the
// committed per-arch SHA-256 pin (independent of Maven's same-origin sidecar), and
// a mismatch refuses to start; on a cold cache the freshly-downloaded archive is
// verified before the database is trusted. Bundled mode is the ONLY path that
// fetches that binary on first run; external mode never downloads anything.
func startBundledPostgres(cfg config.Postgres) (dsn string, stop func() error, err error) {
	dataDir := cfg.DataDir
	if dataDir == "" {
		dataDir = "data/postgres"
	}
	port := bundledPort(cfg)
	binariesPath := filepath.Join(os.TempDir(), "trstctl-pg-bin")

	// Provenance, phase 1 (warm cache): if the PostgreSQL archive is already
	// cached, verify it against the committed pin BEFORE starting anything, so a
	// tampered cached binary never executes (SUPPLY-003). A cold cache returns
	// (false, nil) and is gated by phase 2 after the download.
	archive := bundledPGCacheArchive(binariesPath)
	if _, verr := verifyBundledPostgresArchive(archive); verr != nil {
		return "", nil, verr
	}

	db := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(uint32(port)).
		DataPath(filepath.Join(dataDir, "db")).
		RuntimePath(filepath.Join(dataDir, "rt")).
		// Cache the pinned binary outside the data dir so it is not re-downloaded on
		// every fresh eval; the same path the integration tests use.
		BinariesPath(binariesPath).
		// Co-locate the downloaded `.txz` archive with the binaries (the library
		// otherwise caches it under ~/.embedded-postgres-go), so the provenance check
		// (SUPPLY-003) verifies the archive in a path we control deterministically.
		CachePath(binariesPath).
		Logger(io.Discard).
		StartTimeout(90 * time.Second))
	if err := db.Start(); err != nil {
		return "", nil, fmt.Errorf("start bundled postgres on port %d: %w (set TRSTCTL_POSTGRES_PORT to a free port, or use TRSTCTL_POSTGRES_MODE=external)", port, err)
	}

	// Provenance, phase 2 (cold cache just downloaded): a cold Start writes the
	// `.txz` into BinariesPath as it extracts, so verify it now against the committed
	// pin; if it does not match (a Maven/MITM that defeated the same-origin sidecar),
	// stop the database and fail closed (SUPPLY-003). A warm cache that was already
	// extracted by a prior (verified) run keeps only the extracted bin/ and no
	// archive — verifyBundledPostgresArchive returns (false, nil) for that absent
	// case, which phase 1 already covered, so we do not require the archive to exist.
	if _, verr := verifyBundledPostgresArchive(archive); verr != nil {
		_ = db.Stop()
		return "", nil, verr
	}

	dsn = fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port)
	return dsn, db.Stop, nil
}
