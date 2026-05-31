package server

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"certctl.io/certctl/internal/config"
)

// defaultBundledPGPort is the loopback port the bundled evaluation Postgres
// listens on when none is configured. Bundled mode is single-node eval, so a
// predictable default is friendly; CERTCTL_POSTGRES_PORT overrides it (e.g. when
// 5432 is already taken). Production runs CERTCTL_POSTGRES_MODE=external.
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
// store drops to the non-superuser `certctl_app` role per transaction (SET LOCAL
// ROLE), so row-level security still applies (AN-1) exactly as in external mode.
//
// Evaluation state persists under cfg.DataDir/db so it survives restarts; the
// pinned Postgres binary is cached (re-downloadable, checksum-pinned) in a shared
// path. Bundled mode is the ONLY path that fetches that binary on first run;
// external mode never downloads anything.
func startBundledPostgres(cfg config.Postgres) (dsn string, stop func() error, err error) {
	dataDir := cfg.DataDir
	if dataDir == "" {
		dataDir = "data/postgres"
	}
	port := bundledPort(cfg)
	db := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(uint32(port)).
		DataPath(filepath.Join(dataDir, "db")).
		RuntimePath(filepath.Join(dataDir, "rt")).
		// Cache the pinned binary outside the data dir so it is not re-downloaded on
		// every fresh eval; the same path the integration tests use.
		BinariesPath(filepath.Join(os.TempDir(), "certctl-pg-bin")).
		Logger(io.Discard).
		StartTimeout(90 * time.Second))
	if err := db.Start(); err != nil {
		return "", nil, fmt.Errorf("start bundled postgres on port %d: %w (set CERTCTL_POSTGRES_PORT to a free port, or use CERTCTL_POSTGRES_MODE=external)", port, err)
	}
	dsn = fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port)
	return dsn, db.Stop, nil
}
