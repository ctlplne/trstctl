// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"

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
// (R4.5): it starts a managed PostgreSQL using the pinned binary the
// supply-chain manifest records (bundledPGVersion = 16.15.0, see
// deploy/supply-chain/embedded-postgres.json), and returns a loopback DSN plus a
// stop function. The control plane connects as the bootstrap superuser, but the
// store drops to the non-superuser `trstctl_app` role per transaction (SET LOCAL
// ROLE), so row-level security still applies (AN-1) exactly as in external mode.
//
// Evaluation data persists under cfg.DataDir/db. The exact platform/version
// archive must match a committed pin before it is extracted or any executable is
// invoked. Every start derives a fresh private binary tree; existing extracted
// caches are neither trusted nor deleted.
func startBundledPostgres(cfg config.Postgres) (dsn string, stop func() error, err error) {
	if cfg.Port < 0 || cfg.Port > 65535 {
		return "", nil, fmt.Errorf("bundled postgres: port must be between 1 and 65535, or zero for the default")
	}
	dataDir := cfg.DataDir
	if dataDir == "" {
		dataDir = "data/postgres"
	}
	port := bundledPort(cfg)

	identity, err := bundledPGArchiveIdentity()
	if err != nil {
		return "", nil, err
	}

	legacyArchive := bundledPGCacheArchive(filepath.Join(os.TempDir(), "trstctl-pg-bin"))
	cache, err := embeddedpostgres.OpenVerifiedCache(os.TempDir(), "trstctl-pg-archives", identity.OS+"-"+identity.Arch+"-"+string(identity.Version)+"-"+identity.SHA256)
	if err != nil {
		return "", nil, err
	}
	defer func() {
		if closeErr := cache.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
			if stop != nil {
				err = errors.Join(err, stop())
				dsn, stop = "", nil
			}
		}
	}()
	cachePath := cache.Path()
	db, err := embeddedpostgres.NewVerifiedDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.PostgresVersion(bundledPGVersion)).
		Port(uint32(port)). // #nosec G115 -- cfg.Port is checked above and the zero default is 5432 (CWE-190)
		DataPath(filepath.Join(dataDir, "db")).
		CachePath(cachePath).
		ArchiveSourcePath(legacyArchive).
		// Use the numeric loopback address for this local-only server. Resolving
		// localhost otherwise makes PostgreSQL depend on the host's resolver.
		// Disable the unused Unix listener and its shared /tmp lock file.
		StartParameters(map[string]string{"listen_addresses": "127.0.0.1", "unix_socket_directories": ""}).
		Logger(io.Discard).
		StartTimeout(90*time.Second), identity)
	if err != nil {
		return "", nil, err
	}
	archivePath := bundledPGCacheArchive(cachePath)
	verified, err := verifyArchiveFileAgainst(archivePath, identity.SHA256)
	if err != nil {
		return "", nil, err
	}
	if !verified {
		if err := db.AcquireArchive(); err != nil {
			return "", nil, err
		}
	}
	verified, err = verifyArchiveFileAgainst(archivePath, identity.SHA256)
	if err != nil {
		return "", nil, err
	}
	if !verified {
		return "", nil, fmt.Errorf("bundled postgres: archive absent after authenticated acquisition")
	}
	// Start independently hashes its opened bytes and extracts a fresh tree, so
	// these wrapper checks never grant trust to a later pathname reopen.
	if err := db.Start(); err != nil {
		return "", nil, fmt.Errorf("start bundled postgres on port %d: %w (set TRSTCTL_POSTGRES_PORT to a free port, or use TRSTCTL_POSTGRES_MODE=external)", port, err)
	}

	dsn = fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/postgres", port)
	return dsn, db.Stop, nil
}

// bundledPGArchiveIdentity is the served trust authority. Empty or unsupported
// pins are errors, never a request to fall back to the legacy fixture loader.
func bundledPGArchiveIdentity() (embeddedpostgres.ArchiveIdentity, error) {
	supported := runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")
	supported = supported || runtime.GOOS == "darwin" && runtime.GOARCH == "arm64"
	if !supported {
		return embeddedpostgres.ArchiveIdentity{}, fmt.Errorf("bundled postgres: unsupported pinned runtime %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	arch := archiveArch()
	digest, ok := bundledPGTxzSHA256[runtime.GOOS+"-"+arch]
	if !ok {
		return embeddedpostgres.ArchiveIdentity{}, fmt.Errorf("bundled postgres: no committed provenance pin for %s/%s", runtime.GOOS, arch)
	}
	return embeddedpostgres.ArchiveIdentity{OS: runtime.GOOS, Arch: arch, Version: embeddedpostgres.PostgresVersion(bundledPGVersion), SHA256: digest}, nil
}
