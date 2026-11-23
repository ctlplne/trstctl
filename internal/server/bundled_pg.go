// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"

	"trstctl.com/trstctl/internal/config"
)

// defaultBundledPGPort is the private Unix socket number the bundled evaluation
// Postgres uses when none is configured. It never opens a TCP listener.
// Production runs TRSTCTL_POSTGRES_MODE=external.
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
// supply-chain manifest records (bundledPGVersion = 16.16.0, see
// deploy/supply-chain/embedded-postgres.json), and returns a private Unix-socket
// DSN plus a stop function. OS peer authentication limits the bootstrap role to
// the service account. Tenant transactions use the non-superuser trstctl_app
// role under row-level security (AN-1).
//
// Evaluation data persists under cfg.DataDir/db. The exact platform/version
// archive must match a committed pin before it is extracted or any executable is
// invoked. Every start derives a fresh private binary tree; existing extracted
// caches are neither trusted nor deleted.
func startBundledPostgres(cfg config.Postgres) (dsn string, stop func() error, err error) {
	dsn, _, stop, err = startBundledPostgresWith(cfg, nil)
	return dsn, stop, err
}

// startBundledPostgresWith is startBundledPostgres with extra server start
// parameters, and it also reports the directory holding the verified binaries
// so a repository proof can run the pinned server's own pg_ctl. The verified
// runtime chooses that directory itself (a private temporary tree); nothing
// outside it is trusted for binaries.
func startBundledPostgresWith(cfg config.Postgres, extraParams map[string]string) (dsn, binariesPath string, stop func() error, err error) {
	if cfg.Port < 0 || cfg.Port > 65535 {
		return "", "", nil, fmt.Errorf("bundled postgres: port must be between 1 and 65535, or zero for the default")
	}
	dataDir := cfg.DataDir
	if dataDir == "" {
		dataDir = "data/postgres"
	}
	port := bundledPort(cfg)

	identity, err := bundledPGArchiveIdentity()
	if err != nil {
		return "", "", nil, err
	}

	cacheRoot := bundledPGCacheRoot()
	legacyArchive := bundledPGCacheArchive(bundledPGArchiveDir(cacheRoot))
	cache, err := embeddedpostgres.OpenVerifiedCache(cacheRoot, "trstctl-pg-archives", identity.OS+"-"+identity.Arch+"-"+string(identity.Version)+"-"+identity.SHA256)
	if err != nil {
		return "", "", nil, err
	}
	defer func() {
		if closeErr := cache.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
			if stop != nil {
				err = errors.Join(err, stop())
				dsn, binariesPath, stop = "", "", nil
			}
		}
	}()
	cachePath := cache.Path()
	// A random 0700 socket directory and peer mapping replace the public
	// postgres/postgres TCP login. This is installed before any database start,
	// including the first restart of an existing bundled cluster.
	socketDir, err := bundledPGSocketDirectory()
	if err != nil {
		return "", "", nil, err
	}
	removeSocket := true
	defer func() {
		if removeSocket {
			_ = os.RemoveAll(socketDir)
		}
	}()
	params := map[string]string{
		"listen_addresses": "", "unix_socket_directories": socketDir,
		"hba_file":   filepath.Join(socketDir, "pg_hba.conf"),
		"ident_file": filepath.Join(socketDir, "pg_ident.conf"),
	}
	for key, value := range extraParams {
		switch key {
		case "listen_addresses":
			// The connector's local TLS-readback test needs a TCP handshake.
			// pg_hba has no host entry, so that listener authenticates nobody.
			if value != "127.0.0.1" {
				return "", "", nil, errors.New("bundled postgres: optional TCP readback may listen on loopback only")
			}
		case "unix_socket_directories", "hba_file", "ident_file":
			return "", "", nil, fmt.Errorf("bundled postgres: %s is reserved for peer-only authentication", key)
		}
		params[key] = value
	}
	db, err := embeddedpostgres.NewVerifiedDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.PostgresVersion(bundledPGVersion)).
		Port(uint32(port)). // #nosec G115 -- cfg.Port is checked above and the zero default is 5432 (CWE-190)
		ConnectionHost(socketDir).
		DataPath(filepath.Join(dataDir, "db")).
		CachePath(cachePath).
		ArchiveSourcePath(legacyArchive).
		StartParameters(params).
		Logger(io.Discard).
		StartTimeout(90*time.Second), identity)
	if err != nil {
		return "", "", nil, err
	}
	archivePath := bundledPGCacheArchive(cachePath)
	verified, err := verifyArchiveFileAgainst(archivePath, identity.SHA256)
	if err != nil {
		return "", "", nil, err
	}
	if !verified {
		if err := db.AcquireArchive(); err != nil {
			return "", "", nil, err
		}
	}
	verified, err = verifyArchiveFileAgainst(archivePath, identity.SHA256)
	if err != nil {
		return "", "", nil, err
	}
	if !verified {
		return "", "", nil, fmt.Errorf("bundled postgres: archive absent after authenticated acquisition")
	}
	// Start independently hashes its opened bytes and extracts a fresh tree, so
	// these wrapper checks never grant trust to a later pathname reopen.
	if err := db.Start(); err != nil {
		removeSocket = !db.StartOwnershipUncertain()
		return "", "", nil, fmt.Errorf("start bundled postgres on port %d: %w (set TRSTCTL_POSTGRES_PORT to a free port, or use TRSTCTL_POSTGRES_MODE=external)", port, err)
	}
	query := url.Values{"host": {socketDir}, "port": {strconv.Itoa(port)}, "sslmode": {"disable"}}
	dsn = (&url.URL{Scheme: "postgres", User: url.User("postgres"), Path: "/postgres", RawQuery: query.Encode()}).String()
	// Password login is disabled before the datastore is returned. Existing
	// clusters may still carry the library-default password, but the peer-only
	// HBA is already active when that cluster starts for upgrade.
	if err := disableBundledPGPassword(dsn); err != nil {
		stopErr := db.Stop()
		if stopErr != nil {
			removeSocket = false
		}
		return "", "", nil, errors.Join(err, stopErr)
	}
	removeSocket = false
	return dsn, db.BinariesPath(), func() error {
		if err := db.Stop(); err != nil {
			return err
		}
		return os.RemoveAll(socketDir)
	}, nil
}

func bundledPGSocketDirectory() (string, error) {
	account, err := user.Current()
	if err != nil || account.Username == "" {
		return "", errors.New("bundled postgres: peer authentication needs a named OS user")
	}
	for _, ch := range account.Username {
		if ch != '_' && ch != '-' && ch != '.' && (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') {
			return "", errors.New("bundled postgres: OS username cannot be represented in the peer map")
		}
	}
	dir, err := os.MkdirTemp("", "trstctl-pg-socket-")
	if err != nil {
		return "", err
	}
	if strings.ContainsAny(dir, "\"\\\r\n") {
		_ = os.RemoveAll(dir)
		return "", errors.New("bundled postgres: temporary socket path cannot be quoted safely")
	}
	for name, contents := range map[string]string{
		"pg_hba.conf":   "local all postgres peer map=trstctl_bundled\n",
		"pg_ident.conf": "trstctl_bundled " + account.Username + " postgres\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600); err != nil { // #nosec G304 -- fixed files in the owned private socket directory (CWE-22)
			_ = os.RemoveAll(dir)
			return "", err
		}
	}
	return dir, nil
}

func disableBundledPGPassword(dsn string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("bundled postgres: connect through private peer socket: %w", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	if _, err := conn.Exec(ctx, `ALTER ROLE postgres PASSWORD NULL`); err != nil {
		return fmt.Errorf("bundled postgres: disable superuser password login: %w", err)
	}
	return nil
}

// An operator may place the verified, executable archive cache on a dedicated
// private filesystem. OpenVerifiedCache validates ownership, mode, and every
// child before acquisition; selecting a root never bypasses that guard.
func bundledPGCacheRoot() string {
	if root := os.Getenv("TRSTCTL_BUNDLED_PG_CACHE_ROOT"); root != "" {
		return root
	}
	return os.TempDir()
}

// bundledPGArchiveDir is where an existing archive is looked for before any
// download: TRSTCTL_BUNDLED_PG_ARCHIVE_DIR, or trstctl-pg-bin under the cache
// root. The archive there is read, authenticated against the committed
// SHA-256 and copied into the verified cache; nothing in the directory is
// trusted, so it may be a read-only mount another user owns (CI-L47: the DoD
// runner offers the host's cached archive this way instead of every census
// shard downloading it).
func bundledPGArchiveDir(cacheRoot string) string {
	if dir := os.Getenv("TRSTCTL_BUNDLED_PG_ARCHIVE_DIR"); dir != "" {
		return dir
	}
	return filepath.Join(cacheRoot, "trstctl-pg-bin")
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
