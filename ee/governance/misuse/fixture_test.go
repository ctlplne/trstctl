// SPDX-License-Identifier: LicenseRef-trstctl-EE

package misuse_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"
)

// Authenticate and unpack PostgreSQL once per test process. Each served test
// still gets its own database, so prior setup cannot hide misuse detection defects.
var sharedMisusePostgres struct {
	once       sync.Once
	dsn        string
	dir        string
	stop       func() error
	err        error
	databaseID atomic.Uint64
}

func TestMain(m *testing.M) {
	code := m.Run()
	if sharedMisusePostgres.stop != nil {
		if err := sharedMisusePostgres.stop(); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "stop misuse test PostgreSQL:", err)
			code = 1
		}
	}
	if sharedMisusePostgres.dir != "" {
		if err := os.RemoveAll(sharedMisusePostgres.dir); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "remove owned misuse test PostgreSQL directory:", err)
			code = 1
		}
	}
	os.Exit(code)
}

func misuseTestPostgresDSN(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("starts an authenticated PostgreSQL fixture; skipped in -short")
	}
	sharedMisusePostgres.once.Do(func() {
		sharedMisusePostgres.dir, sharedMisusePostgres.err = os.MkdirTemp("", "trstctl-misuse-pg-")
		if sharedMisusePostgres.err == nil {
			sharedMisusePostgres.dsn, sharedMisusePostgres.stop, sharedMisusePostgres.err = startVerifiedMisusePostgres(sharedMisusePostgres.dir)
		}
	})
	if sharedMisusePostgres.err != nil {
		t.Fatal(sharedMisusePostgres.err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, sharedMisusePostgres.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	name := fmt.Sprintf("misuse_test_%d", sharedMisusePostgres.databaseID.Add(1))
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	// Databases live only in this process-owned cluster. TestMain stops it and
	// removes its exact temporary directory after every test has closed its pools.
	return sharedMisusePostgres.dsn + "/" + name
}

func startVerifiedMisusePostgres(dir string) (string, func() error, error) {
	raw, err := os.ReadFile("../../../deploy/supply-chain/embedded-postgres.json")
	if err != nil {
		return "", nil, err
	}
	var manifest struct {
		PostgresVersion string `json:"postgresVersion"`
		Archives        []struct {
			Arch   string `json:"arch"`
			SHA256 string `json:"txz_sha256"`
		} `json:"archives"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return "", nil, err
	}
	arch := runtime.GOARCH
	if arch == "arm64" {
		arch = "arm64v8"
	}
	if _, err := os.Stat("/etc/alpine-release"); err == nil {
		arch += "-alpine"
	}
	identity := embeddedpostgres.ArchiveIdentity{OS: runtime.GOOS, Arch: arch, Version: embeddedpostgres.PostgresVersion(manifest.PostgresVersion)}
	for _, entry := range manifest.Archives {
		if entry.Arch == runtime.GOOS+"-"+arch {
			identity.SHA256 = entry.SHA256
		}
	}
	if identity.SHA256 == "" {
		return "", nil, fmt.Errorf("no committed PostgreSQL pin for %s/%s", runtime.GOOS, arch)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if port < 1 || port > 65535 {
		_ = ln.Close()
		return "", nil, errors.New("invalid fixture TCP port")
	}
	if err := ln.Close(); err != nil {
		return "", nil, err
	}
	cache, err := embeddedpostgres.OpenVerifiedCache(os.TempDir(), "trstctl-pg-archives", identity.OS+"-"+identity.Arch+"-"+manifest.PostgresVersion+"-"+identity.SHA256)
	if err != nil {
		return "", nil, err
	}
	archive := filepath.Join(os.TempDir(), "trstctl-pg-bin", fmt.Sprintf("embedded-postgres-binaries-%s-%s-%s.txz", identity.OS, identity.Arch, manifest.PostgresVersion))
	pg, err := embeddedpostgres.NewVerifiedDatabase(embeddedpostgres.DefaultConfig().Version(identity.Version).Port(uint32(port)).DataPath(filepath.Join(dir, "db")).CachePath(cache.Path()).ArchiveSourcePath(archive).StartParameters(map[string]string{"listen_addresses": "127.0.0.1", "unix_socket_directories": ""}).Logger(io.Discard).StartTimeout(90*time.Second), identity)
	if err != nil {
		return "", nil, errors.Join(err, cache.Close())
	}
	if err := pg.Start(); err != nil {
		return "", nil, errors.Join(err, cache.Close())
	}
	if err := cache.Close(); err != nil {
		return "", nil, errors.Join(err, pg.Stop())
	}
	return fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d", port), pg.Stop, nil
}

func newMisuseTestStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, misuseTestPostgresDSN(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return st
}
