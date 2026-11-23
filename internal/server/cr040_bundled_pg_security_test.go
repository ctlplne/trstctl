// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
)

// A local process that knows only the embedded library's public default must
// never obtain the service account's PostgreSQL superuser session.
func TestCR040BundledPostgresRefusesKnownDefaultSuperuser(t *testing.T) {
	if testing.Short() {
		t.Skip("starts the pinned embedded PostgreSQL")
	}
	port := freeTCPPort(t)
	dsn, stop, err := startBundledPostgres(config.Postgres{
		Mode: config.PostgresBundled, DataDir: t.TempDir(), Port: port,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stop() })
	ctx := t.Context()
	other, err := pgx.Connect(ctx, fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/postgres?sslmode=disable", port))
	if err == nil {
		_ = other.Close(context.Background())
		t.Fatal("a local process used the public postgres/postgres credential to enter the bundled superuser session")
	}
	if dsn == "" {
		t.Fatal("bundled PostgreSQL did not return a control-plane connection")
	}
	if connection, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond); dialErr == nil {
		_ = connection.Close()
		t.Fatal("bundled PostgreSQL still accepts TCP connections")
	}
}

func TestCR040BundledPostgresClosesLegacyPasswordOnRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("starts the pinned embedded PostgreSQL twice")
	}
	root := t.TempDir()
	port := freeTCPPort(t)
	open := func() (string, func() error) {
		t.Helper()
		dsn, stop, err := startBundledPostgres(config.Postgres{Mode: config.PostgresBundled, DataDir: root, Port: port})
		if err != nil {
			t.Fatal(err)
		}
		return dsn, stop
	}
	firstDSN, stop := open()
	first, err := pgx.Connect(t.Context(), firstDSN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Exec(t.Context(), `ALTER ROLE postgres PASSWORD 'postgres'`); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Exec(t.Context(), `CREATE TABLE cr040_restart_marker (id int)`); err != nil {
		t.Fatal(err)
	}
	_ = first.Close(context.Background())
	firstURL, err := url.Parse(firstDSN)
	if err != nil {
		t.Fatal(err)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(firstURL.Query().Get("host")); !os.IsNotExist(err) {
		t.Fatalf("stopped bundled PostgreSQL retained its socket directory: %v", err)
	}
	secondDSN, stop := open()
	t.Cleanup(func() { _ = stop() })
	second, err := pgx.Connect(t.Context(), secondDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close(context.Background()) }()
	var disabled, persisted bool
	if err := second.QueryRow(t.Context(), `SELECT rolpassword IS NULL FROM pg_authid WHERE rolname='postgres'`).Scan(&disabled); err != nil {
		t.Fatal(err)
	}
	if err := second.QueryRow(t.Context(), `SELECT to_regclass('cr040_restart_marker') IS NOT NULL`).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if !disabled || !persisted {
		t.Fatalf("legacy upgrade disabled password=%v, preserved data=%v", disabled, persisted)
	}
}

func TestCR040BundledPostgresReadbackListenerRejectsPasswordLogin(t *testing.T) {
	if testing.Short() {
		t.Skip("starts the pinned embedded PostgreSQL")
	}
	port := freeTCPPort(t)
	_, _, stop, err := startBundledPostgresWith(config.Postgres{
		Mode: config.PostgresBundled, DataDir: t.TempDir(), Port: port,
	}, map[string]string{"listen_addresses": "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stop() })
	other, err := pgx.Connect(t.Context(), fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/postgres?sslmode=disable", port))
	if err == nil {
		_ = other.Close(context.Background())
		t.Fatal("the connector readback listener accepted a password login")
	}
}
