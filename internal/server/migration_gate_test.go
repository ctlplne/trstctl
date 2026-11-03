// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// freshServerTestDatabase creates an empty database in the shared test cluster.
func freshServerTestDatabase(t *testing.T) string {
	t.Helper()
	base := serverTestPostgresDSN(t)
	name := fmt.Sprintf("trstctl_gate_%d", time.Now().UnixNano())
	admin, err := pgx.Connect(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	if _, err := admin.Exec(context.Background(), "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if c, err := pgx.Connect(context.Background(), base); err == nil {
			_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
			_ = c.Close(context.Background())
		}
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}

// With TRSTCTL_MIGRATE_AUTO=false the server refuses to start while any
// migration is pending — an extension's as much as a core one — and applies
// nothing; the operator takes a backup and runs `trstctl --migrate`.
func TestBootRefusesPendingExtensionMigrationWhenAutoMigrateIsOff(t *testing.T) {
	ctx := t.Context()
	dsn := freshServerTestDatabase(t)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	st.Close()

	cfg := config.Default()
	cfg.Postgres.Mode = config.PostgresExternal
	cfg.Postgres.DSN = dsn
	cfg.Migrate.Auto = false
	ext := fstest.MapFS{"migrations/990001_gate_probe.sql": {Data: []byte("CREATE TABLE gate_probe (k int);")}}
	booted, stop, err := openMigratedStore(ctx, cfg, slog.New(slog.DiscardHandler), []fs.FS{ext})
	if err == nil {
		booted.Close()
		if stop != nil {
			_ = stop()
		}
		t.Fatal("the server started with an extension migration pending and automatic migration off")
	}
	if !strings.Contains(err.Error(), "990001_gate_probe.sql") || !strings.Contains(err.Error(), "TRSTCTL_MIGRATE_AUTO=false") {
		t.Fatalf("refusal %q; want it to name the pending migration and the setting", err)
	}

	check, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = check.Close(context.Background()) }()
	var table, ledgered bool
	if err := check.QueryRow(ctx, `SELECT to_regclass('gate_probe') IS NOT NULL,
		EXISTS (SELECT 1 FROM schema_migrations WHERE version = 990001)`).Scan(&table, &ledgered); err != nil {
		t.Fatal(err)
	}
	if table || ledgered {
		t.Fatalf("the refused start applied the migration: table=%v ledgered=%v", table, ledgered)
	}
}
