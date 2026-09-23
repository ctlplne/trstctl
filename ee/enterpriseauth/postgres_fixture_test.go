// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestServedAuthPostgresDatabasesAreIsolated(t *testing.T) {
	dsnA, dsnB := serverTestPostgresDSN(t), serverTestPostgresDSN(t)
	ctx := context.Background()
	a, err := pgx.Connect(ctx, dsnA)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close(ctx) }()
	b, err := pgx.Connect(ctx, dsnB)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close(ctx) }()
	var databaseA, databaseB, directoryA, directoryB string
	if err := a.QueryRow(ctx, "SELECT current_database(), current_setting('data_directory')").Scan(&databaseA, &directoryA); err != nil {
		t.Fatal(err)
	}
	if err := b.QueryRow(ctx, "SELECT current_database(), current_setting('data_directory')").Scan(&databaseB, &directoryB); err != nil {
		t.Fatal(err)
	}
	if databaseA == databaseB || directoryA == "" || directoryA != directoryB {
		t.Fatal("authentication fixtures must use separate databases in one owned PostgreSQL instance")
	}
	if _, err := a.Exec(ctx, "CREATE TABLE fixture_marker (value integer)"); err != nil {
		t.Fatal(err)
	}
	var leaked bool
	if err := b.QueryRow(ctx, "SELECT to_regclass('public.fixture_marker') IS NOT NULL").Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked {
		t.Fatal("one authentication fixture leaked schema into another fixture")
	}
}
