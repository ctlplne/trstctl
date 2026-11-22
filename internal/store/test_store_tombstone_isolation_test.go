// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Package tests share one PostgreSQL database. A tombstone from one test must
// not enter a later tenant-key rotation with a different test KEK/domain.
func TestNewStoreClearsSecretTombstonesBetweenCases(t *testing.T) {
	ctx := context.Background()
	first := newStore(t)
	if err := first.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO secret_store_tombstones
			(tenant_id, name, version, created_at, deleted_at, deleted_event_id)
			VALUES ($1, 'isolation-check', 1, now(), now(), '00000000-0000-0000-0000-000000000091')`, tenantA); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO secret_store_tombstone_versions
			(tenant_id, name, version, sealed, written_at)
			VALUES ($1, 'isolation-check', 1, $2, now())`, tenantA, []byte{0x91})
		return err
	}); err != nil {
		t.Fatal(err)
	}

	second := newStore(t)
	var parents, versions int
	if err := second.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM secret_store_tombstones WHERE tenant_id = $1`, tenantA).Scan(&parents); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM secret_store_tombstone_versions WHERE tenant_id = $1`, tenantA).Scan(&versions)
	}); err != nil {
		t.Fatal(err)
	}
	if parents != 0 || versions != 0 {
		t.Fatalf("new store retained previous test's tombstones: parents=%d versions=%d", parents, versions)
	}
}
