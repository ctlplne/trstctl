// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// TenantQueryForTest exposes the one-round-trip tenant read (CI-L37 d′).
func (s *Store) TenantQueryForTest(ctx context.Context, tenantID, sql string, args []any, read func(pgx.Rows) error) error {
	return s.tenantQuery(ctx, tenantID, sql, args, read)
}

// TenantQueryRowForTest exposes the one-round-trip tenant read of one row.
func (s *Store) TenantQueryRowForTest(ctx context.Context, tenantID, sql string, args []any, scan func(pgx.Row) error) error {
	return s.tenantQueryRow(ctx, tenantID, sql, args, scan)
}

// HasPrivacySubjectErasurePreparationForTest exposes the erasure-preparation
// check the privacy recovery barrier makes.
func (s *Store) HasPrivacySubjectErasurePreparationForTest(ctx context.Context, tenantID string) (bool, error) {
	return s.hasPrivacySubjectErasurePreparation(ctx, tenantID)
}
