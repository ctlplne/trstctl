// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/projections"
)

var _ projections.TransactionalTenantLifecycleProjection = (*AuthorityProjection)(nil)

// withProviderLifecycleScopeTx keeps core's role, transaction and lifecycle
// lock while updating the exact customer and the fixed Provider authority
// partition. RLS remains enabled. Provider tables always live in public, even
// when the erased customer's core tables use an isolated schema.
//
// On success the original tenant and search path are restored before another
// extension runs. On any error the caller must roll back the transaction, just
// as for every other transactional projection failure.
func withProviderLifecycleScopeTx(ctx context.Context, tx pgx.Tx, fn func() error) error {
	var tenant, searchPath string
	if err := tx.QueryRow(ctx, `SELECT COALESCE(current_setting('trstctl.tenant_id', true), ''), current_setting('search_path')`).Scan(&tenant, &searchPath); err != nil {
		return fmt.Errorf("provider: read lifecycle projection scope: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id', $1, true), set_config('search_path', 'pg_catalog, public', true)`, providerAuthorityTenant); err != nil {
		return fmt.Errorf("provider: enter lifecycle projection scope: %w", err)
	}
	if err := fn(); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id', $1, true), set_config('search_path', $2, true)`, tenant, searchPath); err != nil {
		return fmt.Errorf("provider: restore lifecycle projection scope: %w", err)
	}
	return nil
}
