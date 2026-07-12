// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ConfigureMigrationSessionForTest exposes the migration session posture to
// the external test package (OPS-MIG-LOCK-001 acceptance).
func ConfigureMigrationSessionForTest(ctx context.Context, conn *pgxpool.Conn) error {
	return configureMigrationSession(ctx, conn)
}
