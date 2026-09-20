// SPDX-License-Identifier: BUSL-1.1

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

// OnlineMigrationExecutionSQLForTest exposes the exact runtime plan to the
// external online-safety guard. Empty means the original SQL executes unchanged.
func OnlineMigrationExecutionSQLForTest(name string, body []byte) (string, error) {
	p, err := historicalOnlinePlan(name, body)
	if err != nil || p == nil {
		return "", err
	}
	return p.executionSQL(), nil
}

// MigrationChecksumForTest exposes the ledger digest so the checksum guards pin
// the same function the runner records.
func MigrationChecksumForTest(body []byte) string { return migrationChecksum(body) }
