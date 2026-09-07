// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// lockUpsertArbiterTx serializes concurrent applies of one projection row for
// the rest of the transaction.
//
// INSERT ... ON CONFLICT is race-safe only on its arbiter index. Two applies of
// the same event (the request-side projector and the durable event-tail
// projector, or two control-plane replicas) that pass the arbiter pre-check
// together both insert speculatively, and the loser raises unique_violation
// (SQLSTATE 23505) on any OTHER unique index of the table instead of taking the
// idempotent ON CONFLICT path (DP2-043, DP2-046). A transaction-scoped advisory
// lock keyed on the table and the arbiter values makes the second apply observe
// the first's committed row, so ON CONFLICT decides and the replay converges.
//
// The key is table-scoped and unit-separator joined so tuples cannot alias
// through delimiters. Every writer of a dual-unique table takes this lock with
// the same arbiter values before touching the row; the trstctllint
// upsertarbiter analyzer fails the build when such an upsert is left unguarded.
func lockUpsertArbiterTx(ctx context.Context, tx pgx.Tx, table string, arbiter ...string) error {
	if table == "" || len(arbiter) == 0 {
		return fmt.Errorf("store: upsert arbiter lock identity is incomplete")
	}
	key := "upsert-arbiter\x1f" + table + "\x1f" + strings.Join(arbiter, "\x1f")
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, key); err != nil {
		return fmt.Errorf("store: lock %s upsert arbiter: %w", table, err)
	}
	return nil
}
