// SPDX-License-Identifier: BUSL-1.1

package store

import "context"

type tx interface {
	Exec(ctx context.Context, sql string, args ...any) (int64, error)
}

// Unguarded upsert on a table with a second unique index: flagged.
func ApplyDualUnguarded(ctx context.Context, t tx, id, tenant, name string) error {
	_, err := t.Exec(ctx, `INSERT INTO dual (id, tenant_id, name) VALUES ($1, $2, $3) ON CONFLICT (tenant_id, name) DO UPDATE SET id = EXCLUDED.id`, id, tenant, name) // want "upsert on dual arbitrates on \\(name,tenant_id\\) but the table also has unique \\(id\\)"
	return err
}

// The same upsert split across a + chain still parses as one statement: flagged.
func ApplyDualConcatenated(ctx context.Context, t tx, id, tenant, name string) error {
	_, err := t.Exec(ctx, "INSERT INTO dual (id, tenant_id, name) VALUES ($1, $2, $3) "+ // want "upsert on dual arbitrates on \\(name,tenant_id\\)"
		"ON CONFLICT (tenant_id, name) DO NOTHING", id, tenant, name)
	return err
}

// Serialized on an advisory lock keyed on the arbiter: accepted.
func ApplyDualLocked(ctx context.Context, t tx, id, tenant, name string) error {
	if _, err := t.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, tenant+"/"+name); err != nil {
		return err
	}
	_, err := t.Exec(ctx, `INSERT INTO dual (id, tenant_id, name) VALUES ($1, $2, $3)
	 ON CONFLICT (tenant_id, name) DO UPDATE SET id = EXCLUDED.id`, id, tenant, name)
	return err
}

// Retries on unique_violation through a same-package helper: accepted.
func ApplyDualRetried(ctx context.Context, t tx, id, tenant, name string) error {
	_, err := t.Exec(ctx, `INSERT INTO dual (id, tenant_id, name) VALUES ($1, $2, $3)
	 ON CONFLICT (tenant_id, name) DO UPDATE SET id = EXCLUDED.id`, id, tenant, name)
	return classifyWriteError(err)
}

func classifyWriteError(err error) error {
	if err != nil && err.Error() == "23505" {
		return nil
	}
	return err
}

// Only one unique index on the table: nothing for a second index to raise; accepted.
func ApplySingle(ctx context.Context, t tx, id, tenant string) error {
	_, err := t.Exec(ctx, `INSERT INTO single (tenant_id, id) VALUES ($1, $2)
	 ON CONFLICT (tenant_id, id) DO NOTHING`, tenant, id)
	return err
}

// Target-less DO NOTHING absorbs every unique violation: accepted.
func ApplyDualDoNothing(ctx context.Context, t tx, id, tenant, name string) error {
	_, err := t.Exec(ctx, `INSERT INTO dual (id, tenant_id, name) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, id, tenant, name)
	return err
}

// ON CONSTRAINT resolves through the constraint name; unguarded: flagged.
func ApplyNamedUnguarded(ctx context.Context, t tx, id, tenant, key string) error {
	_, err := t.Exec(ctx, `INSERT INTO named (id, tenant_id, key) VALUES ($1, $2, $3) ON CONFLICT ON CONSTRAINT named_pkey DO UPDATE SET key = EXCLUDED.key`, id, tenant, key) // want "upsert on named arbitrates on \\(id\\) but the table also has unique \\(key,tenant_id\\)"
	return err
}

// A CREATE UNIQUE INDEX declared before its table still counts: flagged.
func ApplyIndexedUnguarded(ctx context.Context, t tx, id, tenant, ref string) error {
	_, err := t.Exec(ctx, `INSERT INTO indexed (id, tenant_id, ref) VALUES ($1, $2, $3) ON CONFLICT (id) DO UPDATE SET ref = EXCLUDED.ref`, id, tenant, ref) // want "upsert on indexed arbitrates on \\(id\\) but the table also has unique \\(ref,tenant_id\\)"
	return err
}

// Dropped or moved keys are honoured: none of these is reported.
func ApplyMoved(ctx context.Context, t tx, id, tenant string) error {
	_, err := t.Exec(ctx, `INSERT INTO moved (tenant_id, id) VALUES ($1, $2)
	 ON CONFLICT (tenant_id, id) DO NOTHING`, tenant, id)
	return err
}

func ApplyRepinned(ctx context.Context, t tx, id, tenant string) error {
	_, err := t.Exec(ctx, `INSERT INTO repinned (tenant_id, id) VALUES ($1, $2)
	 ON CONFLICT (tenant_id, diagnostic_id) DO NOTHING`, tenant, id)
	return err
}

func ApplyUnindexed(ctx context.Context, t tx, id, tenant string) error {
	_, err := t.Exec(ctx, `INSERT INTO unindexed (tenant_id, id) VALUES ($1, $2)
	 ON CONFLICT (id) DO NOTHING`, tenant, id)
	return err
}

// A shared backup fence allows both writers to enter and is not serialization.
func ApplyDualSharedFence(ctx context.Context, t tx, id, tenant, name string) error {
	if _, err := t.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(42)`); err != nil {
		return err
	}
	_, err := t.Exec(ctx, `INSERT INTO dual (id, tenant_id, name) VALUES ($1, $2, $3) ON CONFLICT (tenant_id, name) DO NOTHING`, id, tenant, name) // want "upsert on dual arbitrates"
	return err
}

// New independent UUIDs do not repeat the second unique key when the same
// natural-key request races. The arbiter still handles the repeated name.
func ApplyDualFreshID(ctx context.Context, t tx, tenant, name string) error {
	_, err := t.Exec(ctx, `INSERT INTO dual (id, tenant_id, name)
	 VALUES (gen_random_uuid(), $1, $2) ON CONFLICT (tenant_id, name) DO UPDATE SET name = EXCLUDED.name`, tenant, name)
	return err
}

// A fallback expression can reuse a caller-supplied ID; no freshness proof.
func ApplyDualMaybeFreshID(ctx context.Context, t tx, id, tenant, name string) error {
	_, err := t.Exec(ctx, `INSERT INTO dual (id, tenant_id, name) VALUES (coalesce($1, gen_random_uuid()), $2, $3) ON CONFLICT (tenant_id, name) DO NOTHING`, id, tenant, name) // want "upsert on dual arbitrates"
	return err
}

// Updating the generated key with a caller value can still collide.
func ApplyDualReplacedFreshID(ctx context.Context, t tx, id, tenant, name string) error {
	_, err := t.Exec(ctx, `INSERT INTO dual (id, tenant_id, name) VALUES (gen_random_uuid(), $1, $2) ON CONFLICT (tenant_id, name) DO UPDATE SET id = $3`, tenant, name, id) // want "upsert on dual arbitrates"
	return err
}

// A multi-row statement with one reused key is not a fresh-key statement.
func ApplyDualMixedRows(ctx context.Context, t tx, id, tenant, name string) error {
	_, err := t.Exec(ctx, `INSERT INTO dual (id, tenant_id, name) VALUES (gen_random_uuid(), $1, $2), ($3, $1, $2) ON CONFLICT (tenant_id, name) DO NOTHING`, tenant, name, id) // want "upsert on dual arbitrates"
	return err
}

// A fresh primary key does not protect a different repeated unique column.
func ApplyTripleFreshID(ctx context.Context, t tx, tenant, name, alias string) error {
	_, err := t.Exec(ctx, `INSERT INTO triple (id, tenant_id, name, alias) VALUES (gen_random_uuid(), $1, $2, $3) ON CONFLICT (tenant_id, name) DO NOTHING`, tenant, name, alias) // want "upsert on triple arbitrates.*unique \\(alias\\)"
	return err
}
