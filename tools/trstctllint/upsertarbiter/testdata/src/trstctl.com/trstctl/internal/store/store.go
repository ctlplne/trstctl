// SPDX-License-Identifier: MPL-2.0

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
