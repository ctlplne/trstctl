// SPDX-License-Identifier: BUSL-1.1

package upsertarbiter

import "testing"

func TestFreshInsertColumns(t *testing.T) {
	for _, tc := range []struct {
		name, sql string
		fresh     bool
	}{
		{"direct", `INSERT INTO dual (id, name) VALUES (gen_random_uuid(), $1) ON CONFLICT (name) DO NOTHING`, true},
		{"spaces", `INSERT INTO dual ("id", name) VALUES (GEN_RANDOM_UUID ( ), $1) ON CONFLICT (name) DO NOTHING`, true},
		{"quoted comma", `INSERT INTO dual (name, id) VALUES ('a,b''c', gen_random_uuid()) ON CONFLICT (name) DO NOTHING`, true},
		{"nested unrelated", `INSERT INTO dual (name, id) VALUES (coalesce($1, concat('a', 'b')), gen_random_uuid()) ON CONFLICT (name) DO NOTHING`, true},
		{"other update", `INSERT INTO dual (id, name) VALUES (gen_random_uuid(), $1) ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id, name`, true},
		{"bound", `INSERT INTO dual (id, name) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING`, false},
		{"default", `INSERT INTO dual (id, name) VALUES (DEFAULT, $1) ON CONFLICT (name) DO NOTHING`, false},
		{"omitted", `INSERT INTO dual (name) VALUES ($1) ON CONFLICT (name) DO NOTHING`, false},
		{"fallback", `INSERT INTO dual (id, name) VALUES (coalesce($1, gen_random_uuid()), $2) ON CONFLICT (name) DO NOTHING`, false},
		{"string literal", `INSERT INTO dual (id, name) VALUES ('gen_random_uuid()', $1) ON CONFLICT (name) DO NOTHING`, false},
		{"two rows", `INSERT INTO dual (id, name) VALUES (gen_random_uuid(), $1), ($2, $1) ON CONFLICT (name) DO NOTHING`, false},
		{"select", `INSERT INTO dual (id, name) SELECT gen_random_uuid(), $1 ON CONFLICT (name) DO NOTHING`, false},
		{"updated", `INSERT INTO dual (id, name) VALUES (gen_random_uuid(), $1) ON CONFLICT (name) DO UPDATE SET name=$1, id=$2`, false},
		{"tuple update", `INSERT INTO dual (id, name) VALUES (gen_random_uuid(), $1) ON CONFLICT (name) DO UPDATE SET (id, name)=($2, $1)`, false},
		{"comment", `INSERT INTO dual (id, name) VALUES (gen_random_uuid() /* , */ , $1) ON CONFLICT (name) DO NOTHING`, false},
		{"dollar quote", `INSERT INTO dual (name, id) VALUES ($q$a,b$q$, gen_random_uuid()) ON CONFLICT (name) DO NOTHING`, false},
		{"unbalanced", `INSERT INTO dual (id, name) VALUES (gen_random_uuid()), $1) ON CONFLICT (name) DO NOTHING`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := freshInsertColumns(tc.sql)["id"]; got != tc.fresh {
				t.Fatalf("fresh ID = %t, want %t", got, tc.fresh)
			}
		})
	}
}
