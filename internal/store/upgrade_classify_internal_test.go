// SPDX-License-Identifier: BUSL-1.1

package store

import "testing"

// A246-L2: the upgrade preflight counts a migration destructive by what its
// statements do, not by a word anywhere in its text. Removing rows only from
// tables the event log rebuilds (read models, their snapshots) is not
// destructive; removing any other table's rows, a CASCADE that can reach
// other tables, the independently preserved attestations, and a function body
// that would remove them later are. A keyword in a comment or a string is not
// a statement.
func TestClassifyMigrationReadsWhatAStatementRemovesA246L2(t *testing.T) {
	shipped, err := migrationFS.ReadFile("migrations/0160_purge_legacy_read_model_snapshots.sql")
	if err != nil {
		t.Fatal(err)
	}
	if destructive, _ := classifyMigration(shipped); destructive {
		t.Error("0160, which truncates only the disposable read-model snapshots, reads as destructive")
	}
	for _, tc := range []struct {
		sql         string
		destructive bool
	}{
		{"TRUNCATE TABLE read_model_snapshots;", false},
		{"truncate only read_model_snapshots restart identity;", false},
		{"TRUNCATE honey_token_readers, read_model_snapshots;", false},
		{`DELETE FROM "honey_token_readers" WHERE reads > 1000;`, false},
		{"DELETE FROM public.read_model_snapshots WHERE format_version < 22;", false},
		{"-- TRUNCATE outbox;\n/* DROP TABLE secret_store; */\nCREATE TABLE upgrade_probe (k int);", false},
		{"COMMENT ON TABLE owners IS 'never drop table owners; truncate nothing';", false},
		{"TRUNCATE outbox;", true},
		{"TRUNCATE read_model_snapshots, outbox;", true},
		{"TRUNCATE read_model_snapshots CASCADE;", true},
		{"DELETE FROM secret_store WHERE name = 'x';", true},
		{"DELETE FROM attestations WHERE false;", true},
		{"CREATE FUNCTION upgrade_probe_purge() RETURNS void LANGUAGE sql AS $$ DELETE FROM secret_store $$;", true},
		{"ALTER TABLE owners DROP COLUMN email;", true},
		{"ALTER TABLE owners ALTER COLUMN name SET NOT NULL;", true},
		{"TRUNCATE read_model_snapshots; ALTER TABLE owners RENAME COLUMN name TO title;", true},
	} {
		if destructive, _ := classifyMigration([]byte(tc.sql)); destructive != tc.destructive {
			t.Errorf("%q destructive = %v, want %v", tc.sql, destructive, tc.destructive)
		}
	}
}
