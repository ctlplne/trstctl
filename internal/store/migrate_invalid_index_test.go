// SPDX-License-Identifier: MPL-2.0

package store

import (
	"strings"
	"testing"
)

// TestConcurrentIndexNamesIgnoreProse is the regression guard for the parser
// half of the invalid-index check.
//
// These migrations explain themselves in comments, and 0113 literally says
// "CREATE INDEX CONCURRENTLY cannot run inside a transaction". Matched naively,
// that prose reads as a statement and the checker goes hunting for an index
// named "cannot" — which it will never find, failing every migration run.
func TestConcurrentIndexNamesIgnoreProse(t *testing.T) {
	body := `-- online-safe: CONCURRENTLY, so building it does not take a lock.
-- Separate from 0112 because CREATE INDEX CONCURRENTLY cannot run inside a
-- transaction block.
CREATE INDEX CONCURRENTLY IF NOT EXISTS owners_unattested_idx
    ON owners (tenant_id) WHERE attested_at IS NULL;
CREATE UNIQUE INDEX CONCURRENTLY delegations_identity_idx
    ON provider_operator_delegations (tenant_id, operator_id);
`
	got := createIndexConcurrentlyNames.FindAllStringSubmatch(stripSQLLineComments(body), -1)
	var names []string
	for _, m := range got {
		names = append(names, m[1])
	}
	want := []string{"owners_unattested_idx", "delegations_identity_idx"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("extracted %v, want %v; commented-out prose was read as SQL", names, want)
	}
}

// TestStripSQLLineCommentsKeepsStatements pins the stripper: it must remove
// commentary without eating the statements around it.
func TestStripSQLLineCommentsKeepsStatements(t *testing.T) {
	got := stripSQLLineComments("SELECT 1; -- trailing\n-- whole line\nSELECT 2;\n")
	if strings.Contains(got, "trailing") || strings.Contains(got, "whole line") {
		t.Errorf("comments survived stripping: %q", got)
	}
	if !strings.Contains(got, "SELECT 1;") || !strings.Contains(got, "SELECT 2;") {
		t.Errorf("statements were lost: %q", got)
	}
}

// TestEveryShippedConcurrentIndexIsNamed walks the real migrations and asserts
// the checker can extract a name from every CONCURRENTLY build we ship. If it
// cannot, that index would silently skip verification.
func TestEveryShippedConcurrentIndexIsNamed(t *testing.T) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		sql := stripSQLLineComments(string(body))
		lowered := strings.ToLower(sql)
		occurrences := strings.Count(lowered, "concurrently")
		if occurrences == 0 {
			continue
		}
		// Only CREATE INDEX CONCURRENTLY is our concern; DROP INDEX CONCURRENTLY
		// leaves nothing to verify.
		creates := strings.Count(lowered, "index concurrently") - strings.Count(lowered, "drop index concurrently")
		matches := createIndexConcurrentlyNames.FindAllStringSubmatch(sql, -1)
		if len(matches) != creates {
			t.Errorf("%s: extracted %d index names from %d CREATE ... CONCURRENTLY statements; "+
				"an unmatched one would skip the post-migration validity check", e.Name(), len(matches), creates)
		}
		if !migrationNoTransaction(body) && creates > 0 {
			t.Errorf("%s builds an index CONCURRENTLY but lacks the `-- migrate: no-transaction` marker, "+
				"so the runner would wrap it in a transaction and PostgreSQL would reject it", e.Name())
		}
		checked += creates
	}
	if checked == 0 {
		t.Fatal("no shipped CONCURRENTLY index builds found; this guard is not testing anything")
	}
	t.Logf("verified %d shipped CONCURRENTLY index builds are name-extractable and marked no-transaction", checked)
}
