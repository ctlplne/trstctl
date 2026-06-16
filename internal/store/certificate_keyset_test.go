package store_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// The embedded-PostgreSQL harness (TestMain, newStore, tenantA) is shared with the
// rest of the store package's tests; these tests just reuse it.

// TestListCertificatesExpiringKeysetUsesIndex is the SPINE-006 acceptance: the
// combined "expiring before T, paginated" query must ride the (tenant_id,
// not_after, id) composite expiry index with near-zero rows discarded, instead of
// scanning the primary key and filtering (the pre-fix ORDER BY id plan). It seeds a
// large tenant, runs the expiry-ordered keyset query, and asserts via EXPLAIN
// ANALYZE that the plan uses an expiry index and removes ~no rows by filter.
func TestListCertificatesExpiringKeysetUsesIndex(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	// 5,000 rows spread across a wide validity range: only a slice expires before the
	// cutoff, so an id-ordered plan would scan the PK and discard most rows.
	for i := 0; i < 5000; i++ {
		notAfter := now.Add(time.Duration(i) * time.Hour)
		if _, err := s.UpsertCertificate(ctx, store.Certificate{
			TenantID:    tenantA,
			Subject:     fmt.Sprintf("CN=c%d", i),
			Fingerprint: fmt.Sprintf("fp-%d", i),
			NotAfter:    &notAfter,
			Source:      "issued",
		}); err != nil {
			t.Fatalf("seed cert %d: %v", i, err)
		}
	}
	if _, err := s.Pool().Exec(ctx, "ANALYZE certificates"); err != nil {
		t.Fatal(err)
	}

	// The query the store runs for an expiry-filtered first page (mirrors
	// ListCertificatesPage's expiringBefore branch).
	cutoff := now.Add(200 * time.Hour) // ~200 of 5000 rows qualify
	plan := explainCertQuery(t, s, `EXPLAIN ANALYZE
		SELECT id FROM certificates
		 WHERE tenant_id = $1 AND not_after < $2
		 ORDER BY not_after, id LIMIT 50`, tenantA, cutoff)

	// It must use an expiry/composite index, not a primary-key scan.
	usesExpiryIndex := strings.Contains(plan, "certificates_expiry_keyset_idx") ||
		strings.Contains(plan, "certificates_expiry_idx")
	if !usesExpiryIndex {
		t.Errorf("expiry-keyset query does not use an expiry index; plan:\n%s", plan)
	}
	if strings.Contains(plan, "certificates_pkey") {
		t.Errorf("expiry-keyset query still scans the primary key (the SPINE-006 defect); plan:\n%s", plan)
	}
	// And it must not discard a meaningful number of rows by filter (near-zero).
	if removed := certRowsRemovedByFilter(plan); removed > 50 {
		t.Errorf("expiry-keyset query removed %d rows by filter, want ~0 (index should serve the filter); plan:\n%s", removed, plan)
	}
}

// TestListCertificatesExpiringKeysetPaginatesCorrectly proves the composite
// (not_after, id) keyset paginates the expiry-filtered set without gaps or repeats,
// in not_after order — so the index change did not break correctness (SPINE-006).
func TestListCertificatesExpiringKeysetPaginatesCorrectly(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	const total = 25
	for i := 0; i < total; i++ {
		// Deliberately give several rows the SAME not_after so the id tie-breaker is
		// exercised (the reason the keyset is (not_after, id), not not_after alone).
		notAfter := now.Add(time.Duration(i/5) * time.Hour)
		if _, err := s.UpsertCertificate(ctx, store.Certificate{
			TenantID:    tenantA,
			Subject:     fmt.Sprintf("CN=c%d", i),
			Fingerprint: fmt.Sprintf("fp-%d", i),
			NotAfter:    &notAfter,
			Source:      "issued",
		}); err != nil {
			t.Fatalf("seed cert %d: %v", i, err)
		}
	}
	cutoff := now.Add(1000 * time.Hour) // all qualify

	seen := map[string]bool{}
	afterID := store.ZeroUUID
	var afterNotAfter *time.Time
	var lastNotAfter time.Time
	for page := 0; page < total; page++ {
		got, err := s.ListCertificatesPage(ctx, tenantA, afterID, afterNotAfter, 4, &cutoff)
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		if len(got) == 0 {
			break
		}
		for _, c := range got {
			if seen[c.ID] {
				t.Fatalf("certificate %s returned twice across pages (keyset gap/overlap)", c.ID)
			}
			seen[c.ID] = true
			if c.NotAfter != nil {
				if !lastNotAfter.IsZero() && c.NotAfter.Before(lastNotAfter) {
					t.Fatalf("rows out of not_after order: %v before %v", c.NotAfter, lastNotAfter)
				}
				lastNotAfter = *c.NotAfter
			}
		}
		last := got[len(got)-1]
		afterID = last.ID
		afterNotAfter = last.NotAfter
		if len(got) < 4 {
			break
		}
	}
	if len(seen) != total {
		t.Errorf("expiry keyset paginated %d distinct certs, want %d", len(seen), total)
	}
}

func explainCertQuery(t *testing.T, s *store.Store, sql string, args ...any) string {
	t.Helper()
	rows, err := s.Pool().Query(context.Background(), sql, args...)
	if err != nil {
		t.Fatalf("EXPLAIN: %v", err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(line)
		plan.WriteByte('\n')
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return plan.String()
}

// certRowsRemovedByFilter sums the "Rows Removed by Filter: N" counts an EXPLAIN
// ANALYZE plan reports. A near-zero total means the index served the predicate
// rather than a scan-and-discard.
func certRowsRemovedByFilter(plan string) int {
	const marker = "Rows Removed by Filter: "
	total := 0
	for _, line := range strings.Split(plan, "\n") {
		i := strings.Index(line, marker)
		if i < 0 {
			continue
		}
		rest := line[i+len(marker):]
		n := 0
		for _, r := range rest {
			if r < '0' || r > '9' {
				break
			}
			n = n*10 + int(r-'0')
		}
		total += n
	}
	return total
}
