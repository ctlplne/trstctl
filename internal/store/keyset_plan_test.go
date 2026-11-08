// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// capturedQuery is one statement a store call sent, with its arguments.
type capturedQuery struct {
	sql  string
	args []any
}

// queryRecorder keeps the statements that read one table.
type queryRecorder struct {
	mu    sync.Mutex
	from  string
	calls []capturedQuery
}

func (r *queryRecorder) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, "FROM "+r.from) && strings.Contains(data.SQL, "ORDER BY") {
		r.mu.Lock()
		r.calls = append(r.calls, capturedQuery{sql: data.SQL, args: append([]any(nil), data.Args...)})
		r.mu.Unlock()
	}
	return ctx
}

func (r *queryRecorder) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (r *queryRecorder) take(t *testing.T) capturedQuery {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.calls) == 0 {
		t.Fatalf("no page query read %s", r.from)
	}
	last := r.calls[len(r.calls)-1]
	r.calls = nil
	return last
}

// A266: an inventory page sorts by the table's keyset column, so it reads
// one page of the index instead of sorting the whole tenant. The select lists
// cast id to text without an alias; a bare "ORDER BY id" resolved to that
// output column and every page of 50 sorted all rows by their text form.
// This explains the exact statements the page functions send.
func TestInventoryPagesSortByTheTableColumn(t *testing.T) {
	ctx := context.Background()
	base := newStore(t)
	const tenant = "a2660000-0000-4000-8000-0000000000aa"
	if err := base.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "keyset plans"}); err != nil {
		t.Fatal(err)
	}
	if err := base.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO owners (id, tenant_id, kind, name)
			SELECT gen_random_uuid(), $1, 'team', 'keyset team ' || g FROM generate_series(1, 2000) g`, tenant); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO identities (id, tenant_id, kind, name, owner_id)
			SELECT gen_random_uuid(), $1, 'x509_certificate', 'keyset-' || g || '.test', (SELECT id FROM owners WHERE tenant_id = $1 LIMIT 1)
			  FROM generate_series(1, 2000) g`, tenant); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO certificates (id, tenant_id, subject, sans, fingerprint, status, not_after)
			SELECT gen_random_uuid(), $1, 'CN=keyset-' || g, ARRAY['keyset-' || g || '.test'], 'keyset-fingerprint-' || g, 'active',
			       now() + make_interval(days => g % 400)
			  FROM generate_series(1, 4000) g`, tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := base.SystemPool().Exec(ctx, `ANALYZE owners; ANALYZE identities; ANALYZE certificates`); err != nil {
		t.Fatal(err)
	}

	type page struct {
		name string
		from string
		call func(*store.Store) error
	}
	soon := time.Now().Add(200 * 24 * time.Hour)
	pages := []page{
		{"certificate inventory", "certificates", func(s *store.Store) error {
			_, err := s.ListCertificatesPage(ctx, tenant, store.ZeroUUID, nil, 50, nil)
			return err
		}},
		{"expiring certificates", "certificates", func(s *store.Store) error {
			_, err := s.ListCertificatesPage(ctx, tenant, store.ZeroUUID, nil, 50, &soon)
			return err
		}},
		{"identities", "identities", func(s *store.Store) error {
			_, err := s.ListIdentitiesPage(ctx, tenant, store.ZeroUUID, 50)
			return err
		}},
		{"owners", "owners", func(s *store.Store) error {
			_, err := s.ListOwnersPage(ctx, tenant, store.ZeroUUID, 50)
			return err
		}},
	}
	for _, p := range pages {
		t.Run(p.name, func(t *testing.T) {
			rec := &queryRecorder{from: p.from}
			traced, err := store.Open(ctx, testDSN, store.WithQueryTracer(rec))
			if err != nil {
				t.Fatal(err)
			}
			defer traced.Close()
			if err := p.call(traced); err != nil {
				t.Fatal(err)
			}
			q := rec.take(t)
			var plan []string
			if err := base.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
				rows, err := tx.Query(ctx, "EXPLAIN "+q.sql, q.args...)
				if err != nil {
					return err
				}
				defer rows.Close()
				for rows.Next() {
					var line string
					if err := rows.Scan(&line); err != nil {
						return err
					}
					plan = append(plan, line)
				}
				return rows.Err()
			}); err != nil {
				t.Fatal(err)
			}
			for _, line := range plan {
				if strings.Contains(line, "Sort Key:") && strings.Contains(line, "::text") {
					t.Fatalf("the %s page sorts by a text cast, not the table column:\n%s", p.name, strings.Join(plan, "\n"))
				}
			}
		})
	}
}
