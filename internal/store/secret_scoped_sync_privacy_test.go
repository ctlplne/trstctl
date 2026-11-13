// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"strings"
	"testing"
	"time"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

// A237-L5: a subject's erasure rewrites the segments of a scoped sync's secret
// names that are exactly the subject — the source and destination prefixes,
// each managed key and its source name, each queued delete — to the subject's
// placeholder, in that tenant only. A subject that holds a separator
// ("jean-luc") is found whole; a longer segment that merely starts with it
// ("jean-lucy") and the definition's name stay as written. The subject's
// export lists the sync.
func TestScopedSyncSecretNamesAreErasedA237L5(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const subject = "jean-luc"
	syncID := map[string]string{tenantA: "a2375000-0000-4000-8000-000000000001", tenantB: "a2375000-0000-4000-8000-000000000002"}
	now := time.Now().UTC()
	for _, tenant := range []string{tenantA, tenantB} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "A237-L5 scoped sync privacy"}); err != nil {
			t.Fatal(err)
		}
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			if err := s.ApplySecretScopedSyncDefinedTx(ctx, tx, tenant, store.SecretScopedSync{
				ID: syncID[tenant], Name: "people-sync", SourcePrefix: "teams/jean-luc/", Target: "vault",
				DestinationPrefix: "people/jean-luc", KeyTransform: "path", DeleteScope: "managed", UpdatedAt: now,
			}, 1); err != nil {
				return err
			}
			if err := s.ApplySecretScopedSyncAppliedTx(ctx, tx, tenant, "epoch", syncID[tenant], "vault", strings.Repeat("a", 64),
				[]store.SecretScopedSyncApplyItem{
					{RemoteKey: "people/jean-luc/db", SourceName: "teams/jean-luc/db", SourceVersion: 1, Action: "create", JobID: "job-1"},
					{RemoteKey: "people/jean-luc/old", SourceName: "teams/jean-luc/old", SourceVersion: 1, Action: "create", JobID: "job-2"},
					{RemoteKey: "people/shared/jean-lucy", SourceName: "teams/shared/jean-lucy", SourceVersion: 1, Action: "create", JobID: "job-3"},
				}, now, 2); err != nil {
				return err
			}
			return s.ApplySecretScopedSyncAppliedTx(ctx, tx, tenant, "epoch", syncID[tenant], "vault", strings.Repeat("b", 64),
				[]store.SecretScopedSyncApplyItem{{RemoteKey: "people/jean-luc/old", Action: "delete", DeleteID: googleuuid.NewString()}}, now, 3)
		}); err != nil {
			t.Fatal(err)
		}
	}

	exported, err := s.SelectPrivacySubjectExport(ctx, tenantA, subject)
	if err != nil || exported.Counts["secret_scoped_syncs"] != 1 {
		t.Fatalf("the sync naming the subject is missing from their export: %v %v", exported.Counts, err)
	}
	erased, err := s.SelectPrivacySubjectErasure(ctx, tenantA, subject)
	if err != nil {
		t.Fatal(err)
	}
	erased.RequestedByRef = privacy.SubjectRef(tenantA, "privacy-operator")
	erased.Reason = "scoped sync erasure"
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.ApplyPrivacySubjectErasedTx(ctx, tx, erased) }); err != nil {
		t.Fatal(err)
	}
	ph := privacy.Placeholder(privacy.SubjectRef(tenantA, subject))

	type state struct {
		name, source, destination string
		keys                      map[string]string
		deletes                   []string
	}
	read := func(tenant string) state {
		t.Helper()
		st := state{keys: map[string]string{}}
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			if err := tx.QueryRow(ctx, `SELECT name, source_prefix, destination_prefix FROM secret_scoped_syncs WHERE tenant_id = $1 AND id = $2`,
				tenant, syncID[tenant]).Scan(&st.name, &st.source, &st.destination); err != nil {
				return err
			}
			rows, err := tx.Query(ctx, `SELECT remote_key, source_name FROM secret_scoped_sync_keys WHERE tenant_id = $1 AND sync_id = $2`, tenant, syncID[tenant])
			if err != nil {
				return err
			}
			for rows.Next() {
				var k, src string
				if err := rows.Scan(&k, &src); err != nil {
					rows.Close()
					return err
				}
				st.keys[k] = src
			}
			rows.Close()
			rows, err = tx.Query(ctx, `SELECT remote_key FROM secret_scoped_sync_deletes WHERE tenant_id = $1 AND sync_id = $2`, tenant, syncID[tenant])
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var k string
				if err := rows.Scan(&k); err != nil {
					return err
				}
				st.deletes = append(st.deletes, k)
			}
			return rows.Err()
		}); err != nil {
			t.Fatal(err)
		}
		return st
	}
	a := read(tenantA)
	if a.name != "people-sync" || a.source != "teams/"+ph+"/" || a.destination != "people/"+ph {
		t.Fatalf("tenant A definition after erasure = %+v", a)
	}
	wantKeys := map[string]string{
		"people/" + ph + "/db": "teams/" + ph + "/db", "people/" + ph + "/old": "teams/" + ph + "/old",
		"people/shared/jean-lucy": "teams/shared/jean-lucy",
	}
	if len(a.keys) != len(wantKeys) {
		t.Fatalf("tenant A keys = %v, want %v", a.keys, wantKeys)
	}
	for k, src := range wantKeys {
		if a.keys[k] != src {
			t.Fatalf("tenant A keys = %v, want %v", a.keys, wantKeys)
		}
	}
	if len(a.deletes) != 1 || a.deletes[0] != "people/"+ph+"/old" {
		t.Fatalf("tenant A deletes = %v", a.deletes)
	}
	b := read(tenantB)
	if b.source != "teams/jean-luc/" || b.destination != "people/jean-luc" || b.keys["people/jean-luc/db"] != "teams/jean-luc/db" ||
		len(b.deletes) != 1 || b.deletes[0] != "people/jean-luc/old" {
		t.Fatalf("tenant B changed during tenant A's erasure: %+v", b)
	}
	if again, err := s.SelectPrivacySubjectExport(ctx, tenantA, subject); err != nil || again.Counts["secret_scoped_syncs"] != 0 {
		t.Fatalf("after the erasure the subject's export still finds the sync: %v %v", again.Counts, err)
	}
}
