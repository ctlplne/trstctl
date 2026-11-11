// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

// Q6-L3: a decoy's reader is a subject. A subject export lists the decoys
// they triggered; an erasure clears them from the decoy's first reader and
// from the text of their alerts in the outbox, in that tenant only, and
// leaves another reader's alert as it was.
func TestDecoySecretReaderPrivacyQ6L3(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const reader, other = "erin.contractor@example.test", "ci-runner-7"
	decoyID := map[string]string{tenantA: "c6130000-0000-4000-8000-000000000001", tenantB: "c6130000-0000-4000-8000-000000000002"}
	now := time.Now().UTC()
	for _, tenant := range []string{tenantA, tenantB} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "Decoy readers"}); err != nil {
			t.Fatal(err)
		}
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			if err := s.ApplyHoneyTokenCreatedTx(ctx, tx, store.HoneyToken{ID: decoyID[tenant], TenantID: tenant, Name: "payments bait", // #nosec G101 -- a decoy names a fabricated test secret, no credential value (CWE-798)
				Placement: "payments repo .env.example", SecretName: "prod/payments/db-password", CreatedAt: now}); err != nil {
				return err
			}
			if err := s.ApplyDecoySecretReadTx(ctx, tx, tenant, decoyID[tenant], reader, "GET", "/api/v1/secrets/store/prod/payments/db-password", now); err != nil {
				return err
			}
			return s.ApplyDecoySecretReadTx(ctx, tx, tenant, decoyID[tenant], other, "GET", "/api/v1/secrets/store/prod/payments/db-password", now)
		}); err != nil {
			t.Fatal(err)
		}
	}
	exported, err := s.SelectPrivacySubjectExport(ctx, tenantA, reader)
	if err != nil || exported.Counts["honey_tokens"] != 1 {
		t.Fatalf("the decoy the reader triggered is missing from their subject export: %v %v", exported.Counts, err)
	}
	erased, err := s.SelectPrivacySubjectErasure(ctx, tenantA, reader)
	if err != nil {
		t.Fatal(err)
	}
	erased.RequestedByRef = privacy.SubjectRef(tenantA, "privacy-operator")
	erased.Reason = "reader erasure"
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.ApplyPrivacySubjectErasedTx(ctx, tx, erased) }); err != nil {
		t.Fatal(err)
	}
	placeholder := privacy.Placeholder(privacy.SubjectRef(tenantA, reader))
	state := func(tenant string) (string, []string) {
		t.Helper()
		var trigger string
		var details []string
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			if err := tx.QueryRow(ctx, `SELECT trigger_subject FROM honey_tokens WHERE tenant_id = $1 AND id = $2`, tenant, decoyID[tenant]).Scan(&trigger); err != nil {
				return err
			}
			rows, err := tx.Query(ctx, `SELECT convert_from(payload, 'UTF8')::jsonb->>'detail' FROM outbox
			                             WHERE tenant_id = $1 AND destination = 'notification.honeytoken' ORDER BY id`, tenant)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var detail string
				if err := rows.Scan(&detail); err != nil {
					return err
				}
				details = append(details, detail)
			}
			return rows.Err()
		}); err != nil {
			t.Fatal(err)
		}
		return trigger, details
	}
	trigger, details := state(tenantA)
	if trigger != placeholder {
		t.Fatalf("the erased tenant's decoy names its first reader %q, want %q", trigger, placeholder)
	}
	if len(details) != 2 || strings.Contains(details[0], reader) || !strings.Contains(details[0], "was read by "+placeholder+" (GET ") ||
		!strings.Contains(details[1], "was read by "+other+" (GET ") {
		t.Fatalf("alerts after the erasure = %q, want the reader replaced by %q and the other reader kept", details, placeholder)
	}
	if trigger, details := state(tenantB); trigger != reader || len(details) != 2 || !strings.Contains(details[0], reader) {
		t.Fatalf("an erasure in another tenant changed this tenant's decoy: %q %q", trigger, details)
	}
}

// Q6-L1: a secret decoy keeps its readers as one-way references with their
// reads. A subject's export lists every decoy they read, first or later, with
// their own reads and nothing of the first reader when that is someone else.
// An erasure moves their reader row to their placeholder's reference: the
// decoy keeps its reader and read counts, and the row is the one a rebuild
// reaches, since the erasure rewrites the reader of their read events to that
// placeholder.
func TestDecoySecretReadersFollowExportAndErasureQ6L1(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const first, later = "q6l1-first-reader", "q6l1-later-reader@example.test"
	const live, replayed = "c6110000-0000-4000-8000-000000000001", "c6110000-0000-4000-8000-000000000002"
	const path = "/api/v1/secrets/store/prod/payments/db-password"
	now := time.Now().UTC().Truncate(time.Microsecond)
	placeholder := privacy.Placeholder(privacy.SubjectRef(tenantA, later))
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Decoy readers"}); err != nil {
		t.Fatal(err)
	}
	// The live decoy is read by the first reader once and the later reader
	// twice; the replayed decoy gets the same reads as a rebuild after the
	// later reader's erasure would apply them, under the placeholder.
	plant := func(id, laterAs string) {
		t.Helper()
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			if err := s.ApplyHoneyTokenCreatedTx(ctx, tx, store.HoneyToken{ID: id, TenantID: tenantA, Name: "payments bait", // #nosec G101 -- a decoy names a fabricated test secret, no credential value (CWE-798)
				Placement: "payments repo .env.example", SecretName: "prod/payments/db-password", CreatedAt: now}); err != nil {
				return err
			}
			for i, reader := range []string{first, laterAs, laterAs} {
				if err := s.ApplyDecoySecretReadTx(ctx, tx, tenantA, id, reader, "GET", path, now.Add(time.Duration(i)*time.Minute)); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	plant(live, later)
	plant(replayed, placeholder)
	readers := func(id string) map[string]string {
		t.Helper()
		out := map[string]string{}
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT reader_ref, first_read_at, last_read_at, reads FROM honey_token_readers
			                             WHERE tenant_id = $1 AND honey_token_id = $2`, tenantA, id)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var ref string
				var firstAt, lastAt time.Time
				var reads int64
				if err := rows.Scan(&ref, &firstAt, &lastAt, &reads); err != nil {
					return err
				}
				out[ref] = firstAt.UTC().Format(time.RFC3339Nano) + " " + lastAt.UTC().Format(time.RFC3339Nano) + " " + strconv.FormatInt(reads, 10)
			}
			return rows.Err()
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := readers(live); len(got) != 2 || !strings.HasSuffix(got[privacy.SubjectRef(tenantA, later)], " 2") ||
		!strings.HasSuffix(got[privacy.SubjectRef(tenantA, first)], " 1") {
		t.Fatalf("the live decoy's readers = %v, want the first reader once and the later reader twice by reference", got)
	}

	exported, err := s.SelectPrivacySubjectExport(ctx, tenantA, later)
	if err != nil || exported.Counts["honey_tokens"] != 1 {
		t.Fatalf("the decoy the later reader read is missing from their export: %v %v", exported.Counts, err)
	}
	for _, record := range exported.ReadModels {
		if record.Table != "honey_tokens" {
			continue
		}
		if record.ID != live || !strings.Contains(record.Data, `"reads": 2`) || strings.Contains(record.Data, first) {
			t.Fatalf("the later reader's export of the decoy = %s %s, want their two reads and nothing of the first reader", record.ID, record.Data)
		}
	}
	if exported, err := s.SelectPrivacySubjectExport(ctx, tenantA, first); err != nil || exported.Counts["honey_tokens"] != 2 {
		t.Fatalf("the first reader's export lists %v decoys (%v), want both", exported.Counts, err)
	}

	erased, err := s.SelectPrivacySubjectErasure(ctx, tenantA, later)
	if err != nil {
		t.Fatal(err)
	}
	erased.RequestedByRef = privacy.SubjectRef(tenantA, "privacy-operator")
	erased.Reason = "reader erasure"
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.ApplyPrivacySubjectErasedTx(ctx, tx, erased) }); err != nil {
		t.Fatal(err)
	}
	after := readers(live)
	if _, ok := after[privacy.SubjectRef(tenantA, later)]; ok || len(after) != 2 {
		t.Fatalf("after the erasure the live decoy's readers = %v, want the later reader moved off their reference", after)
	}
	if want := readers(replayed); !reflect.DeepEqual(after, want) {
		t.Fatalf("after the erasure the live decoy's readers = %v, want what a rebuild reaches %v", after, want)
	}
	if exported, err := s.SelectPrivacySubjectExport(ctx, tenantA, later); err != nil || exported.Counts["honey_tokens"] != 0 {
		t.Fatalf("after the erasure the later reader's export lists %v decoys (%v)", exported.Counts, err)
	}
}
