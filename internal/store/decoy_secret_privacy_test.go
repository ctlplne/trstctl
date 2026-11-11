// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
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
