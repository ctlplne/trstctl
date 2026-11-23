// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestApplicationSecretReceiptV2SchemaKeepsLegacyRowsAndChecksNewDigest(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	insert := func(tx pgx.Tx, id, v2 string) error {
		var digest any
		if v2 != "" {
			digest = v2
		}
		_, err := tx.Exec(ctx, `INSERT INTO application_secret_mutation_receipts
			(tenant_id,event_id,semantic_sha256,semantic_sha256_v2,request_binding,
			 secret_name,action,result_version,result_created_at,result_updated_at,applied_at)
			VALUES ($1,$2,$3,$4,$5,'receipt/v2','create',1,now(),now(),now())`,
			tenantA, id, strings.Repeat("a", 64), digest, strings.Repeat("b", 64))
		return err
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return insert(tx, "a7770000-0000-4000-8000-000000009501", "")
	}); err != nil {
		t.Fatalf("legacy v1-only receipt must remain readable: %v", err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return insert(tx, "a7770000-0000-4000-8000-000000009502", strings.Repeat("c", 64))
	}); err != nil {
		t.Fatalf("valid v2 receipt: %v", err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return insert(tx, "a7770000-0000-4000-8000-000000009503", strings.Repeat("C", 64))
	}); err == nil {
		t.Fatal("uppercase v2 digest bypassed lowercase hexadecimal check")
	}
}
