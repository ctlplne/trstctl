// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/store"
)

func TestCertificateBindingsPreserveCanonicalIdentityText(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const owner = "21800000-0000-4000-8000-000000000011"
	const identity = "abcdef00-abcd-4abc-8abc-abcdefabcdef"
	const otherKind = "abcdef00-abcd-4abc-8abc-abcdefabcdee"
	for _, tenant := range []string{tenantA, tenantB} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "exact text"}); err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertOwner(ctx, store.Owner{ID: owner, TenantID: tenant, Kind: store.OwnerService, Name: "owner"}); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{identity, otherKind} {
			kind := store.KindX509Certificate
			if id == otherKind {
				kind = "api_key"
			}
			if err := s.UpsertIdentity(ctx, store.Identity{ID: id, TenantID: tenant, OwnerID: owner, Name: "same.example", Kind: kind, Status: "deployed", Attributes: []byte(`{}`)}); err != nil {
				t.Fatal(err)
			}
		}
	}
	cases := []struct {
		name, text, tenant string
		want               bool
	}{
		{"canonical", identity, tenantA, true},
		{"uppercase", strings.ToUpper(identity), tenantA, false},
		{"no_hyphens", strings.ReplaceAll(identity, "-", ""), tenantA, false},
		{"braces", "{" + identity + "}", tenantA, false},
		{"space", identity + " ", tenantA, false},
		{"invalid", "not-a-uuid", tenantA, false},
		{"foreign_tenant", identity, tenantB, false},
		{"other_credential_kind", otherKind, tenantA, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := "canonical-text-" + tc.name
			cert, err := s.UpsertCertificate(ctx, store.Certificate{TenantID: tenantA, OwnerID: &[]string{owner}[0], Subject: "CN=same.example", Fingerprint: "fp-" + key, IssuanceIdempotencyKey: "issue:" + key, Source: "import"})
			if err != nil {
				t.Fatal(err)
			}
			payload, err := json.Marshal(map[string]string{"identity_id": tc.text})
			if err != nil {
				t.Fatal(err)
			}
			if err := s.WithTenant(ctx, tc.tenant, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `INSERT INTO outbox(tenant_id,destination,payload,idempotency_key) VALUES($1,'ca.issue',$2,$3)`, tc.tenant, payload, key)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			got, err := s.CertificateIdentityBindings(ctx, tenantA, []string{cert.ID})
			if err != nil {
				t.Fatal(err)
			}
			if tc.want {
				if fmt.Sprint(got[cert.ID]) != fmt.Sprint([]string{identity}) {
					t.Fatalf("canonical binding=%v", got)
				}
			} else if len(got) != 0 {
				t.Fatalf("noncanonical or unauthorized identity gained binding: %v", got)
			}
		})
	}
}
