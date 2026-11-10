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

// G1-L1: a lease's requester is a subject, so a subject export lists the
// leases they requested, an erasure rewrites the requester in that tenant only,
// and retention keeps an ended lease's requester as a digest.
func TestDynamicSecretLeaseRequesterPrivacyG1L1(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const requester = "dana.ops@example.test"
	for _, tenant := range []string{tenantA, tenantB} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "Lease requesters"}); err != nil {
			t.Fatal(err)
		}
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO dynamic_secret_leases
				       (tenant_id, id, tenant_epoch, idempotency_key, request_binding, provider, role,
				        backend_ref, sealed_credential, state, issue_outbox_id, revocation_status,
				        issued_at, expires_at, hard_expires_at, updated_at, requested_by)
				VALUES ($1, 'lease-g1l1', 'epoch-g1l1', 'idem-g1l1', 'sha256:g1l1', 'warehouse-pg', 'readonly',
				        'trstctl_readonly_g1l1', 'sealed-g1l1'::bytea, 'active', 9101, 'none',
				        now() - interval '500 days', now() - interval '499 days', now() - interval '499 days', now(), $2)`, tenant, requester)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	exported, err := s.SelectPrivacySubjectExport(ctx, tenantA, requester)
	if err != nil || exported.Counts["dynamic_secret_leases"] != 1 {
		t.Fatalf("the requester's lease is missing from their subject export: %v %v", exported.Counts, err)
	}
	erased, err := s.SelectPrivacySubjectErasure(ctx, tenantA, requester)
	if err != nil {
		t.Fatal(err)
	}
	erased.RequestedByRef = privacy.SubjectRef(tenantA, "privacy-operator")
	erased.Reason = "requester erasure"
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.ApplyPrivacySubjectErasedTx(ctx, tx, erased) }); err != nil {
		t.Fatal(err)
	}
	requestedBy := func(tenant string) string {
		t.Helper()
		var got string
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT requested_by FROM dynamic_secret_leases WHERE tenant_id = $1 AND id = 'lease-g1l1'`, tenant).Scan(&got)
		}); err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got, want := requestedBy(tenantA), privacy.Placeholder(privacy.SubjectRef(tenantA, requester)); got != want {
		t.Fatalf("the erased tenant's lease names %q, want %q", got, want)
	}
	if got := requestedBy(tenantB); got != requester {
		t.Fatalf("an erasure in another tenant changed this tenant's requester to %q", got)
	}
	run, err := s.SelectPrivacyRetention(ctx, tenantB, "91110000-0000-4000-8000-000000000001", privacy.DefaultRetentionPolicy(), time.Now().UTC())
	if err != nil || run.Counts["dynamic_secret_leases"] != 1 {
		t.Fatalf("an ended lease's requester is missing from retention: %v %v", run.Counts, err)
	}
	run.RequestedByRef = privacy.SubjectRef(tenantB, "privacy-operator")
	if err := s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error { return s.ApplyPrivacyRetentionEnforcedTx(ctx, tx, run) }); err != nil {
		t.Fatal(err)
	}
	if got := requestedBy(tenantB); !strings.HasPrefix(got, "retained:") || strings.Contains(got, requester) {
		t.Fatalf("retention kept the lease requester as %q, want a retained digest", got)
	}
}
