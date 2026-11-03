// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenancy"
)

// Tenant admission reads its four conditions — a registered tenant, no
// inactive provider record, no provider suspension pending or in force, no
// erasure pending — in one statement instead of four, and each refusal names
// its own reason, in the order the conditions were always checked.
func TestTenantAdmissionIsOneStatementAndNamesEachRefusal(t *testing.T) {
	base := newStore(t)
	seedTwoTenants(t, base)
	ctx := t.Context()
	pool := base.SystemPool()
	clean := func() {
		for _, sql := range []string{
			`DELETE FROM provider_tenants WHERE tenant_id = ANY($1::uuid[])`,
			`DELETE FROM provider_suspend_commands WHERE tenant_id = ANY($1::uuid[])`,
		} {
			if _, err := pool.Exec(context.Background(), sql, []string{tenantA, tenantB}); err != nil {
				t.Fatal(err)
			}
		}
	}
	clean()
	t.Cleanup(clean)

	tracer := &setupTracer{}
	s, err := store.Open(ctx, testDSN, store.WithQueryTracer(tracer))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	tracer.take()
	if err := s.RequireLiveTenantService(ctx, tenantA); err != nil {
		t.Fatalf("a live tenant was refused: %v", err)
	}
	sent := tracer.take()
	if len(sent) != 3 || sent[2] != "commit" {
		t.Fatalf("admission sent %d messages %q; want the setup, one statement, commit", len(sent), sent)
	}
	for _, table := range []string{"FROM tenants", "provider_tenants", "provider_suspend_commands", "idempotency_keys"} {
		if !strings.Contains(sent[1], table) {
			t.Fatalf("the admission statement %q does not read %s", sent[1], table)
		}
	}

	refused := func(name, tenantID, reason string) {
		t.Helper()
		err := s.RequireLiveTenantService(ctx, tenantID)
		if !errors.Is(err, tenancy.ErrServiceUnavailable) || tenancy.RefusalReason(err) != reason {
			t.Errorf("%s: %v (reason %q); want ErrServiceUnavailable naming %q", name, err, tenancy.RefusalReason(err), reason)
		}
		// Callers answer with the error's text; it must not change with the
		// condition, so it is ErrServiceUnavailable's exactly.
		if err != nil && err.Error() != tenancy.ErrServiceUnavailable.Error() {
			t.Errorf("%s: the refusal reads %q; want %q, the same for every condition", name, err.Error(), tenancy.ErrServiceUnavailable.Error())
		}
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	refused("unregistered", "33333333-3333-3333-3333-333333333333", "the tenant is not registered")

	exec(`INSERT INTO provider_tenants (tenant_id,slug,name,status,created_at,updated_at) VALUES ($1,'admission','Admission','suspended',now(),now())`, tenantA)
	refused("provider record not active", tenantA, "the tenant's provider record is not active")

	exec(`INSERT INTO provider_suspend_commands (tenant_id,event_id,event_time,status,projected_sequence) VALUES ($1,'admission-suspend',now(),'completed',1)`, tenantB)
	refused("provider suspension", tenantB, "a provider suspension is pending or in force")
	clean()

	exec(`INSERT INTO idempotency_keys (tenant_id,key,status,request_binding) VALUES ($1,$2,'pending','')`, tenantA, store.TenantOffboardReceiverKeyPrefix+"admission")
	refused("erasure pending", tenantA, "the tenant's erasure is pending")

	// With two conditions true, the earlier one names the refusal.
	exec(`INSERT INTO provider_tenants (tenant_id,slug,name,status,created_at,updated_at) VALUES ($1,'admission','Admission','offboarded',now(),now())`, tenantA)
	refused("restricted and erasing", tenantA, "the tenant's provider record is not active")
	if err := s.RequireLiveTenantService(ctx, tenantB); err != nil {
		t.Fatalf("another tenant was refused: %v", err)
	}
}
