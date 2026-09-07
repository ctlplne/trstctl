// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// The delegation bootstrap can time-box a grant: a grant whose expires_at is in
// the past never authorizes, while a future one does, and both use the same
// enforcement the API expiry and revocation use.
func TestBootstrapGrantHonorsExpiry(t *testing.T) {
	ctx := context.Background()
	st := openProviderStore(t)
	truncateProviderAuthority(t, st)

	insert := func(operatorID, expr string, expires *time.Time) {
		t.Helper()
		if _, err := st.SystemPool().Exec(ctx,
			`INSERT INTO provider_operator_delegations
			 (tenant_id, operator_id, customer_tenant_id, operation, granted_by, granted_at, source, expires_at, revoked_at, revoked_by)
			 VALUES ($1, $2, $3, 'read', 'platform-admin', now(), 'legacy_local_command', $4, NULL, '')`,
			providerAuthorityTenant, operatorID, CustomerID("acme"), expires); err != nil {
			t.Fatalf("seed %s grant: %v", expr, err)
		}
	}
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	insert("op-live", "future", &future)
	insert("op-expired", "past", &past)

	source := NewPGDelegationSource(st)
	set, err := source.Delegations(ctx)
	if err != nil {
		t.Fatalf("read delegations: %v", err)
	}
	if err := set.Authorize(Operator{ID: "op-live", Email: "live@x", Role: OperatorOperator, MFA: true}, CustomerID("acme"), OpRead); err != nil {
		t.Fatalf("a future-dated grant must authorize: %v", err)
	}
	if err := set.Authorize(Operator{ID: "op-expired", Email: "expired@x", Role: OperatorOperator, MFA: true}, CustomerID("acme"), OpRead); err == nil {
		t.Fatal("an expired grant must not authorize; the Delegations query must filter expires_at <= now()")
	}
	// The row is retained as evidence even though it no longer authorizes.
	var retained int
	if err := st.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM provider_operator_delegations WHERE operator_id = 'op-expired'`).Scan(&retained); err != nil && err != pgx.ErrNoRows {
		t.Fatalf("count expired grant: %v", err)
	}
	if retained != 1 {
		t.Fatalf("expired grant rows = %d, want it retained as evidence", retained)
	}
}
