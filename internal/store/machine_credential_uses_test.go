// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// TestMachineCredentialUsesAreCountedUpToTheMethodsLimitM4L4: a credential a
// method lets be used three times before it expires is allowed three uses and
// refused the fourth; a single-use credential is allowed one; another tenant's
// and another method's uses are their own; and a further use of a live record
// is not held to the tenant's limit of live records, while a new key is.
func TestMachineCredentialUsesAreCountedUpToTheMethodsLimitM4L4(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	const tenantID, otherTenant, fullTenant = "a4041000-0000-4000-8b01-000000000000", "a4041000-0000-4000-8b02-000000000000",
		"a4041000-0000-4000-8b03-000000000000"
	seedTenant(t, s, tenantID)
	seedTenant(t, s, otherTenant)
	seedTenant(t, s, fullTenant)
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	use := func(tenant, method, key string, maxUses int) bool {
		t.Helper()
		allowed, err := s.UseMachineCredential(ctx, tenant, method, key, expires, 100, maxUses)
		if err != nil {
			t.Fatalf("use %s/%s: %v", method, key, err)
		}
		return allowed
	}
	for i := 1; i <= 3; i++ {
		if !use(tenantID, "kubernetes", "m4l4-pod-token", 3) {
			t.Fatalf("use %d of 3 was refused", i)
		}
	}
	if use(tenantID, "kubernetes", "m4l4-pod-token", 3) {
		t.Fatal("a fourth use of a three-use credential was allowed")
	}
	if !use(tenantID, "oidc", "m4l4-ci-token", 1) || use(tenantID, "oidc", "m4l4-ci-token", 1) {
		t.Fatal("a single-use credential was not allowed exactly once")
	}
	if !use(otherTenant, "kubernetes", "m4l4-pod-token", 3) || !use(tenantID, "jwt", "m4l4-pod-token", 3) {
		t.Fatal("another tenant's or another method's use of the same key was refused")
	}
	// A tenant at its limit of one live record: a further use of the live
	// record is allowed, a new key is refused.
	for i := 1; i <= 2; i++ {
		if allowed, err := s.UseMachineCredential(ctx, fullTenant, "kubernetes", "m4l4-full-token", expires, 1, 3); err != nil || !allowed {
			t.Fatalf("use %d of a live record at the tenant's limit = %v %v; want allowed", i, allowed, err)
		}
	}
	if _, err := s.UseMachineCredential(ctx, fullTenant, "kubernetes", "m4l4-new-key", expires, 1, 3); !errors.Is(err, store.ErrSingleUseLimitReached) {
		t.Fatalf("a new key at the tenant's limit = %v; want the limit", err)
	}
}
