// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// M4-L2: each tenant holds at most its limit of live single-use login
// records. A new token past the limit is refused with the time the oldest
// record expires, and is not recorded; a replayed token is still a replay, not
// a limit; another tenant is unaffected; and once the oldest record expires
// the next new token is recorded.
func TestMachineCredentialUseIsCappedPerTenantM4L2(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	const tenantID, otherTenant = "a4021000-0000-4000-8b01-000000000000", "a4021000-0000-4000-8b02-000000000000"
	seedTenant(t, s, tenantID)
	seedTenant(t, s, otherTenant)
	soon, later := time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	use := func(tenant, key string, expires time.Time) (bool, error) {
		t.Helper()
		return s.FirstMachineCredentialUse(ctx, tenant, "jwt", key, expires, 2)
	}
	for _, key := range []string{"m4l2-first", "m4l2-second"} {
		expires := later
		if key == "m4l2-first" {
			expires = soon
		}
		if first, err := use(tenantID, key, expires); err != nil || !first {
			t.Fatalf("%s = %v %v; want a first use", key, first, err)
		}
	}
	if first, err := use(tenantID, "m4l2-first", later); err != nil || first {
		t.Fatalf("a replay at the limit = %v %v; want a replay, not a limit", first, err)
	}
	first, err := use(tenantID, "m4l2-third", later)
	var full *store.SingleUseLimitError
	if first || !errors.Is(err, store.ErrSingleUseLimitReached) || !errors.As(err, &full) || full.Limit != 2 || !full.RetryAt.Equal(soon) {
		t.Fatalf("a third token = %v %v; want the limit with the oldest expiry %s", first, err, soon)
	}
	if first, err := use(otherTenant, "m4l2-third", later); err != nil || !first {
		t.Fatalf("another tenant = %v %v; want its own records", first, err)
	}
	if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE machine_credential_replays SET expires_at = now() - interval '1 second'
			WHERE tenant_id = $1 AND key_digest = 'm4l2-first'`, tenantID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if first, err := use(tenantID, "m4l2-third", later); err != nil || !first {
		t.Fatalf("after the oldest record expired = %v %v; want a first use", first, err)
	}
	if first, err := s.FirstMachineCredentialUse(ctx, tenantID, "jwt", "m4l2-unlimited", later, 0); err != nil || !first {
		t.Fatalf("limit 0 = %v %v; want no limit", first, err)
	}
}
