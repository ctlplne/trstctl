// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// G2-L3: an unchanged read of a lease's access stamps the recorded
// observation instead of recording another. The stamp lands only on the
// observation it names and only moves forward, and an observation recorded
// meanwhile starts with no stamp, so a stale read never dates a newer one.
func TestRecheckStampsOnlyTheRecordedObservationG2L3(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Lease access"}); err != nil {
		t.Fatal(err)
	}
	const lease = "lease-g2l3"
	apply := func(sequence uint64, at time.Time, status, reason string) {
		t.Helper()
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyDynamicSecretLeaseAccessTx(ctx, tx, store.DynamicSecretLeaseAccess{TenantID: tenantA, LeaseID: lease,
				Provider: "aws-deploy", Status: status, Reason: reason, Grants: []string{"inline policy g2l3"}, CheckedAt: at}, sequence)
		}); err != nil {
			t.Fatal(err)
		}
	}
	read := func() store.DynamicSecretLeaseAccess {
		t.Helper()
		got, err := s.DynamicSecretLeaseAccessFor(ctx, tenantA, []string{lease})
		if err != nil {
			t.Fatal(err)
		}
		return got[lease]
	}
	recordedAt := time.Now().UTC().Add(-7 * time.Hour).Truncate(time.Microsecond)
	apply(1, recordedAt, store.DynamicSecretAccessResolved, "")
	now := time.Now().UTC().Truncate(time.Microsecond)
	if stamped, err := s.RecheckDynamicSecretLeaseAccess(ctx, tenantA, lease, recordedAt, now); err != nil || !stamped {
		t.Fatalf("stamping the recorded observation = %v %v", stamped, err)
	}
	if a := read(); !a.CheckedAt.Equal(recordedAt) || a.RecheckedAt == nil || !a.RecheckedAt.Equal(now) || !a.LastRead().Equal(now) {
		t.Fatalf("after the stamp the access = recorded %v, rechecked %v, last read %v", a.CheckedAt, a.RecheckedAt, a.LastRead())
	}
	if stamped, err := s.RecheckDynamicSecretLeaseAccess(ctx, tenantA, lease, recordedAt, now.Add(-time.Minute)); err != nil || stamped {
		t.Fatalf("an older stamp moved the last read back: %v %v", stamped, err)
	}

	changedAt := now.Add(time.Second)
	apply(2, changedAt, store.DynamicSecretAccessUnknown, "access_denied")
	if a := read(); a.RecheckedAt != nil || !a.LastRead().Equal(changedAt) {
		t.Fatalf("a newly recorded observation kept the old stamp: rechecked %v", a.RecheckedAt)
	}
	if stamped, err := s.RecheckDynamicSecretLeaseAccess(ctx, tenantA, lease, recordedAt, now.Add(2*time.Second)); err != nil || stamped {
		t.Fatalf("a read of the replaced observation stamped the new one: %v %v", stamped, err)
	}
}
