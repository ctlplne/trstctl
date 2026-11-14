// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// TestNHIReviewActClaimIsOneHolderPerItemAcrossReplicasQ1L10: one review
// item's act claim has one holder across replicas, however its IDs are
// spelled; another item, campaign or tenant is not held up; the holder's
// nested projection lock reuses its tenant service session (a one-slot lock
// pool would self-deadlock otherwise); and a released claim is free again.
func TestNHIReviewActClaimIsOneHolderPerItemAcrossReplicasQ1L10(t *testing.T) {
	_ = newStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	open := func() *store.Store {
		t.Helper()
		s, err := store.Open(ctx, testDSN, store.WithPoolSizes(store.PoolSizes{Lock: 1}))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s
	}
	const (
		campaign = "1b0b3f1e-4d1c-4f38-9d0a-2f6e8c1a0001"
		item     = "1b0b3f1e-4d1c-4f38-9d0a-2f6e8c1a0002"
		other    = "1b0b3f1e-4d1c-4f38-9d0a-2f6e8c1a0003"
	)
	first, second := open(), open()
	ran := false
	acquired, err := first.WithNHIReviewActClaim(ctx, tenantA, campaign, item, func(work context.Context) error {
		ran = true
		if err := first.WithProjectionLock(work, func(context.Context) error { return nil }); err != nil {
			return err
		}
		called := false
		held, err := second.WithNHIReviewActClaim(ctx, tenantA, strings.ToUpper(campaign), strings.ToUpper(item), func(context.Context) error {
			called = true
			return nil
		})
		if err != nil || held || called {
			t.Errorf("the same item's claim was taken twice: acquired=%v called=%v err=%v", held, called, err)
		}
		for _, free := range []struct{ tenant, campaign, item string }{
			{tenantA, campaign, other}, {tenantA, other, item}, {tenantB, campaign, item},
		} {
			if held, err := second.WithNHIReviewActClaim(ctx, free.tenant, free.campaign, free.item, func(context.Context) error { return nil }); err != nil || !held {
				t.Errorf("an unrelated claim %+v was held up: acquired=%v err=%v", free, held, err)
			}
		}
		return nil
	})
	if err != nil || !acquired || !ran {
		t.Fatalf("take a free claim: acquired=%v ran=%v err=%v", acquired, ran, err)
	}
	if held, err := second.WithNHIReviewActClaim(ctx, tenantA, campaign, item, func(context.Context) error { return nil }); err != nil || !held {
		t.Fatalf("a released claim was retained: acquired=%v err=%v", held, err)
	}
}
