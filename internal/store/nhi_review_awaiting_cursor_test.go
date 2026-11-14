// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// TestNHIReviewAwaitingCursorOrdersAsTheListingQ1L4: a cursor orders as the
// awaiting-closure listing does (decision time, then campaign, then item, the
// UUIDs as PostgreSQL sorts them), and the zero cursor is the start.
func TestNHIReviewAwaitingCursorOrdersAsTheListingQ1L4(t *testing.T) {
	at := time.Date(2026, 11, 14, 9, 0, 0, 123000, time.UTC)
	decided := at.Add(time.Microsecond)
	base := store.NHIReviewAwaitingCursorAt(store.NHIReviewItem{
		CampaignID: "1b0b3f1e-4d1c-4f38-9d0a-2f6e8c1a0001", ItemID: "1b0b3f1e-4d1c-4f38-9d0a-2f6e8c1a00ff", DecidedAt: &at,
	})
	ordered := []store.NHIReviewAwaitingCursor{
		base,
		{At: at, CampaignID: base.CampaignID, ItemID: "1b0b3f1e-4d1c-4f38-9d0a-2f6e8c1a0a00"},
		{At: at, CampaignID: "1b0b3f1e-4d1c-4f38-9d0a-2f6e8c1a000a", ItemID: "00000000-0000-4000-8000-000000000001"},
		store.NHIReviewAwaitingCursorAt(store.NHIReviewItem{CampaignID: "00000000-0000-4000-8000-000000000001", ItemID: base.ItemID, DecidedAt: &decided}),
	}
	for i, a := range ordered {
		for j, b := range ordered {
			if got, want := a.Before(b), i < j; got != want {
				t.Fatalf("cursor %d before %d = %v, want %v", i, j, got, want)
			}
		}
	}
	if base.IsZero() || !(store.NHIReviewAwaitingCursor{}).IsZero() {
		t.Fatal("IsZero does not mark only the start")
	}
	undecided := store.NHIReviewAwaitingCursorAt(store.NHIReviewItem{CampaignID: base.CampaignID, ItemID: base.ItemID, CreatedAt: decided})
	if !undecided.At.Equal(decided) {
		t.Fatalf("an item without a decision time is placed at %s, want its creation %s", undecided.At, decided)
	}
}
