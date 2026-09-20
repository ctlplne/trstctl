// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"testing"
)

func TestNotificationNewestPageRemainsStableWhileAlertsArrive(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	seedAgentJobTenant(t, ctx, s, tenantA)
	seedAgentJobTenant(t, ctx, s, tenantB)
	seedJobs(t, ctx, s, tenantA, 101, "notification.expiry")
	seedJobs(t, ctx, s, tenantB, 3, "notification.expiry")
	oldest, err := s.ListNotificationOutboxPage(ctx, tenantA, 0, 1, "")
	if err != nil || len(oldest) != 1 {
		t.Fatalf("legacy ascending page: %d %v", len(oldest), err)
	}
	page, err := s.ListNotificationOutboxPageWithOrder(ctx, tenantA, 0, 100, "", true)
	if err != nil || len(page) != 100 {
		t.Fatalf("newest page: %d %v", len(page), err)
	}
	for i, row := range page {
		if row.TenantID != tenantA || row.ID == oldest[0].ID || (i > 0 && row.ID >= page[i-1].ID) {
			t.Fatalf("not tenant-bound newest-first: %+v", row)
		}
	}
	// A new alert must lead the next refresh, without shifting the cursor for
	// the older page or causing a duplicate/missing row across these pages.
	seedJobs(t, ctx, s, tenantA, 1, "notification.expiry")
	older, err := s.ListNotificationOutboxPageWithOrder(ctx, tenantA, page[len(page)-1].ID, 100, "", true)
	if err != nil || len(older) != 1 || older[0].ID != oldest[0].ID {
		t.Fatalf("older cursor shifted: %+v err=%v", older, err)
	}
	latest, err := s.ListNotificationOutboxPageWithOrder(ctx, tenantA, 0, 1, "", true)
	if err != nil || len(latest) != 1 || latest[0].ID <= page[0].ID {
		t.Fatalf("new warning hidden: %+v err=%v", latest, err)
	}
	filtered, err := s.ListNotificationOutboxPageWithOrder(ctx, tenantA, 0, 100, "dead", true)
	if err != nil || len(filtered) != 0 {
		t.Fatalf("status filter lost: count=%d err=%v", len(filtered), err)
	}
}
