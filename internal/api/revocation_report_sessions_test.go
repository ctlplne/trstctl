// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// A245-L2: without a containment stop, the existing-sessions facet reads the
// hosts' own session counts on the destinations that now serve a replacement:
// confirmed when every such destination was counted after the replacement's
// deploy with no connection held by an older process, pending when one is,
// and not observed when a destination was not counted (or its count was for
// another deploy, or its holders could not be read). A stop still confirms it.
func TestExistingSessionsReadTheHostsSessionCountsA245L2(t *testing.T) {
	revoked := store.Certificate{Fingerprint: "aa", RevokedAt: ptrTime(time.Unix(1000, 0))}
	at := time.Unix(2000, 0)
	replaced := func(target, print string) store.RevocationDelivery {
		return store.RevocationDelivery{Target: target, LatestStatus: "verified", LatestPrint: print}
	}
	count := func(target, print string, older, unread int) store.RevocationSessions {
		return store.RevocationSessions{Target: target, Fingerprint: print, Established: 4, HeldByOlder: older, Unattributed: unread,
			Since: at.Add(-time.Minute), CheckedAt: at}
	}
	cases := []struct {
		name  string
		ev    store.RevocationEvidence
		state string
		has   string
	}{
		{"nothing replaced", store.RevocationEvidence{Deliveries: []store.RevocationDelivery{{Target: "t1", LatestStatus: "delivered", LatestPrint: "aa"}}},
			revocationNotObserved, "not observed"},
		{"replaced, not counted", store.RevocationEvidence{Deliveries: []store.RevocationDelivery{replaced("t1", "bb")}},
			revocationNotObserved, "0 of 1"},
		{"every replacement counted clean", store.RevocationEvidence{
			Deliveries: []store.RevocationDelivery{replaced("t1", "bb"), replaced("t2", "cc")},
			Sessions:   []store.RevocationSessions{count("t1", "bb", 0, 0), count("t2", "cc", 0, 0)}},
			revocationConfirmed, "on all 2 destinations"},
		{"an older process still holds connections", store.RevocationEvidence{
			Deliveries: []store.RevocationDelivery{replaced("t1", "bb"), replaced("t2", "cc")},
			Sessions:   []store.RevocationSessions{count("t1", "bb", 0, 0), count("t2", "cc", 2, 0)}},
			revocationPending, "2 on t2"},
		{"a count for another deploy", store.RevocationEvidence{
			Deliveries: []store.RevocationDelivery{replaced("t1", "bb")},
			Sessions:   []store.RevocationSessions{count("t1", "zz", 0, 0)}},
			revocationNotObserved, "0 of 1"},
		{"unreadable holders", store.RevocationEvidence{
			Deliveries: []store.RevocationDelivery{replaced("t1", "bb")},
			Sessions:   []store.RevocationSessions{count("t1", "bb", 0, 1)}},
			revocationNotObserved, "could not read"},
		{"a containment stop", store.RevocationEvidence{
			Deliveries: []store.RevocationDelivery{replaced("t1", "bb")},
			Sessions:   []store.RevocationSessions{count("t1", "bb", 3, 0)},
			Stops:      []store.RevocationStop{{Target: "t1", Status: "containment_stopped", At: at}}},
			revocationConfirmed, "listener holding it was stopped"},
	}
	for _, c := range cases {
		got := buildRevocationCertificateReport(revoked, c.ev).ExistingSessions
		if got.State != c.state || !strings.Contains(got.Detail, c.has) {
			t.Fatalf("%s: %+v; want %s containing %q", c.name, got, c.state, c.has)
		}
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
