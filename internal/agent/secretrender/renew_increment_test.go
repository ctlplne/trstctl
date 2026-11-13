// SPDX-License-Identifier: BUSL-1.1

package secretrender

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A238-L5: lease_renew_increment sets how far each renewal reaches apart from
// the lifetime asked for at issue: renewed once a third of it is left, to
// expire that long after the renewal. It is between a second and lease_ttl.
func TestRendererRenewsLeasesByItsIncrementA238L5(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	now := t0
	leases := &serverLeases{clock: &now, hard: 2 * time.Hour, leases: map[string]*Lease{}}
	tmpl := Template{Name: "db", Destination: filepath.Join(dir, "db.env"), LeaseTTL: time.Hour, LeaseRenewIncrement: 15 * time.Minute,
		Text: "pass={{ lease \"payments-db/readonly\" \"password\" }}\n"}
	r, err := New(Config{
		Server: "unused", TokenFile: "unused", Consumer: "web-1/app", StateDir: filepath.Join(dir, "state"), Freshness: 24 * time.Hour,
		Templates: []Template{tmpl},
	}, &fakeSource{values: map[string]string{}, versions: map[string]int{}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.UseLeases(leases)
	r.now = func() time.Time { return now }
	t.Cleanup(r.Close)
	for _, s := range []struct {
		at   time.Duration
		want string
	}{
		{0, "issue L1"},
		{50 * time.Minute, ""}, // ten minutes left: more than a third of fifteen
		{56 * time.Minute, "renew L1 +11m0s"},
		{67 * time.Minute, "renew L1 +11m0s"},
	} {
		now = t0.Add(s.at)
		r.Once(t.Context())
		if got := leases.take(); got != s.want {
			t.Fatalf("at +%s the lease calls were %q, want %q", s.at, got, s.want)
		}
	}
	if got := leases.expiry("L1").Sub(now); got != 15*time.Minute {
		t.Fatalf("after a renewal the lease lives %s more, want the increment (15m)", got)
	}

	cfg := Config{Server: "unused", TokenFile: "unused", Consumer: "web-1/app", StateDir: filepath.Join(dir, "v")}
	for _, c := range []struct {
		ttl, increment time.Duration
		ok             bool
	}{
		{time.Hour, 2 * time.Hour, false},
		{0, 2 * time.Hour, false}, // the default TTL is an hour
		{time.Hour, -time.Minute, false},
		{time.Hour, 500 * time.Millisecond, false},
		{0, 30 * time.Minute, true},
		{time.Hour, time.Hour, true},
	} {
		tc := tmpl
		tc.LeaseTTL, tc.LeaseRenewIncrement = c.ttl, c.increment
		cfg.Templates = []Template{tc}
		err := cfg.Validate()
		if (err == nil) != c.ok || (err != nil && !strings.Contains(err.Error(), "lease_renew_increment")) {
			t.Fatalf("ttl %s, increment %s: %v (want ok=%v)", c.ttl, c.increment, err, c.ok)
		}
	}
}
