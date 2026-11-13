// SPDX-License-Identifier: BUSL-1.1

package secretrender

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// serverLeases renews the way the control plane does: an extension adds to
// the lease's current expiry, and one that would pass its hard expiry is
// refused outright. It records each call with the extension asked for.
type serverLeases struct {
	mu     sync.Mutex
	clock  *time.Time
	hard   time.Duration
	leases map[string]*Lease
	calls  []string
	n      int
}

func (s *serverLeases) IssueLease(_ context.Context, _, _ string, ttl time.Duration, _ string) (Lease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	l := &Lease{ID: fmt.Sprintf("L%d", s.n), Credential: []byte(fmt.Sprintf(`{"password":"p%d"}`, s.n)),
		ExpiresAt: s.clock.Add(ttl), HardExpiresAt: s.clock.Add(s.hard)}
	s.leases[l.ID] = l
	s.calls = append(s.calls, "issue "+l.ID)
	return Lease{ID: l.ID, Credential: bytes.Clone(l.Credential), ExpiresAt: l.ExpiresAt, HardExpiresAt: l.HardExpiresAt}, nil
}

func (s *serverLeases) RenewLease(_ context.Context, id string, extend time.Duration, _ string) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.leases[id]
	s.calls = append(s.calls, fmt.Sprintf("renew %s +%s", id, extend))
	next := l.ExpiresAt.Add(extend)
	if next.After(l.HardExpiresAt) {
		return time.Time{}, errors.New("the renewal would pass the lease's hard expiry")
	}
	l.ExpiresAt = next
	return next, nil
}

func (s *serverLeases) RevokeLease(_ context.Context, id, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "revoke "+id)
	return nil
}

func (s *serverLeases) take() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := strings.Join(s.calls, ",")
	s.calls = nil
	return out
}

func (s *serverLeases) expiry(id string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.leases[id].ExpiresAt
}

// A238-L5 Done-when: a renewal brings the lease to expire one TTL after the
// renewal, not one TTL after its old expiry, and never asks past the hard
// expiry: near it, the lease is renewed up to it and then replaced without a
// refused call. The control plane's semantics are modeled by serverLeases.
func TestRendererRenewsALeaseToItsTTLFromNowA238L5(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "db.env")
	t0 := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	now := t0
	leases := &serverLeases{clock: &now, hard: 2 * time.Hour, leases: map[string]*Lease{}}
	r, err := New(Config{
		Server: "unused", TokenFile: "unused", Consumer: "web-1/app", StateDir: filepath.Join(dir, "state"), Freshness: 24 * time.Hour,
		Templates: []Template{{Name: "db", Destination: file, LeaseTTL: time.Hour,
			Text: "pass={{ lease \"payments-db/readonly\" \"password\" }}\n"}},
	}, &fakeSource{values: map[string]string{}, versions: map[string]int{}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.UseLeases(leases)
	r.now = func() time.Time { return now }
	t.Cleanup(r.Close)
	step := func(at time.Duration, want string) {
		t.Helper()
		now = t0.Add(at)
		r.Once(t.Context())
		if got := leases.take(); got != want {
			t.Fatalf("at +%s the lease calls were %q, want %q", at, got, want)
		}
	}
	step(0, "issue L1")
	// A third of the hour left: renewed to expire an hour from now.
	step(45*time.Minute, "renew L1 +45m0s")
	if got := leases.expiry("L1").Sub(now); got != time.Hour {
		t.Fatalf("after the renewal the lease lives %s more, want the TTL (1h)", got)
	}
	// Near the hard expiry (2h): renewed up to it, not refused.
	step(90*time.Minute, "renew L1 +15m0s")
	if got := leases.expiry("L1"); !got.Equal(t0.Add(2 * time.Hour)) {
		t.Fatalf("the lease expires at %s, want its hard expiry", got)
	}
	// At the hard expiry's edge it can't be extended: replaced, no renew call.
	step(101*time.Minute, "issue L2,revoke L1")
	if raw, _ := os.ReadFile(file); string(raw) != "pass=p2\n" { // #nosec G304 -- the test's own temp file (CWE-22)
		t.Fatalf("file %q", raw)
	}
}
