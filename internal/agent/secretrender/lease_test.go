// SPDX-License-Identifier: BUSL-1.1

package secretrender

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeLeases is a dynamic-secret target: it issues numbered credentials, keeps
// a lease per issue key, renews until a hard limit, and records the order of
// what happened.
type fakeLeases struct {
	mu        sync.Mutex
	clock     *time.Time
	byKey     map[string]Lease
	revoked   map[string]bool
	noRenew   bool
	failIssue int
	events    []string
	n         int
}

func (f *fakeLeases) IssueLease(_ context.Context, _, _ string, ttl time.Duration, key string) (Lease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if l, ok := f.byKey[key]; ok {
		f.events = append(f.events, "replay "+l.ID)
		return Lease{ID: l.ID, Credential: append([]byte(nil), l.Credential...), ExpiresAt: l.ExpiresAt}, nil
	}
	f.n++
	id := fmt.Sprintf("L%d", f.n)
	l := Lease{ID: id, Credential: []byte(fmt.Sprintf(`{"username":"u%d","password":"p%d"}`, f.n, f.n)), ExpiresAt: f.clock.Add(ttl)}
	f.byKey[key] = l
	if f.failIssue > 0 {
		f.failIssue--
		f.events = append(f.events, "issue "+id+" (answer lost)")
		return Lease{}, errors.New("the answer was lost")
	}
	f.events = append(f.events, "issue "+id)
	return Lease{ID: id, Credential: append([]byte(nil), l.Credential...), ExpiresAt: l.ExpiresAt}, nil
}

func (f *fakeLeases) RenewLease(_ context.Context, id string, extend time.Duration, _ string) (time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.noRenew {
		return time.Time{}, errors.New("the lease reached its maximum lifetime")
	}
	f.events = append(f.events, "renew "+id)
	return f.clock.Add(extend), nil
}

func (f *fakeLeases) RevokeLease(_ context.Context, id, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked[id] = true
	f.events = append(f.events, "revoke "+id)
	return nil
}

func (f *fakeLeases) valid(password string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, l := range f.byKey {
		if strings.Contains(string(l.Credential), `"password":"`+password+`"`) && !f.revoked[l.ID] {
			return true
		}
	}
	return false
}

func (f *fakeLeases) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.events
	f.events = nil
	return out
}

// A238: a lease is renewed in place while it can be; when it can't, a new
// lease is issued, written and verified by the application before the old one
// is revoked. A failed verification keeps the old lease alive; a lost issue
// answer is retried under the same key, so no untracked lease is left behind;
// and a file holding a lease credential goes when the lease expires.
func TestRendererReplacesLeasesBeforeRevokingThemA238(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "db.env")
	now := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	leases := &fakeLeases{clock: &now, byKey: map[string]Lease{}, revoked: map[string]bool{}}
	var healthy atomic.Bool
	healthy.Store(true)
	// The application connects with whatever credential the file holds; the
	// target refuses a revoked one.
	application := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		raw, _ := os.ReadFile(file) // #nosec G304 -- the test's own temp file (CWE-22)
		_, pass, _ := strings.Cut(strings.TrimSpace(string(raw)), "pass=")
		if !healthy.Load() || !leases.valid(pass) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(application.Close)
	src := &fakeSource{values: map[string]string{}, versions: map[string]int{}}
	r, err := New(Config{
		Server: "unused", TokenFile: "unused", Consumer: "web-1/app", StateDir: filepath.Join(dir, "state"), Freshness: 24 * time.Hour,
		Templates: []Template{{
			Name: "db", Destination: file, LeaseTTL: time.Hour,
			Text:   "user={{ lease \"payments-db/readonly\" \"username\" }} pass={{ lease \"payments-db/readonly\" \"password\" }}\n",
			Verify: Verify{URL: application.URL, Timeout: time.Second},
		}},
	}, src, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.UseLeases(leases)
	r.now = func() time.Time { return now }
	read := func() string {
		raw, _ := os.ReadFile(file) // #nosec G304 -- the test's own temp file (CWE-22)
		return string(raw)
	}

	// A lost issue answer is retried under the same key: one lease, not two.
	leases.failIssue = 1
	r.Once(t.Context())
	r.Once(t.Context())
	if got := leases.take(); strings.Join(got, ",") != "issue L1 (answer lost),replay L1" {
		t.Fatalf("issue retry: %v", got)
	}
	if read() != "user=u1 pass=p1\n" {
		t.Fatalf("file %q", read())
	}

	// Inside two thirds of its life the lease is left alone; after, renewed in place.
	now = now.Add(30 * time.Minute)
	r.Once(t.Context())
	now = now.Add(15 * time.Minute)
	r.Once(t.Context())
	if got := leases.take(); strings.Join(got, ",") != "renew L1" || read() != "user=u1 pass=p1\n" {
		t.Fatalf("renewal: %v %q", got, read())
	}

	// It can't be renewed any more: a replacement is issued, written and
	// verified, and only then is the old lease revoked.
	leases.noRenew = true
	now = now.Add(50 * time.Minute)
	r.Once(t.Context())
	if got := leases.take(); strings.Join(got, ",") != "issue L2,revoke L1" || read() != "user=u2 pass=p2\n" {
		t.Fatalf("replacement: %v %q", got, read())
	}

	// The application can't take the next replacement: the old lease stays
	// valid until it does.
	healthy.Store(false)
	now = now.Add(50 * time.Minute)
	r.Once(t.Context())
	if got := leases.take(); strings.Join(got, ",") != "issue L3" {
		t.Fatalf("unverified replacement: %v", got)
	}
	healthy.Store(true)
	r.Once(t.Context())
	if got := leases.take(); strings.Join(got, ",") != "revoke L2" {
		t.Fatalf("revocation after verification: %v", got)
	}

	// Without the control plane the file goes at the lease's expiry, before a
	// longer freshness bound.
	src.down = true
	src.values["web/x"] = "unused"
	r.cfg.Templates[0].Text += `{{ secret "web/x" }}`
	now = now.Add(70 * time.Minute)
	r.Once(t.Context())
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("a file holding an expired lease credential survived")
	}
}
