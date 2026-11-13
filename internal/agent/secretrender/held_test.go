// SPDX-License-Identifier: BUSL-1.1

package secretrender

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A238-L4: a lease credential is held in locked memory only while it serves
// its file. The file removed past its bound destroys it (the next write issues
// a new lease), Close destroys what is held, and Run destroys it when it stops.
func TestRendererDestroysHeldLeaseCredentialsA238L4(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "db.env")
	now := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	leases := &fakeLeases{clock: &now, byKey: map[string]Lease{}, revoked: map[string]bool{}}
	src := &fakeSource{values: map[string]string{"web/name": "one"}, versions: map[string]int{"web/name": 1}}
	newRenderer := func(state, dest string) *Renderer {
		t.Helper()
		r, err := New(Config{
			Server: "unused", TokenFile: "unused", Consumer: "web-1/app", StateDir: filepath.Join(dir, state), Freshness: 24 * time.Hour,
			Templates: []Template{{Name: "db", Destination: dest, LeaseTTL: time.Hour,
				Text: "name={{ secret \"web/name\" }} pass={{ lease \"payments-db/readonly\" \"password\" }}\n"}},
		}, src, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.UseLeases(leases)
		r.now = func() time.Time { return now }
		return r
	}
	heldFor := func(r *Renderer) (string, int) {
		r.held.mu.Lock()
		defer r.held.mu.Unlock()
		h, ok := r.held.m[heldKey("db", "payments-db/readonly")]
		if !ok {
			return "", len(r.held.m)
		}
		return h.id, len(r.held.m)
	}
	r := newRenderer("state", file)
	r.Once(t.Context())
	if id, n := heldFor(r); id != "L1" || n != 1 {
		t.Fatalf("after the first write the renderer holds %q (%d entries), want L1 only", id, n)
	}
	if got := string(r.held.get("db", "payments-db/readonly", "L1")); !strings.Contains(got, `"password":"p1"`) {
		t.Fatalf("held credential %q", got)
	}
	if r.held.get("db", "payments-db/readonly", "L0") != nil {
		t.Fatal("a credential was handed out for another lease")
	}
	first := r.held.m[heldKey("db", "payments-db/readonly")].cred

	// Without the control plane, past the lease's expiry the file goes, and the
	// credential with it.
	src.down = true
	now = now.Add(2 * time.Hour)
	r.Once(t.Context())
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("the file outlived its lease")
	}
	if id, n := heldFor(r); id != "" || n != 0 || first.Len() != 0 {
		t.Fatalf("the removed file's credential is still held: %q, %d entries, %d bytes", id, n, first.Len())
	}
	// Back again, the next write issues a new lease: the old credential is gone.
	src.down = false
	r.Once(t.Context())
	if got := strings.Join(leases.take(), ","); !strings.Contains(got, "issue L2") {
		t.Fatalf("lease calls after the outage: %q", got)
	}
	second := r.held.m[heldKey("db", "payments-db/readonly")].cred
	if second.Len() == 0 {
		t.Fatal("the new lease's credential is not held")
	}
	r.Close()
	if id, n := heldFor(r); id != "" || n != 0 || second.Len() != 0 {
		t.Fatalf("Close left %q held (%d entries, %d bytes)", id, n, second.Len())
	}

	// Run makes its first pass and, once its context ends, destroys what it holds.
	runner := newRenderer("run-state", filepath.Join(dir, "run.env"))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := runner.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run: %v", err)
	}
	if got := strings.Join(leases.take(), ","); got != "issue L3" {
		t.Fatalf("Run's pass made lease calls %q, want one issue", got)
	}
	if id, n := heldFor(runner); id != "" || n != 0 {
		t.Fatalf("Run returned holding %q (%d entries)", id, n)
	}
}
