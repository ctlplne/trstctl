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

// renewRefusing is a lease target that can refuse to renew one lease.
type renewRefusing struct {
	*fakeLeases
	refuse string
}

func (r *renewRefusing) RenewLease(ctx context.Context, id string, extend time.Duration, key string) (time.Time, error) {
	if id == r.refuse {
		return time.Time{}, errors.New("the lease reached its maximum lifetime")
	}
	return r.fakeLeases.RenewLease(ctx, id, extend, key)
}

// A238-L4 Done-when: a file written again because a static secret changed, or
// because the file went, keeps its live leases: each credential is held in
// locked memory from its issue, so the rewrite issues and revokes nothing. A
// lease that can't be renewed is replaced on its own while the other keeps its
// credential. A restarted renderer holds nothing, so its next rewrite issues
// fresh leases and revokes the old ones after writing them.
func TestRendererKeepsLiveLeasesWhenStaticSecretsChangeA238L4(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "db.env")
	now := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	leases := &renewRefusing{fakeLeases: &fakeLeases{clock: &now, byKey: map[string]Lease{}, revoked: map[string]bool{}}}
	src := &fakeSource{values: map[string]string{"web/name": "one"}, versions: map[string]int{"web/name": 1}}
	cfg := Config{
		Server: "unused", TokenFile: "unused", Consumer: "web-1/app", StateDir: filepath.Join(dir, "state"), Freshness: 24 * time.Hour,
		Templates: []Template{{
			Name: "db", Destination: file, LeaseTTL: time.Hour,
			Text: "name={{ secret \"web/name\" }} a={{ lease \"payments-db/readonly\" \"password\" }} " +
				"b={{ lease \"orders-db/readonly\" \"password\" }}\n",
		}},
	}
	start := func() *Renderer {
		t.Helper()
		r, err := New(cfg, src, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.UseLeases(leases)
		r.now = func() time.Time { return now }
		return r
	}
	read := func() string {
		raw, _ := os.ReadFile(file) // #nosec G304 -- the test's own temp file (CWE-22)
		return string(raw)
	}
	step := func(r *Renderer, name, wantCalls, wantFile string) {
		t.Helper()
		r.Once(t.Context())
		if got := strings.Join(leases.take(), ","); got != wantCalls || read() != wantFile {
			t.Fatalf("%s: lease calls %q and file %q; want %q and %q", name, got, read(), wantCalls, wantFile)
		}
	}
	r := start()
	step(r, "first write", "issue L1,issue L2", "name=one a=p1 b=p2\n")

	// Two static rotations and a removed file: written again with the same
	// credentials, and no lease call at all.
	src.set("web/name", "two")
	now = now.Add(5 * time.Minute)
	step(r, "first rotation", "", "name=two a=p1 b=p2\n")
	src.set("web/name", "three")
	now = now.Add(5 * time.Minute)
	step(r, "second rotation", "", "name=three a=p1 b=p2\n")
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	step(r, "removed file", "", "name=three a=p1 b=p2\n")

	// orders-db's lease can't be renewed any more: only it is replaced, and the
	// rotation that comes with it keeps payments-db's renewed lease.
	leases.refuse = "L2"
	src.set("web/name", "four")
	now = now.Add(35 * time.Minute)
	step(r, "one lease replaced", "renew L1,issue L3,revoke L2", "name=four a=p1 b=p3\n")

	// A restarted renderer holds nothing: its next rewrite issues fresh leases
	// and revokes the old ones after writing them; later rotations keep them.
	r.Close()
	r = start()
	t.Cleanup(r.Close)
	src.set("web/name", "five")
	now = now.Add(5 * time.Minute)
	step(r, "after a restart", "issue L4,issue L5,revoke L1,revoke L3", "name=five a=p4 b=p5\n")
	src.set("web/name", "six")
	now = now.Add(5 * time.Minute)
	step(r, "rotation after the restart", "", "name=six a=p4 b=p5\n")
}
