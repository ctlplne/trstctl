package leaseworker

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/dynsecret"
)

type backend struct {
	mu      sync.Mutex
	n       int
	revoked map[string]bool
}

func (b *backend) Create(_ context.Context, _ string) (string, []byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.n++
	return fmt.Sprintf("u%d", b.n), []byte("secret"), nil
}
func (b *backend) Revoke(_ context.Context, ref string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.revoked[ref] = true
	return nil
}

func TestWorkerRecoversRevocationAcrossRestart(t *testing.T) {
	ctx := context.Background()
	b := &backend{revoked: map[string]bool{}}
	q := dynsecret.NewMemoryQueue() // durable across the "restart"

	e1, _ := dynsecret.New(dynsecret.Config{TenantID: "t1", Providers: []dynsecret.Provider{dynsecret.NewProvider("stub", b)}, Queue: q})
	lease, _, err := e1.Issue(ctx, "stub", "role", time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	// Expiry enqueues the revoke durably; the worker has not drained it yet (crash).
	if _, err := e1.ExpireDue(ctx, time.Now().Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if b.revoked[lease.BackendRef] {
		t.Fatal("revoked before any worker drained the queue")
	}
	// Restart: a fresh engine + worker over the same durable queue and backend.
	e2, _ := dynsecret.New(dynsecret.Config{TenantID: "t1", Providers: []dynsecret.Provider{dynsecret.NewProvider("stub", b)}, Queue: q})
	w := New(e2, time.Second)
	n, err := w.Recover(ctx)
	if err != nil || n != 1 || !b.revoked[lease.BackendRef] {
		t.Errorf("worker did not recover+revoke across restart: n=%d revoked=%v err=%v", n, b.revoked[lease.BackendRef], err)
	}
}

func TestWorkerTickExpiresAndDrains(t *testing.T) {
	ctx := context.Background()
	b := &backend{revoked: map[string]bool{}}
	e, _ := dynsecret.New(dynsecret.Config{TenantID: "t1", Providers: []dynsecret.Provider{dynsecret.NewProvider("stub", b)}, Queue: dynsecret.NewMemoryQueue()})
	lease, _, _ := e.Issue(ctx, "stub", "role", -time.Minute, "") // already expired
	w := New(e, time.Second)
	exp, rev, err := w.Tick(ctx)
	if err != nil || exp != 1 || rev != 1 || !b.revoked[lease.BackendRef] {
		t.Errorf("tick = expired %d revoked %d (err %v), backend revoked=%v", exp, rev, err, b.revoked[lease.BackendRef])
	}
}
