// SPDX-License-Identifier: BUSL-1.1

package reprotect

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/decommission/depstate"
	"trstctl.com/trstctl/internal/dynsecret"
)

// Guard for VDEC-claim-19.
func TestReprotect_LeasedCredentialRevocationResumes(t *testing.T) {
	ctx := context.Background()
	queue := dynsecret.NewMemoryQueue()
	backend := &leaseTestBackend{}
	downProvider := leaseTestProvider{name: "lease-provider", backend: backend, revokeErr: errors.New("backend unavailable")}
	firstEngine, err := dynsecret.New(dynsecret.Config{TenantID: "tenant-a", Providers: []dynsecret.Provider{downProvider}, Queue: queue})
	if err != nil {
		t.Fatalf("dynsecret.New first: %v", err)
	}
	lease, _, err := firstEngine.Issue(ctx, downProvider.Name(), "db-read", time.Minute, "issue-lease")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	job := leaseRevocationJob(lease.ID)
	sink := &recordingCompletionSink{}
	recorder := NewCompletionRecorder(sink)
	firstExec, err := NewLeaseRevocationExecutor(firstEngine, queue, recorder)
	if err != nil {
		t.Fatalf("NewLeaseRevocationExecutor first: %v", err)
	}

	first, err := firstExec.Execute(ctx, LeaseRevocationRequest{Job: job})
	if !errors.Is(err, ErrLeaseRevocationPending) {
		t.Fatalf("first Execute err = %v, want ErrLeaseRevocationPending", err)
	}
	if first.Drained != 0 || !first.Pending {
		t.Fatalf("first result = %#v, want pending with no drained revocation", first)
	}
	if len(sink.events) != 0 {
		t.Fatalf("interrupted revocation recorded completion: %#v", sink.events)
	}
	assertLeaseQueued(t, queue, lease.ID, true)
	if got := backend.revokes(lease.BackendRef); got != 0 {
		t.Fatalf("failed provider should not mark backend revoked, got %d", got)
	}

	// Simulate control-plane restart: the fresh engine has no in-memory lease map,
	// but it shares the durable revocation queue and can drain the pending item.
	upProvider := leaseTestProvider{name: downProvider.Name(), backend: backend}
	resumedEngine, err := dynsecret.New(dynsecret.Config{TenantID: "tenant-a", Providers: []dynsecret.Provider{upProvider}, Queue: queue})
	if err != nil {
		t.Fatalf("dynsecret.New resumed: %v", err)
	}
	resumedExec, err := NewLeaseRevocationExecutor(resumedEngine, queue, recorder)
	if err != nil {
		t.Fatalf("NewLeaseRevocationExecutor resumed: %v", err)
	}
	resumed, err := resumedExec.Execute(ctx, LeaseRevocationRequest{Job: job})
	if err != nil {
		t.Fatalf("resumed Execute: %v", err)
	}
	if resumed.Pending || resumed.Drained != 1 {
		t.Fatalf("resumed result = %#v, want one drained revocation and no pending item", resumed)
	}
	assertLeaseQueued(t, queue, lease.ID, false)
	if got := backend.revokes(lease.BackendRef); got != 1 {
		t.Fatalf("backend revokes for %s = %d, want 1", lease.BackendRef, got)
	}
	if len(sink.events) != 1 {
		t.Fatalf("completion events = %d, want 1", len(sink.events))
	}
	event := sink.events[0]
	if event.JobID != job.ID || event.Dependent != job.Dependent || event.SuccessorKeyID != leaseRevokedSuccessorID(lease.ID) {
		t.Fatalf("completion event mismatch: %#v for job %#v", event, job)
	}
	if !resumed.Completion.Recorded {
		t.Fatalf("resumed execution did not record completion: %#v", resumed.Completion)
	}

	redelivered, err := firstExec.Execute(ctx, LeaseRevocationRequest{Job: job})
	if err != nil {
		t.Fatalf("redelivered Execute: %v", err)
	}
	if redelivered.Completion.Recorded {
		t.Fatal("redelivery recorded a duplicate completion")
	}
	if len(sink.events) != 1 {
		t.Fatalf("completion event count after redelivery = %d, want 1", len(sink.events))
	}
	if got := backend.revokes(lease.BackendRef); got != 1 {
		t.Fatalf("backend revoke repeated after redelivery: got %d, want 1", got)
	}
}

type leaseTestProvider struct {
	name      string
	backend   *leaseTestBackend
	revokeErr error
}

func (p leaseTestProvider) Name() string { return p.name }

func (p leaseTestProvider) Generate(_ context.Context, req dynsecret.GenerateRequest) (dynsecret.Credential, error) {
	ref := "backend-ref:" + req.LeaseID
	p.backend.create(ref)
	return dynsecret.Credential{BackendRef: ref, Secret: []byte{1, 2, 3}, Metadata: map[string]string{"role": req.Role}}, nil
}

func (p leaseTestProvider) Revoke(_ context.Context, ref string) error {
	if p.revokeErr != nil {
		return p.revokeErr
	}
	p.backend.revoke(ref)
	return nil
}

type leaseTestBackend struct {
	mu      sync.Mutex
	created map[string]struct{}
	revoked map[string]int
}

func (b *leaseTestBackend) create(ref string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.created == nil {
		b.created = make(map[string]struct{})
	}
	b.created[ref] = struct{}{}
}

func (b *leaseTestBackend) revoke(ref string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.revoked == nil {
		b.revoked = make(map[string]int)
	}
	b.revoked[ref]++
}

func (b *leaseTestBackend) revokes(ref string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.revoked[ref]
}

func leaseRevocationJob(leaseID string) Job {
	return Job{
		ID:             "job-lease-revoke",
		TenantID:       "tenant-a",
		KeyID:          "key://tenant-a/root",
		LedgerPosition: 13,
		Kind:           JobKindRevokeLease,
		Dependent:      depstate.Dependent{Class: depstate.DependentLeasedSecret, ID: leaseID},
		IdempotencyKey: "idem-lease-revoke",
	}
}

func assertLeaseQueued(t *testing.T, queue *dynsecret.MemoryQueue, leaseID string, want bool) {
	t.Helper()
	items, err := queue.Pending(context.Background())
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	for _, item := range items {
		if item.LeaseID == leaseID {
			if !want {
				t.Fatalf("lease %s still queued: %#v", leaseID, items)
			}
			return
		}
	}
	if want {
		t.Fatalf("lease %s not queued: %#v", leaseID, items)
	}
}
