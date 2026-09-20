// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/dependents"
)

// stubBackend tracks created and revoked refs to assert engine behaviour.
type stubBackend struct {
	mu      sync.Mutex
	n       int
	created map[string]bool
	revoked map[string]bool
}

func newStubBackend() *stubBackend {
	return &stubBackend{created: map[string]bool{}, revoked: map[string]bool{}}
}

type stubProvider struct{ b *stubBackend }

func (stubProvider) Name() string { return "stub" }
func (p stubProvider) Generate(_ context.Context, _ GenerateRequest) (Credential, error) {
	p.b.mu.Lock()
	defer p.b.mu.Unlock()
	p.b.n++
	ref := fmt.Sprintf("user-%d", p.b.n)
	p.b.created[ref] = true
	return Credential{BackendRef: ref, Secret: []byte("pw-" + ref)}, nil
}
func (p stubProvider) Revoke(_ context.Context, ref string) error {
	p.b.mu.Lock()
	defer p.b.mu.Unlock()
	p.b.revoked[ref] = true
	return nil
}

func TestEngineIssueRenewRevoke(t *testing.T) {
	b := newStubBackend()
	q := NewMemoryQueue()
	rec := &auditsink.Recorder{}
	e, _ := New(Config{TenantID: "t1", Providers: []Provider{stubProvider{b}}, Queue: q, Audit: rec})
	ctx := context.Background()
	lease, secret, err := e.Issue(ctx, "stub", "role", time.Minute, "")
	if err != nil || len(secret) == 0 {
		t.Fatalf("Issue: %v (secret len %d)", err, len(secret))
	}
	if _, err := e.Renew(ctx, lease.ID, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := e.Revoke(ctx, lease.ID); err != nil {
		t.Fatal(err)
	}
	n, _ := e.RunRevocations(ctx)
	if n != 1 || !b.revoked[lease.BackendRef] {
		t.Errorf("revocation did not reach backend: drained %d revoked=%v", n, b.revoked)
	}
	if rec.Count("dynsecret.lease.issued") != 1 {
		t.Error("issuance not audited")
	}
}

func TestRevocationSurvivesCrash(t *testing.T) {
	b := newStubBackend()
	q := NewMemoryQueue() // the durable outbox — survives the "crash"
	e1, _ := New(Config{TenantID: "t1", Providers: []Provider{stubProvider{b}}, Queue: q})
	ctx := context.Background()
	lease, _, err := e1.Issue(ctx, "stub", "role", time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	// Expiry enqueues the revoke durably but does not itself hit the backend.
	if n, _ := e1.ExpireDue(ctx, time.Now().Add(2*time.Minute)); n != 1 {
		t.Fatalf("ExpireDue revoked %d, want 1", n)
	}
	if b.revoked[lease.BackendRef] {
		t.Fatal("backend revoked before the worker ran")
	}
	// CRASH: e1 is gone. A fresh engine sharing the durable queue + backend.
	e2, _ := New(Config{TenantID: "t1", Providers: []Provider{stubProvider{b}}, Queue: q})
	done, _ := e2.RunRevocations(ctx)
	if done != 1 || !b.revoked[lease.BackendRef] {
		t.Errorf("revocation did not survive the crash: drained %d revoked=%v", done, b.revoked[lease.BackendRef])
	}
}

func TestIssueIdempotentNoDuplicateCredential(t *testing.T) {
	b := newStubBackend()
	e, _ := New(Config{TenantID: "t1", Providers: []Provider{stubProvider{b}}, Queue: NewMemoryQueue()})
	ctx := context.Background()
	l1, _, _ := e.Issue(ctx, "stub", "r", time.Minute, "key-1")
	l2, _, _ := e.Issue(ctx, "stub", "r", time.Minute, "key-1")
	if l1.ID != l2.ID {
		t.Errorf("idempotent replay created a new lease: %s vs %s", l1.ID, l2.ID)
	}
	if b.n != 1 {
		t.Errorf("backend credential generated %d times, want 1 (AN-5)", b.n)
	}
}

func TestIssueRecordsLeasedSecretDependent(t *testing.T) {
	b := newStubBackend()
	var records []dependents.Record
	e, _ := New(Config{
		TenantID:  "t1",
		Providers: []Provider{stubProvider{b}},
		Queue:     NewMemoryQueue(),
		Dependent: dependents.RecorderFunc(func(_ context.Context, rec dependents.Record) error {
			records = append(records, rec)
			return nil
		}),
	})
	ctx := context.Background()
	lease, _, err := e.Issue(ctx, "stub", "db-read", time.Minute, "lease-dependent")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("dependent records = %d, want 1", len(records))
	}
	got := records[0]
	if got.TenantID != "t1" || got.ProtectedByKeyID != "stub" || got.Kind != dependents.KindLeasedSecret || got.DependentID != lease.ID {
		t.Fatalf("dependent record = %+v, lease=%+v", got, lease)
	}
	if got.Metadata["role"] != "db-read" || got.Metadata["backend_ref"] != lease.BackendRef {
		t.Fatalf("dependent metadata = %+v, lease=%+v", got.Metadata, lease)
	}

	if _, _, err := e.Issue(ctx, "stub", "db-read", time.Minute, "lease-dependent"); err != nil {
		t.Fatalf("Issue replay: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("idempotent replay recorded %d dependents, want 1", len(records))
	}
}

func TestIssueDependentRecorderFailureRevokesGeneratedCredential(t *testing.T) {
	b := newStubBackend()
	e, _ := New(Config{
		TenantID:  "t1",
		Providers: []Provider{stubProvider{b}},
		Queue:     NewMemoryQueue(),
		Dependent: dependents.RecorderFunc(func(context.Context, dependents.Record) error {
			return errors.New("registration unavailable")
		}),
	})
	ctx := context.Background()
	if _, _, err := e.Issue(ctx, "stub", "db-read", time.Minute, "lease-dependent"); err == nil {
		t.Fatal("Issue succeeded despite dependent recorder failure")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.n != 1 {
		t.Fatalf("generated credentials = %d, want 1", b.n)
	}
	if !b.revoked["user-1"] {
		t.Fatalf("generated credential was not revoked after recorder failure: revoked=%v", b.revoked)
	}
}

func TestStubProviderConforms(t *testing.T) {
	if err := Conform(stubProvider{newStubBackend()}); err != nil {
		t.Fatalf("Conform: %v", err)
	}
}
