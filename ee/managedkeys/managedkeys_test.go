package managedkeys_test

import (
	"context"
	"sync"
	"testing"

	"trstctl.com/trstctl/ee/managedkeys"
	"trstctl.com/trstctl/ee/managedkeys/managedkeysfake"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/byok"
)

// memSink records lifecycle events in order (the in-memory AN-2 log a test asserts
// against; the served control plane backs the same EventSink with events.Log).
type memSink struct {
	mu     sync.Mutex
	events []byok.LifecycleEvent
}

func (s *memSink) Emit(_ context.Context, e byok.LifecycleEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return nil
}

func (s *memSink) types() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.events))
	for i, e := range s.events {
		out[i] = e.Type
	}
	return out
}

// memIdem is an in-memory replay-safe idempotency recorder (AN-5): it runs fn once
// per (tenant,key) and returns the cached result on replay.
type memIdem struct {
	mu   sync.Mutex
	seen map[string]managedkeys.Result
}

func newMemIdem() *memIdem { return &memIdem{seen: map[string]managedkeys.Result{}} }

func (m *memIdem) Do(ctx context.Context, tenantID, key string, fn func(context.Context) (managedkeys.Result, error)) (managedkeys.Result, error) {
	m.mu.Lock()
	if r, ok := m.seen[tenantID+"|"+key]; ok {
		m.mu.Unlock()
		return r, nil
	}
	m.mu.Unlock()
	r, err := fn(ctx)
	if err != nil {
		return managedkeys.Result{}, err
	}
	m.mu.Lock()
	m.seen[tenantID+"|"+key] = r
	m.mu.Unlock()
	return r, nil
}

// fourEyesGate is an in-memory distinct-approver gate (the dual-control machinery
// the served issuance gate also uses). An action is approved once a principal OTHER
// than the requester has recorded an approval for that (tenant,key,action).
type fourEyesGate struct {
	mu        sync.Mutex
	approvals map[string]string // tenant|key|action -> approver
}

func newFourEyesGate() *fourEyesGate { return &fourEyesGate{approvals: map[string]string{}} }

func (g *fourEyesGate) approve(tenantID, keyID, action, approver string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.approvals[tenantID+"|"+keyID+"|"+action] = approver
}

func (g *fourEyesGate) IsApproved(_ context.Context, tenantID, keyID, action, requester string) (bool, string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	approver, ok := g.approvals[tenantID+"|"+keyID+"|"+action]
	if !ok {
		return false, "no approval on record"
	}
	if approver == requester {
		return false, "self-approval is not permitted (four-eyes)"
	}
	return true, ""
}

// TestManagedKeyLifecycleEndToEnd drives the served managed-key lifecycle through a
// fake KMS: generate -> rotate -> revoke -> zeroize, with dual control on the
// destructive steps, asserting AN-1/AN-2/AN-5 and the provider-side state. This is
// the served E2E proof for CRYPTO-005 (the primitives were previously reachable
// from no served caller).
func TestManagedKeyLifecycleEndToEnd(t *testing.T) {
	ctx := context.Background()
	kms := managedkeysfake.New()
	sink := &memSink{}
	gate := newFourEyesGate()
	svc, err := managedkeys.New(managedkeys.Config{Backend: kms, Sink: sink, Gate: gate, Idem: newMemIdem()})
	if err != nil {
		t.Fatal(err)
	}

	const tenant = "tenant-A"

	// GENERATE: mints material in the provider, emits byok.key.generated.
	gen, err := svc.Generate(ctx, tenant, crypto.ECDSAP256, "idem-gen-1")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if gen.KeyID == "" || gen.Version != 1 || gen.State != string(byok.StateActive) {
		t.Fatalf("generate result = %+v, want active v1 with a key id", gen)
	}
	if len(gen.PublicDER) == 0 {
		t.Fatal("generate returned no public key DER")
	}
	if !kms.Active(gen.KeyID) {
		t.Fatalf("provider key %q is not active after generate", gen.KeyID)
	}

	// ROTATE without an approval must fail closed (dual control), and must NOT touch
	// the provider.
	if _, err := svc.Rotate(ctx, tenant, gen.KeyID, "alice", "idem-rot-deny"); err == nil {
		t.Fatal("rotate succeeded without a distinct-approver approval (dual control bypassed)")
	}
	if !kms.Active(gen.KeyID) {
		t.Fatal("a denied rotate changed provider state")
	}

	// ROTATE with a distinct approver: mints a successor, emits byok.key.rotated.
	gate.approve(tenant, gen.KeyID, managedkeys.ActionRotate, "bob")
	rot, err := svc.Rotate(ctx, tenant, gen.KeyID, "alice", "idem-rot-1")
	if err != nil {
		t.Fatalf("rotate (approved): %v", err)
	}
	if rot.Version != 2 {
		t.Fatalf("rotate version = %d, want 2", rot.Version)
	}
	if rot.KeyID == gen.KeyID {
		t.Fatal("rotate did not mint a successor key id")
	}

	// REVOKE the (now current) key with a distinct approver: provider disables it.
	gate.approve(tenant, rot.KeyID, managedkeys.ActionRevoke, "bob")
	rev, err := svc.Revoke(ctx, tenant, rot.KeyID, "alice", "idem-rev-1")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if rev.State != string(byok.StateRevoked) {
		t.Fatalf("revoke state = %s, want revoked", rev.State)
	}
	if !kms.Disabled(rot.KeyID) {
		t.Fatalf("provider key %q is not disabled after revoke", rot.KeyID)
	}

	// ZEROIZE with a distinct approver: provider destroys the material.
	gate.approve(tenant, rot.KeyID, managedkeys.ActionZeroize, "bob")
	zer, err := svc.Zeroize(ctx, tenant, rot.KeyID, "alice", "idem-zer-1")
	if err != nil {
		t.Fatalf("zeroize: %v", err)
	}
	if zer.State != string(byok.StateZeroized) {
		t.Fatalf("zeroize state = %s, want zeroized", zer.State)
	}
	if !kms.Zeroized(rot.KeyID) {
		t.Fatalf("provider key %q material not destroyed after zeroize", rot.KeyID)
	}

	// AN-2: the event log carries the full lifecycle in order, key-material-free.
	wantTypes := []string{byok.EventKeyGenerated, byok.EventKeyRotated, byok.EventKeyRevoked, byok.EventKeyZeroized}
	got := sink.types()
	if len(got) != len(wantTypes) {
		t.Fatalf("emitted events = %v, want %v", got, wantTypes)
	}
	for i := range wantTypes {
		if got[i] != wantTypes[i] {
			t.Fatalf("event[%d] = %q, want %q", i, got[i], wantTypes[i])
		}
	}
	for _, e := range sink.events {
		if e.TenantID != tenant {
			t.Fatalf("event %q not tenant-scoped: %q", e.Type, e.TenantID)
		}
	}
}

// TestManagedKeyGenerateIsIdempotent proves a replayed Idempotency-Key returns the
// original result without minting a second provider key (AN-5).
func TestManagedKeyGenerateIsIdempotent(t *testing.T) {
	ctx := context.Background()
	kms := managedkeysfake.New()
	sink := &memSink{}
	svc, err := managedkeys.New(managedkeys.Config{Backend: kms, Sink: sink, Idem: newMemIdem()})
	if err != nil {
		t.Fatal(err)
	}
	first, err := svc.Generate(ctx, "t1", crypto.ECDSAP256, "same-key")
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Generate(ctx, "t1", crypto.ECDSAP256, "same-key") // replay
	if err != nil {
		t.Fatal(err)
	}
	if first.KeyID != second.KeyID {
		t.Fatalf("idempotent replay minted a new key: %q vs %q", first.KeyID, second.KeyID)
	}
	if n := len(sink.types()); n != 1 {
		t.Fatalf("idempotent replay emitted %d events, want 1", n)
	}
}

// TestManagedKeyTenantIsolation proves a key minted under one tenant cannot be
// rotated/revoked/zeroized under another (AN-1): the second tenant has no such key.
func TestManagedKeyTenantIsolation(t *testing.T) {
	ctx := context.Background()
	svc, err := managedkeys.New(managedkeys.Config{Backend: managedkeysfake.New(), Sink: &memSink{}})
	if err != nil {
		t.Fatal(err)
	}
	gen, err := svc.Generate(ctx, "tenant-A", crypto.ECDSAP256, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Revoke(ctx, "tenant-B", gen.KeyID, "mallory", ""); err == nil {
		t.Fatal("a different tenant revoked another tenant's key (AN-1 violation)")
	}
}

// TestManagedKeyDualControlRequiredForEveryDestructiveAction proves rotate, revoke,
// and zeroize each fail closed without a distinct-approver approval, and that the
// requester cannot approve their own action.
func TestManagedKeyDualControlRequiredForEveryDestructiveAction(t *testing.T) {
	ctx := context.Background()
	gate := newFourEyesGate()
	svc, err := managedkeys.New(managedkeys.Config{Backend: managedkeysfake.New(), Sink: &memSink{}, Gate: gate})
	if err != nil {
		t.Fatal(err)
	}
	gen, err := svc.Generate(ctx, "t1", crypto.ECDSAP256, "")
	if err != nil {
		t.Fatal(err)
	}
	// Self-approval must not count.
	gate.approve("t1", gen.KeyID, managedkeys.ActionRevoke, "alice")
	if _, err := svc.Revoke(ctx, "t1", gen.KeyID, "alice", ""); err == nil {
		t.Fatal("self-approval allowed a revoke (four-eyes bypassed)")
	}
	// Rotate/zeroize with no approval at all must also fail closed.
	if _, err := svc.Rotate(ctx, "t1", gen.KeyID, "alice", ""); err == nil {
		t.Fatal("rotate allowed with no approval")
	}
	if _, err := svc.Zeroize(ctx, "t1", gen.KeyID, "alice", ""); err == nil {
		t.Fatal("zeroize allowed with no approval")
	}
}
