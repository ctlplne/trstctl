package secretsync

import (
	"context"
	"errors"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
)

type memTarget struct {
	mu       sync.Mutex
	got      map[string]string
	failNext bool
}

func newMemTarget() *memTarget { return &memTarget{got: map[string]string{}} }

func (m *memTarget) Push(_ context.Context, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failNext {
		m.failNext = false
		return errors.New("target unavailable")
	}
	m.got[key] = string(value)
	return nil
}

func TestSyncDeliversIdempotentlyViaOutbox(t *testing.T) {
	ctx := context.Background()
	mt := newMemTarget()
	e := New("t1", NewKubernetesTarget(mt), NewMemoryOutbox(), &auditsink.Recorder{})
	if err := e.Sync(ctx, "DB_URL", []byte("postgres://x")); err != nil {
		t.Fatal(err)
	}
	n, err := e.RunDeliveries(ctx)
	if err != nil || n != 1 {
		t.Fatalf("delivered %d (err %v), want 1", n, err)
	}
	if mt.got["DB_URL"] != "postgres://x" {
		t.Errorf("target value = %q", mt.got["DB_URL"])
	}
	// Re-running is idempotent (nothing pending, no error).
	if n2, _ := e.RunDeliveries(ctx); n2 != 0 {
		t.Errorf("re-run delivered %d, want 0", n2)
	}
}

func TestSyncFailureRetriesNoHalfWrite(t *testing.T) {
	ctx := context.Background()
	mt := newMemTarget()
	mt.failNext = true
	e := New("t1", NewWebhookTarget(mt), NewMemoryOutbox(), nil)
	_ = e.Sync(ctx, "K", []byte("v"))
	// First delivery fails; item must remain queued, target unwritten.
	if n, _ := e.RunDeliveries(ctx); n != 0 {
		t.Fatalf("delivered %d on a failing target, want 0", n)
	}
	if _, ok := mt.got["K"]; ok {
		t.Error("half-write: target received a value despite the failure")
	}
	// Retry succeeds.
	if n, _ := e.RunDeliveries(ctx); n != 1 || mt.got["K"] != "v" {
		t.Errorf("retry delivered %d (value %q), want 1/v", n, mt.got["K"])
	}
}

func TestSyncDriftDetection(t *testing.T) {
	e := New("t1", NewVercelTarget(newMemTarget()), NewMemoryOutbox(), nil)
	_ = e.Sync(context.Background(), "K", []byte("v1"))
	if e.Drift("K", []byte("v1")) {
		t.Error("false drift on unchanged value")
	}
	if !e.Drift("K", []byte("v2")) {
		t.Error("drift not detected on changed value")
	}
}

func TestAllSyncTargetsDistinct(t *testing.T) {
	mt := newMemTarget()
	targets := []*Target{
		NewKubernetesTarget(mt), NewGitHubActionsTarget(mt), NewGitLabCITarget(mt),
		NewTerraformTarget(mt), NewVercelTarget(mt), NewAWSParamStoreTarget(mt), NewWebhookTarget(mt),
	}
	if len(targets) != 7 {
		t.Fatalf("expected 7 targets, have %d", len(targets))
	}
	names := map[string]bool{}
	for _, tg := range targets {
		if names[tg.Name()] {
			t.Errorf("duplicate target name %q", tg.Name())
		}
		names[tg.Name()] = true
	}
}
