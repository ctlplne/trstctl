package rotation

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
)

// fakeRotator models a backend; "active" is the version consumers currently use.
type fakeRotator struct {
	active    string
	staged    string
	failVerif bool
	rolled    bool
}

func (r *fakeRotator) Stage(_ context.Context, key string) (string, error) {
	r.staged = key + "-v2"
	return r.staged, nil
}
func (r *fakeRotator) Cutover(_ context.Context, _, newRef string) error {
	r.active = newRef
	return nil
}
func (r *fakeRotator) Verify(_ context.Context, _ string) error {
	if r.failVerif {
		return errors.New("consumers unhealthy")
	}
	return nil
}
func (r *fakeRotator) Retire(_ context.Context, _, _ string) error { return nil }
func (r *fakeRotator) Rollback(_ context.Context, _, oldRef string) error {
	r.active = oldRef
	r.rolled = true
	return nil
}

func TestRotationHappyPath(t *testing.T) {
	r := &fakeRotator{active: "app-v1"}
	rec := &auditsink.Recorder{}
	e := New("t1", r, rec)
	rep, err := e.Rotate(context.Background(), "app", "app-v1")
	if err != nil || !rep.Completed {
		t.Fatalf("rotate = %+v (err %v)", rep, err)
	}
	if r.active != "app-v2" {
		t.Errorf("active = %q, want app-v2", r.active)
	}
	if rec.Count("rotation.completed") != 1 {
		t.Error("completion not audited")
	}
}

func TestRotationRollsBackOnVerifyFailure(t *testing.T) {
	r := &fakeRotator{active: "app-v1", failVerif: true}
	rec := &auditsink.Recorder{}
	e := New("t1", r, rec)
	rep, err := e.Rotate(context.Background(), "app", "app-v1")
	if err == nil {
		t.Fatal("expected an error on verify failure")
	}
	if !rep.RolledBack || rep.FailedPhase != "verify" {
		t.Errorf("report = %+v, want rolled-back at verify", rep)
	}
	// The central safety property: the consuming application is back on the old secret.
	if r.active != "app-v1" || !r.rolled {
		t.Errorf("after rollback active = %q rolled = %v, want app-v1/true", r.active, r.rolled)
	}
	if rec.Count("rotation.rolled_back") != 1 {
		t.Error("rollback not audited")
	}
}
