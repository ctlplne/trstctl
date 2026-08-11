// SPDX-License-Identifier: MPL-2.0

package rotation

import (
	"context"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
)

// fakeRotator models a backend; "active" is the version consumers currently use.
type fakeRotator struct {
	active      string
	staged      string
	failVerif   bool
	rollbackErr error
	rolled      bool
	verified    bool
	retired     bool
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
	r.verified = true
	if r.failVerif {
		return errors.New("consumers unhealthy")
	}
	return nil
}
func (r *fakeRotator) Retire(_ context.Context, _, _ string) error {
	r.retired = true
	return nil
}
func (r *fakeRotator) Rollback(_ context.Context, _, oldRef string) error {
	if r.rollbackErr != nil {
		return r.rollbackErr
	}
	r.active = oldRef
	r.rolled = true
	return nil
}

type queuedFakeRotator struct{ fakeRotator }

func (*queuedFakeRotator) CutoverQueued() bool { return true }

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

func TestRotationQueuedCutoverLeavesVerificationAndRetirementToWorker(t *testing.T) {
	r := &queuedFakeRotator{fakeRotator: fakeRotator{active: "app-v1"}}
	rec := &auditsink.Recorder{}
	rep, err := New("t1", r, rec).Rotate(context.Background(), "app", "app-v1")
	if err != nil || !rep.Queued || rep.Completed || rep.NewRef != "app-v2" {
		t.Fatalf("queued rotate = %+v (err %v)", rep, err)
	}
	if r.verified || r.retired {
		t.Fatalf("request path verified=%t retired=%t after queued cutover", r.verified, r.retired)
	}
	if rec.Count("rotation.queued") != 1 || rec.Count("rotation.completed") != 0 {
		t.Fatalf("queued/completed audit counts = %d/%d", rec.Count("rotation.queued"), rec.Count("rotation.completed"))
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
	if !rep.RollbackAttempted || rep.RollbackFailed || !rep.RolledBack || rep.FailedPhase != "verify" {
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

func TestRotationReportsRollbackFailure(t *testing.T) {
	r := &fakeRotator{
		active:      "app-v1",
		failVerif:   true,
		rollbackErr: errors.New("backend refused rollback"),
	}
	rec := &auditsink.Recorder{}
	e := New("t1", r, rec)
	rep, err := e.Rotate(context.Background(), "app", "app-v1")
	if err == nil {
		t.Fatal("expected verify failure plus rollback failure")
	}
	for _, want := range []string{"verify", "consumers unhealthy", "backend refused rollback"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}
	if !rep.RollbackAttempted || !rep.RollbackFailed || rep.RolledBack || rep.FailedPhase != "verify" {
		t.Fatalf("report = %+v, want rollback attempted, failed, not rolled back at verify", rep)
	}
	if !strings.Contains(rep.RollbackError, "backend refused rollback") {
		t.Fatalf("RollbackError = %q", rep.RollbackError)
	}
	if r.active != "app-v2" || r.rolled {
		t.Fatalf("active=%q rolled=%v, want app-v2/false after failed rollback", r.active, r.rolled)
	}
	if rec.Count("rotation.rollback_failed") != 1 {
		t.Fatal("failed rollback was not audited")
	}
	if rec.Count("rotation.rolled_back") != 0 {
		t.Fatal("failed rollback must not be audited as successful")
	}
}
