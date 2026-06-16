package rotation

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
)

type failRotator struct {
	failStage, failCutover, failRetire bool
	rolled                             bool
}

func (r *failRotator) Stage(_ context.Context, _ string) (string, error) {
	if r.failStage {
		return "", errors.New("stage failed")
	}
	return "new", nil
}
func (r *failRotator) Cutover(context.Context, string, string) error {
	if r.failCutover {
		return errors.New("cutover failed")
	}
	return nil
}
func (r *failRotator) Verify(context.Context, string) error { return nil }
func (r *failRotator) Retire(context.Context, string, string) error {
	if r.failRetire {
		return errors.New("retire failed")
	}
	return nil
}
func (r *failRotator) Rollback(context.Context, string, string) error { r.rolled = true; return nil }

func TestRotationStageFailureChangesNothing(t *testing.T) {
	r := &failRotator{failStage: true}
	rep, err := New("t1", r, &auditsink.Recorder{}).Rotate(context.Background(), "app", "old")
	if err == nil || rep.FailedPhase != "stage" || rep.RolledBack || r.rolled {
		t.Errorf("stage failure: rep=%+v err=%v (must not roll back; nothing changed)", rep, err)
	}
}

func TestRotationCutoverFailureRollsBack(t *testing.T) {
	r := &failRotator{failCutover: true}
	rec := &auditsink.Recorder{}
	rep, err := New("t1", r, rec).Rotate(context.Background(), "app", "old")
	if err == nil || rep.FailedPhase != "cutover" || !rep.RolledBack || !r.rolled {
		t.Errorf("cutover failure: rep=%+v err=%v (must roll back)", rep, err)
	}
	if rec.Count("rotation.rolled_back") != 1 {
		t.Error("rollback not audited")
	}
}

func TestRotationRetireFailureLeavesNewLive(t *testing.T) {
	r := &failRotator{failRetire: true}
	rep, err := New("t1", r, &auditsink.Recorder{}).Rotate(context.Background(), "app", "old")
	// New version is live and verified; only retiring the old one failed — not a
	// rollback, not "completed", safe to retry the retire.
	if err == nil || rep.FailedPhase != "retire" || rep.RolledBack || rep.Completed {
		t.Errorf("retire failure: rep=%+v err=%v", rep, err)
	}
}
