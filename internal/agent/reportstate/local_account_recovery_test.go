// SPDX-License-Identifier: BUSL-1.1
package reportstate

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/winaccounts"
)

// localAccountRecoverer answers as the native recoverer does: a proof
// completes the fence, ErrRotationNotApplied says the predecessor still signs
// in, and anything else leaves the generation unknown.
type localAccountRecoverer struct {
	calls   int
	outcome string
}

func (r *localAccountRecoverer) Recover(ctx context.Context, b winaccounts.RotationBinding, generation string, _, _ []byte, fence winaccounts.RotationFence) (winaccounts.RotationProof, error) {
	r.calls++
	switch r.outcome {
	case "applied":
		p := winaccounts.RotationProof{Binding: b, GenerationID: generation, NewAuthenticated: true, OldRefused: true, ObservedAt: time.Now().UTC()}
		if e := fence.Complete(ctx, p); e != nil {
			return winaccounts.RotationProof{}, e
		}
		return p, nil
	case "not_applied":
		return winaccounts.RotationProof{}, winaccounts.ErrRotationNotApplied
	}
	return winaccounts.RotationProof{}, winaccounts.ErrRotationUncertain
}

// TestLocalAccountRotationRecoverySettlesAnUnknownGenerationA268O1 is A268-O1
// on the host's journal: only a begun generation is recovered, by sign-in. A
// proof completes it as a rotation would. A generation the account never took
// is recorded as not applied, survives a restart, is never rotated again, and
// lets the next generation from the same predecessor begin. A recovery that
// still cannot tell keeps the generation begun.
func TestLocalAccountRotationRecoverySettlesAnUnknownGenerationA268O1(t *testing.T) {
	b := journalAccountBinding()
	begin := func(t *testing.T) (*Store, string) {
		t.Helper()
		root := t.TempDir()
		s := openAccountStore(t, root)
		if _, e := s.ExecuteLocalAccountRotationOnce(t.Context(), 81, b, accountGeneration, "", nil, nil, &localAccountFixture{unknown: true}); !errors.Is(e, winaccounts.ErrRotationUncertain) {
			t.Fatal("the fixture did not leave an unknown generation", e)
		}
		return s, root
	}
	t.Run("nothing_begun", func(t *testing.T) {
		s := openAccountStore(t, t.TempDir())
		r := &localAccountRecoverer{outcome: "applied"}
		if _, e := s.RecoverLocalAccountRotationOnce(t.Context(), 82, b, accountGeneration, "", nil, nil, r); e == nil || r.calls != 0 {
			t.Fatal("a generation that was never begun was recovered", e)
		}
	})
	t.Run("applied", func(t *testing.T) {
		s, _ := begin(t)
		r := &localAccountRecoverer{outcome: "applied"}
		p, e := s.RecoverLocalAccountRotationOnce(t.Context(), 82, b, accountGeneration, "", nil, nil, r)
		if e != nil || !p.NewAuthenticated || !p.OldRefused || r.calls != 1 {
			t.Fatal("an applied generation was not recovered", e)
		}
		replayed, found, e := s.ReplayLocalAccountRotation(t.Context(), 83, b, accountGeneration, "")
		if e != nil || !found || !sameAccountRotationProof(replayed, p) {
			t.Fatal("the recovered proof is not the journal's", e)
		}
		if again, e := s.RecoverLocalAccountRotationOnce(t.Context(), 83, b, accountGeneration, "", nil, nil, r); e != nil || !sameAccountRotationProof(again, p) || r.calls != 1 {
			t.Fatal("a recovered generation signed in again", e)
		}
	})
	t.Run("not_applied", func(t *testing.T) {
		s, root := begin(t)
		r := &localAccountRecoverer{outcome: "not_applied"}
		if _, e := s.RecoverLocalAccountRotationOnce(t.Context(), 82, b, accountGeneration, "", nil, nil, r); !errors.Is(e, winaccounts.ErrRotationNotApplied) || r.calls != 1 {
			t.Fatal("a generation the account never took was not recorded", e)
		}
		_ = s.Close()
		s = openAccountStore(t, root)
		if _, e := s.RecoverLocalAccountRotationOnce(t.Context(), 83, b, accountGeneration, "", nil, nil, r); !errors.Is(e, winaccounts.ErrRotationNotApplied) || r.calls != 1 {
			t.Fatal("the settled answer did not survive a restart", e)
		}
		f := &localAccountFixture{}
		if _, e := s.ExecuteLocalAccountRotationOnce(t.Context(), 84, b, accountGeneration, "", nil, nil, f); e == nil || f.calls != 0 {
			t.Fatal("a generation that was never applied was rotated again", e)
		}
		if _, e := s.ExecuteLocalAccountRotationOnce(t.Context(), 85, b, nextAccountGeneration, accountGeneration, nil, nil, f); e == nil || f.calls != 0 {
			t.Fatal("a generation that was never applied became a predecessor", e)
		}
		p, e := s.ExecuteLocalAccountRotationOnce(t.Context(), 86, b, nextAccountGeneration, "", nil, nil, f)
		if e != nil || !p.NewAuthenticated || f.resets != 1 {
			t.Fatal("the next generation from the same predecessor could not begin", e)
		}
	})
	t.Run("still_unknown", func(t *testing.T) {
		s, _ := begin(t)
		r := &localAccountRecoverer{outcome: "unknown"}
		if _, e := s.RecoverLocalAccountRotationOnce(t.Context(), 82, b, accountGeneration, "", nil, nil, r); !errors.Is(e, winaccounts.ErrRotationUncertain) || r.calls != 1 {
			t.Fatal("an unknown recovery settled the generation", e)
		}
		f := &localAccountFixture{}
		if _, e := s.ExecuteLocalAccountRotationOnce(t.Context(), 83, b, nextAccountGeneration, "", nil, nil, f); e == nil || f.calls != 0 {
			t.Fatal("a generation still unknown let the next one begin", e)
		}
	})
}
