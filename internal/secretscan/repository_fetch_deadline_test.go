// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// CR-090. Only the worker's follow-up fetch owns this child context.
func TestRepositoryFollowupFetchOwnsABoundedContext(t *testing.T) {
	for _, mode := range []string{"without caller deadline", "shorter caller deadline"} {
		t.Run(mode, func(t *testing.T) {
			parent := t.Context()
			if mode == "shorter caller deadline" {
				var cancel context.CancelFunc
				parent, cancel = context.WithTimeout(parent, time.Second*5)
				defer cancel()
			}
			var fetch context.Context
			origin := t.TempDir()
			run := func(ctx context.Context, _ string, _ []string, args ...string) error {
				switch args[0] {
				case "clone":
					return nil
				case "fetch":
					fetch = ctx
					deadline, ok := ctx.Deadline()
					if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 2*time.Minute {
						t.Error("follow-up fetch requires its own deadline of at most two minutes")
					}
					if parentDeadline, ok := parent.Deadline(); ok && !deadline.Equal(parentDeadline) {
						t.Error("follow-up fetch did not honor the shorter caller deadline")
					}
					return nil
				case "checkout":
					if fetch == nil {
						return errors.New("fixture commit still needs to be fetched")
					}
					if !errors.Is(fetch.Err(), context.Canceled) || ctx.Err() != nil {
						t.Error("fetch context should close before the caller's checkout continues")
					}
					return nil
				default:
					t.Fatalf("unexpected Git stage %q", args[0])
					return nil
				}
			}
			target, err := prepareRepositoryTargetWithGit(parent, RepositoryScanConfig{CloneURL: origin, CommitSHA: "01234567"}, nil, run)
			if err != nil || fetch == nil || target.Mode != "clone_url" {
				t.Fatalf("prepare fixture checkout through bounded fetch: mode=%q err=%v", target.Mode, err)
			}
			target.Cleanup()
			if _, err := os.Stat(target.Path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("worker-owned fixture checkout was retained: %v", err)
			}
		})
	}
}
