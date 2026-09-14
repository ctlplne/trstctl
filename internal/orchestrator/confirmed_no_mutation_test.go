// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
)

func TestConfirmedNoMutationBoundaries(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		name := "memory"
		if persistent {
			name = "postgres"
		}
		t.Run(name, func(t *testing.T) {
			idem := orchestrator.NewMemoryIdempotency()
			if persistent {
				idem = orchestrator.NewIdempotency(newStore(t))
			}
			ctx := t.Context()
			t.Run("concurrent-call-refuses-until-proof", func(t *testing.T) {
				var attempts atomic.Int32
				started, release := make(chan struct{}), make(chan struct{})
				var releaseOnce sync.Once
				unblock := func() { releaseOnce.Do(func() { close(release) }) }
				t.Cleanup(unblock)
				done := make(chan error, 1)
				firstCtx, cancel := context.WithCancel(ctx)
				t.Cleanup(cancel)
				go func() {
					_, err := idem.DoAtMostOnceEffect(firstCtx, tenantA, "no-mutation-concurrent", func(context.Context) ([]byte, error) {
						attempts.Add(1)
						close(started)
						<-release
						// Preserve a real cancelled operation's proof: no signing
						// request was sent, so bounded cleanup must still run.
						return nil, orchestrator.ConfirmedNoMutation(firstCtx.Err())
					})
					done <- err
				}()
				select {
				case <-started:
				case <-time.After(5 * time.Second):
					t.Fatal("first effect never started")
				}
				var committed atomic.Int32
				issue := func(context.Context) ([]byte, error) {
					attempts.Add(1)
					committed.Add(1)
					return []byte("one-certificate-result"), nil
				}
				_, racingErr := idem.DoAtMostOnceEffect(ctx, tenantA, "no-mutation-concurrent", issue)
				cancel()
				unblock()
				firstErr := <-done
				if !errors.Is(racingErr, orchestrator.ErrEffectIndeterminate) || committed.Load() != 0 {
					t.Fatal("concurrent caller entered the effect before proof was available")
				}
				if firstErr == nil || errors.Is(firstErr, orchestrator.ErrEffectIndeterminate) {
					t.Fatalf("proved cancellation could not release its claim: %v", firstErr)
				}
				for attempt := 0; attempt < 2; attempt++ {
					result, err := idem.DoAtMostOnceEffect(ctx, tenantA, "no-mutation-concurrent", issue)
					if err != nil || string(result) != "one-certificate-result" {
						t.Fatalf("recovery/replay failed: %v", err)
					}
				}
				if attempts.Load() != 2 || committed.Load() != 1 {
					t.Fatalf("recovery duplicated the protected effect: attempts=%d commits=%d", attempts.Load(), committed.Load())
				}
			})
			for _, partial := range []bool{false, true} {
				caseName := "untyped-lookalike-retains-fence"
				if partial {
					caseName = "partial-result-overrides-proof"
				}
				t.Run(caseName, func(t *testing.T) {
					calls := 0
					var returned []byte
					fn := func(context.Context) ([]byte, error) {
						calls++
						err := errors.New("protected mutation was not submitted: untrusted private-token-value")
						if partial {
							returned = []byte("unexpected-partial-secret-result")
							return returned, orchestrator.ConfirmedNoMutation(err)
						}
						return nil, err
					}
					for attempt := 0; attempt < 2; attempt++ {
						result, err := idem.DoAtMostOnceEffect(ctx, tenantA, caseName, fn)
						if len(result) != 0 || !errors.Is(err, orchestrator.ErrEffectIndeterminate) {
							t.Fatalf("uncertain result was made replayable: %v", err)
						}
						if strings.Contains(err.Error(), "private-token-value") {
							t.Fatal("provider secret escaped")
						}
					}
					if calls != 1 {
						t.Fatalf("uncertain callback ran %d times", calls)
					}
					for _, b := range returned {
						if b != 0 {
							t.Fatal("partial callback result was not wiped")
						}
					}
				})
			}
		})
	}
}
