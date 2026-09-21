// SPDX-License-Identifier: BUSL-1.1

package ctmonitor_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/ctlog"
	"trstctl.com/trstctl/internal/discovery/ctmonitor"
)

// fakePersist is an in-memory Persistence for scheduler tests.
type fakePersist struct {
	mu      sync.Mutex
	domains []string
	logs    []ctmonitor.LogState
	saved   map[string]int64
	saveSig chan struct{} // signaled on each SaveCheckpoint
}

type aud70MixedFetcher struct{}

func (aud70MixedFetcher) TreeSize(_ context.Context, logURL string) (int64, error) {
	if logURL == "dead-log" {
		return 0, errors.New("RFC 6962 get-sth returned 404")
	}
	return 1, nil
}

func (aud70MixedFetcher) Entries(_ context.Context, _ string, start, end int64) ([]ctlog.Entry, error) {
	if start != 0 || end != 1 {
		return nil, errors.New("unexpected entry range")
	}
	return []ctlog.Entry{entry("shadow.example.com")}, nil
}

func newFakePersist(domains []string, logs []ctmonitor.LogState) *fakePersist {
	return &fakePersist{domains: domains, logs: logs, saved: map[string]int64{}, saveSig: make(chan struct{}, 16)}
}

func (f *fakePersist) WatchedDomains(context.Context, string) ([]string, error) {
	return f.domains, nil
}

func (f *fakePersist) Checkpoints(context.Context, string) ([]ctmonitor.LogState, error) {
	return f.logs, nil
}

func (f *fakePersist) SaveCheckpoint(_ context.Context, _ string, logURL string, next int64) error {
	f.mu.Lock()
	f.saved[logURL] = next
	f.mu.Unlock()
	select {
	case f.saveSig <- struct{}{}:
	default:
	}
	return nil
}

func (f *fakePersist) SavePollResult(ctx context.Context, tenantID string, result ctmonitor.LogPollResult) error {
	if result.Status != ctmonitor.LogPollSucceeded {
		return nil
	}
	return f.SaveCheckpoint(ctx, tenantID, result.URL, result.Checkpoint)
}

func (f *fakePersist) savedFor(logURL string) (int64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.saved[logURL]
	return v, ok
}

// RunOnce loads the tenant's domains and checkpoints, polls, raises alerts on
// unexpected issuance, and persists the advanced checkpoints.
func TestSchedulerRunOnceLoadsPollsSaves(t *testing.T) {
	fetch := &fakeFetcher{tree: []ctlog.Entry{entry("shadow.example.com")}}
	persist := newFakePersist([]string{"example.com"}, []ctmonitor.LogState{{URL: "log-a", Checkpoint: 0}})
	alerter := ctmonitor.NewMemoryAlerter()
	kg := ctmonitor.KnownGoodFunc(func(context.Context, string, ctlog.Entry) (bool, error) { return false, nil })

	sched := ctmonitor.NewScheduler(persist, fetch, kg, alerter)

	findings, err := sched.RunOnce(context.Background(), tenant)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(findings) != 1 || len(alerter.Raised()) != 1 {
		t.Fatalf("findings=%d raised=%d, want 1/1", len(findings), len(alerter.Raised()))
	}
	if got, ok := persist.savedFor("log-a"); !ok || got != 1 {
		t.Errorf("persisted checkpoint = %d (ok=%v), want 1", got, ok)
	}
}

// AUD-70: one dead CT log is one failed log, not permission to erase the
// working log's checkpoint or hide its successful poll. The detailed result is
// the authority the served run and console use to report partial health.
func TestAUD70SchedulerPreservesSuccessfulProgressAndReportsEveryLog(t *testing.T) {
	persist := newFakePersist([]string{"example.com"}, []ctmonitor.LogState{
		{URL: "dead-log", Checkpoint: 4},
		{URL: "working-log", Checkpoint: 0},
	})
	sched := ctmonitor.NewScheduler(
		persist,
		aud70MixedFetcher{},
		ctmonitor.KnownGoodFunc(func(context.Context, string, ctlog.Entry) (bool, error) { return false, nil }),
		ctmonitor.NewMemoryAlerter(),
	)

	result, err := sched.RunOnceDetailed(context.Background(), tenant)
	if err == nil {
		t.Fatal("mixed CT pass error = nil, want honest partial failure")
	}
	if len(result.Logs) != 2 || len(result.Findings) != 1 {
		t.Fatalf("mixed CT result = %+v, want two log outcomes and one working-log finding", result)
	}
	outcomes := map[string]ctmonitor.LogPollResult{}
	for _, outcome := range result.Logs {
		outcomes[outcome.URL] = outcome
	}
	if dead := outcomes["dead-log"]; dead.Status != ctmonitor.LogPollFailed || dead.Checkpoint != 4 || dead.Error == "" {
		t.Fatalf("dead-log outcome = %+v, want failed at unchanged checkpoint with safe detail", dead)
	}
	if working := outcomes["working-log"]; working.Status != ctmonitor.LogPollSucceeded || working.Checkpoint != 1 || working.Error != "" {
		t.Fatalf("working-log outcome = %+v, want succeeded at checkpoint 1", working)
	}
	if got, ok := persist.savedFor("working-log"); !ok || got != 1 {
		t.Fatalf("working-log persisted checkpoint = %d (ok=%v), want 1 despite peer failure", got, ok)
	}
}

// With nothing configured the scheduler does no work.
func TestSchedulerRunOnceNoConfig(t *testing.T) {
	fetch := &fakeFetcher{tree: []ctlog.Entry{entry("shadow.example.com")}}
	persist := newFakePersist(nil, nil)
	sched := ctmonitor.NewScheduler(persist, fetch, ctmonitor.KnownGoodFunc(
		func(context.Context, string, ctlog.Entry) (bool, error) { return false, nil }), ctmonitor.NewMemoryAlerter())

	findings, err := sched.RunOnce(context.Background(), tenant)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %d, want 0 with no watched domains/logs", len(findings))
	}
}

// Run polls immediately, then loops until the context is canceled, returning
// cleanly.
func TestSchedulerRunStopsOnContextCancel(t *testing.T) {
	fetch := &fakeFetcher{tree: []ctlog.Entry{entry("shadow.example.com")}}
	persist := newFakePersist([]string{"example.com"}, []ctmonitor.LogState{{URL: "log-a", Checkpoint: 0}})
	sched := ctmonitor.NewScheduler(persist, fetch,
		ctmonitor.KnownGoodFunc(func(context.Context, string, ctlog.Entry) (bool, error) { return false, nil }),
		ctmonitor.NewMemoryAlerter(),
		ctmonitor.WithInterval(time.Hour)) // only the immediate poll runs

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sched.Run(ctx, tenant) }()

	// Wait for the immediate first poll to persist its checkpoint, then stop.
	select {
	case <-persist.saveSig:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("scheduler did not run an initial poll")
	}
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v, want nil on clean shutdown", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
	if got, _ := persist.savedFor("log-a"); got != 1 {
		t.Errorf("checkpoint after run = %d, want 1", got)
	}
}
