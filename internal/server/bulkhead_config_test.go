package server

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
)

func TestRunConfigBulkheadsCreateConfiguredPools(t *testing.T) {
	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(t.TempDir(), "audit.pem")
	cfg.Bulkheads.API.Workers = 3
	cfg.Bulkheads.API.Queue = 17
	cfg.Bulkheads.Outbox.Workers = 2
	cfg.Bulkheads.Outbox.Queue = 19

	deps, err := buildRunDeps(cfg, nil, nil, runSigner{}, runSecrets{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("buildRunDeps: %v", err)
	}
	if deps.Bulkhead == nil {
		t.Fatal("buildRunDeps did not create the configured bulkhead set")
	}
	t.Cleanup(deps.Bulkhead.Close)

	stats := map[string]bulkhead.Stats{}
	for _, stat := range deps.Bulkhead.Stats() {
		stats[stat.Name] = stat
	}
	for name, want := range map[string]struct {
		workers int
		queue   int
	}{
		bulkhead.SubsystemAPI:    {workers: 3, queue: 17},
		bulkhead.SubsystemOutbox: {workers: 2, queue: 19},
	} {
		got := stats[name]
		if got.Workers != want.workers || got.Capacity != want.queue {
			t.Fatalf("%s stats = workers %d queue %d, want workers %d queue %d", name, got.Workers, got.Capacity, want.workers, want.queue)
		}
	}
}
