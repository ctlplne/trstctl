// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
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
	cfg.Bulkheads.OutboxConnectors = &config.BulkheadLimit{Workers: 1, Queue: 7}
	cfg.Bulkheads.KMIP.Workers = 5
	cfg.Bulkheads.KMIP.Queue = 23
	auditKey := testAuditSigningKey(t)

	deps, err := buildRunDeps(context.Background(), cfg, nil, nil, runSigner{}, runSecrets{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, auditKey)
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
		bulkhead.SubsystemAPI:                 {workers: 3, queue: 17},
		bulkhead.SubsystemKMIP:                {workers: 5, queue: 23},
		bulkhead.SubsystemOutbox:              {workers: 2, queue: 19},
		bulkhead.SubsystemOutboxExternalCA:    {workers: 2, queue: 19},
		bulkhead.SubsystemOutboxConnectors:    {workers: 1, queue: 7},
		bulkhead.SubsystemOutboxSecrets:       {workers: 2, queue: 19},
		bulkhead.SubsystemOutboxManagedKeys:   {workers: 2, queue: 19},
		bulkhead.SubsystemOutboxTransparency:  {workers: 2, queue: 19},
		bulkhead.SubsystemOutboxNotifications: {workers: 2, queue: 19},
		bulkhead.SubsystemOutboxTenantSeal:    {workers: 2, queue: 19},
		bulkhead.SubsystemOutboxFleet:         {workers: 2, queue: 19},
		bulkhead.SubsystemOutboxAuditFeeds:    {workers: 2, queue: 19},
	} {
		got := stats[name]
		if got.Workers != want.workers || got.Capacity != want.queue {
			t.Fatalf("%s stats = workers %d queue %d, want workers %d queue %d", name, got.Workers, got.Capacity, want.workers, want.queue)
		}
	}

	// The kmip lane is connection-scoped (a worker is held for an entire client
	// connection), so the CONFIG-DERIVED set — the one production actually
	// builds, not bulkhead.Default() — must give it a pool of its own. This is
	// the A2/V11 regression guard: the lane existed in Default() and tests
	// passed while every real deployment fell back to the shared protocols
	// pool.
	kmipPool := deps.Bulkhead.Pool(bulkhead.SubsystemKMIP)
	if kmipPool == nil {
		t.Fatal("config-derived bulkhead set has no kmip pool; production KMIP would fall back to a shared lane")
	}
	if kmipPool == deps.Bulkhead.Pool(bulkhead.SubsystemProtocols) {
		t.Fatal("config-derived kmip pool IS the protocols pool; connection-scoped KMIP would starve every issuance protocol")
	}
	if kmipPool == deps.Bulkhead.Pool(bulkhead.SubsystemAPI) {
		t.Fatal("config-derived kmip pool IS the API pool")
	}

	seen := map[*bulkhead.Pool]string{}
	for _, name := range []string{
		bulkhead.SubsystemOutbox,
		bulkhead.SubsystemOutboxExternalCA,
		bulkhead.SubsystemOutboxConnectors,
		bulkhead.SubsystemOutboxSecrets,
		bulkhead.SubsystemOutboxManagedKeys,
		bulkhead.SubsystemOutboxTransparency,
		bulkhead.SubsystemOutboxNotifications,
		bulkhead.SubsystemOutboxTenantSeal,
		bulkhead.SubsystemOutboxFleet,
		bulkhead.SubsystemOutboxAuditFeeds,
	} {
		pool := deps.Bulkhead.Pool(name)
		if prior, exists := seen[pool]; exists {
			t.Fatalf("outbox families %q and %q share one pool; saturation would leak", prior, name)
		}
		seen[pool] = name
	}
}
