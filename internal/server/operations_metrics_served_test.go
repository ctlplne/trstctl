// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

// TestBuiltServerServesConfiguredBulkheadStats is the assembled-runtime guard
// for the Jobs and queues worker evidence. API-only tests prove the response
// shape, but they cannot catch startup ordering that forgets to attach the real
// pool provider. A built control plane must report the exact configured pools,
// not the truthful-but-wrong-for-this-runtime served=false fallback.
func TestBuiltServerServesConfiguredBulkheadStats(t *testing.T) {
	if testing.Short() {
		t.Skip("starts embedded PostgreSQL and NATS; skipped in -short")
	}
	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	registerServerTestTenant(t, st, log, "44444444-4444-4444-8444-444444444444", "Bulkhead metrics fixture")
	set := bulkhead.NewSet(
		bulkhead.Config{Name: bulkhead.SubsystemAPI, Workers: 3, Queue: 17},
		bulkhead.Config{Name: bulkhead.SubsystemOutbox, Workers: 2, Queue: 11},
	)
	srv, err := Build(ctx, Deps{
		Store: st, Log: log, Bulkhead: set,
		APIOptions: []api.Option{api.WithInsecureHeaderResolver()},
	})
	if err != nil {
		_ = log.Close()
		set.Close()
		t.Fatalf("build control plane: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/operations/bulkheads", nil)
	req.Header.Set("X-Tenant-ID", "44444444-4444-4444-8444-444444444444")
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET bulkhead stats = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Served bool `json:"served"`
		Pools  []struct {
			Name     string `json:"name"`
			Workers  int    `json:"workers"`
			Capacity int    `json:"capacity"`
		} `json:"pools"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode bulkhead stats: %v", err)
	}
	if !body.Served {
		t.Fatal("built server reported served=false even though its bulkhead set is configured")
	}
	if len(body.Pools) != 2 {
		t.Fatalf("pools = %+v, want both configured pools", body.Pools)
	}
	if body.Pools[0].Name != bulkhead.SubsystemAPI || body.Pools[0].Workers != 3 || body.Pools[0].Capacity != 17 {
		t.Fatalf("api pool = %+v, want workers=3 capacity=17", body.Pools[0])
	}
	if body.Pools[1].Name != bulkhead.SubsystemOutbox || body.Pools[1].Workers != 2 || body.Pools[1].Capacity != 11 {
		t.Fatalf("outbox pool = %+v, want workers=2 capacity=11", body.Pools[1])
	}
}
