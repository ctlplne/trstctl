package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// TestHeavyReadRoutesUseSeparatePool is the SPINE-005 acceptance: the heavy
// O(inventory) read families (the credential graph + risk scoring) run on their OWN
// bounded bulkhead pool, so saturating them sheds on the query pool WITHOUT starving
// cheap CRUD on the api pool. The pre-fix tree wrapped /api+/auth+/enroll in one
// pool, so a graph flood could crowd out CRUD; this test proves the split by giving
// the query pool zero capacity (always rejects) while the api pool stays healthy, and
// asserting /graph + /risk shed (503) while /owners does NOT.
func TestHeavyReadRoutesUseSeparatePool(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()

	dsn, stopPG, err := startBundledPostgres(config.Postgres{Mode: config.PostgresBundled, DataDir: t.TempDir(), Port: freeTCPPort(t)})
	if err != nil {
		t.Fatalf("start bundled postgres: %v", err)
	}
	t.Cleanup(func() { _ = stopPG() })

	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		st.Close()
		t.Fatalf("migrate: %v", err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		st.Close()
		t.Fatalf("open event log: %v", err)
	}

	// A bulkhead set with a single-worker, zero-queue QUERY pool and a healthy API
	// pool. Occupying the query worker (below) makes it reject every further
	// submission, so if /graph and /risk are routed to the query pool (the fix) they
	// shed; if they were still on the api pool (the defect) they would be served.
	set := bulkhead.NewSet(
		bulkhead.Config{Name: bulkhead.SubsystemAPI, Workers: 4, Queue: 64},
		bulkhead.Config{Name: bulkhead.SubsystemQuery, Workers: 1, Queue: 0},
	)
	srv, err := Build(ctx, Deps{Store: st, Log: log, Bulkhead: set})
	if err != nil {
		_ = log.Close()
		st.Close()
		t.Fatalf("build control plane: %v", err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()

	// Occupy the query pool's only worker so it rejects every further submission for
	// the duration of the test (mirrors a sustained heavy-read flood).
	release := make(chan struct{})
	defer close(release)
	occupied := make(chan struct{})
	for {
		if err := set.Pool(bulkhead.SubsystemQuery).Submit(func() { close(occupied); <-release }); err == nil {
			break
		}
	}
	<-occupied

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	status := func(path string) int {
		req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	// The heavy read routes are on the saturated query pool -> shed with 503.
	for _, p := range []string{"/api/v1/graph", "/api/v1/risk/credentials"} {
		if got := status(p); got != http.StatusServiceUnavailable {
			t.Errorf("GET %s = %d, want 503 (heavy read must shed on the dedicated query pool)", p, got)
		}
	}

	// Cheap CRUD is on the healthy api pool -> NOT shed (it reaches auth, which 401s
	// without a credential; the point is it is not a 503 from a starved pool).
	if got := status("/api/v1/owners"); got == http.StatusServiceUnavailable {
		t.Errorf("GET /api/v1/owners = 503; CRUD must NOT be starved by the saturated query pool (SPINE-005)")
	}
}
