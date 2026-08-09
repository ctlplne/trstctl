// SPDX-License-Identifier: LicenseRef-trstctl-EE

package silo

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenancy"
)

// laneDrillHarness stands up the REAL substrate the drill runs against in
// production: embedded PostgreSQL carrying the durable silo registry, embedded
// JetStream as the event spine, and the global tenancy router pointed at the
// registry exactly as InstallDurable points it. No mocks — the drill's whole
// reason to exist is observing the live spine.
type laneDrillHarness struct {
	store    *corestore.Store
	log      *events.Log
	registry *PGRegistry
	router   *Router
}

func newLaneDrillHarness(t *testing.T) *laneDrillHarness {
	t.Helper()
	if testing.Short() {
		t.Skip("boots embedded PostgreSQL + embedded JetStream; skipped in -short")
	}
	ctx := context.Background()
	dir := t.TempDir()

	pgDir, err := os.MkdirTemp("", "trstctl-lanedrill-pg")
	if err != nil {
		t.Fatal(err)
	}
	port := freeLaneDrillPort(t)
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).Port(port).
		RuntimePath(pgDir + "/rt").DataPath(pgDir + "/data").BinariesPath(pgDir + "/bin").
		Logger(io.Discard).StartTimeout(60 * time.Second))
	if err := pg.Start(); err != nil {
		_ = os.RemoveAll(pgDir)
		t.Skipf("embedded postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = pg.Stop(); _ = os.RemoveAll(pgDir) })

	dsn := fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port)
	cs, err := corestore.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("core store open: %v", err)
	}
	t.Cleanup(cs.Close)
	if err := cs.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(dir, "nats")})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	registry := NewPGRegistry(cs)
	router := NewRouter(registry, time.Minute)
	previous := tenancy.CurrentRouter()
	tenancy.SetRouter(router)
	t.Cleanup(func() { tenancy.SetRouter(previous) })

	return &laneDrillHarness{store: cs, log: log, registry: registry, router: router}
}

func freeLaneDrillPort(t *testing.T) uint32 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	p := l.Addr().(*net.TCPAddr).Port
	if p <= 0 || p > math.MaxUint16 {
		t.Fatalf("ephemeral port %d out of range", p)
	}
	return uint32(p) // #nosec G115 -- bounds-checked to [1, MaxUint16] above (CWE-190)
}

func checksByName(checks []corestore.IsolationDrillCheck) map[string]corestore.IsolationDrillCheck {
	out := map[string]corestore.IsolationDrillCheck{}
	for _, c := range checks {
		out[c.Name] = c
	}
	return out
}

// TestLaneDrill_LiveStreamProvesLaneIsolation is the L4 event-lane dimension
// run for real: probe tenants placed in the durable registry, probe events
// appended through the live router onto embedded JetStream, and the lane
// counts observed on the actual stream. Every check must pass, the probe
// placements must be gone afterwards, and the probe slugs collide under
// normalization on purpose — the historical breach shape must not recur.
func TestLaneDrill_LiveStreamProvesLaneIsolation(t *testing.T) {
	h := newLaneDrillHarness(t)
	drill := NewLaneDrill(h.registry, h.router, h.log)

	checks := drill.Run(context.Background())
	byName := checksByName(checks)
	for _, name := range []string{"event_lane_disjoint", "event_lane_active", "event_lane_cross_isolation", "event_lane_cleanup"} {
		c, ok := byName[name]
		if !ok {
			t.Fatalf("drill did not run check %q (got %v)", name, checks)
		}
		if !c.Passed {
			t.Fatalf("check %q failed on a healthy deployment: %s", name, c.Detail)
		}
	}

	// The registry holds no probe residue (the drill verified this itself;
	// verify independently so a broken self-verification cannot vouch for
	// itself).
	snapshot, err := h.registry.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	for id := range snapshot {
		if strings.HasPrefix(id, laneDrillProbePrefix) {
			t.Fatalf("probe placement %s survived the drill", id)
		}
	}

	// A second run passes too: the drill is repeatable, and the prior run's
	// permanent probe EVENTS (append-only log, by design) must not poison the
	// next run's baselines.
	second := checksByName(drill.Run(context.Background()))
	for name, c := range second {
		if !c.Passed {
			t.Fatalf("repeat drill check %q failed: %s", name, c.Detail)
		}
	}
}

// TestLaneDrill_SeededBreachFails proves the drill DETECTS rather than assumes,
// in both breach directions the architecture has actually worried about:
// (1) a lane-derivation regression that collides two tenants onto one lane must
// fail the disjointness check; (2) laning silently OFF — appends landing on the
// unlaned shared subject — must fail the active check rather than passing by
// vacuity. A drill that cannot fail is ceremony, not assurance.
func TestLaneDrill_SeededBreachFails(t *testing.T) {
	h := newLaneDrillHarness(t)

	// Direction 1: colliding derivation (the pre-fix slug-keyed bug, seeded).
	collided := NewLaneDrill(h.registry, h.router, h.log)
	collided.laneFor = func(_, slug string) string { return "t-" + identifierPart(slug, "-") }
	byName := checksByName(collided.Run(context.Background()))
	c, ok := byName["event_lane_disjoint"]
	if !ok {
		t.Fatal("collided drill did not run the disjointness check")
	}
	if c.Passed {
		t.Fatal("a colliding lane derivation PASSED the disjointness check — the drill assumes instead of detecting")
	}

	// Direction 2: laning off. The global router reads an EMPTY registry (the
	// probes are placed in the drill's registry but the router the APPEND path
	// consults knows nothing of them), so probe appends land on the unlaned
	// shared subject and the tenant's own lane count must not move.
	emptyRouter := NewRouter(NewMemRegistry(), time.Minute)
	previous := tenancy.CurrentRouter()
	tenancy.SetRouter(emptyRouter)
	t.Cleanup(func() { tenancy.SetRouter(previous) })

	unlaned := NewLaneDrill(h.registry, h.router, h.log)
	byName = checksByName(unlaned.Run(context.Background()))
	c, ok = byName["event_lane_active"]
	if !ok {
		t.Fatalf("unlaned drill did not reach the active check (checks: %v)", byName)
	}
	if c.Passed {
		t.Fatal("with per-tenant laning inactive the drill still reported event_lane_active passed — it must observe the live stream, not the derivation")
	}
}
