// SPDX-License-Identifier: LicenseRef-trstctl-EE

package silo

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	corestore "trstctl.com/trstctl/internal/store"
)

// The LIVE event-lane dimension of the L4 isolation drill.
//
// The structural test in this package proves distinct tenants DERIVE distinct
// lanes; the doctor's ISO probes prove the PostgreSQL dimensions against the
// real database. What neither proves is that the deployment's actual JetStream
// carries per-lane subjects and keeps them apart — that the router is ACTIVE on
// the live spine, not merely correct on paper. This drill closes that gap: it
// places two ephemeral probe tenants, appends one real enveloped event as each
// through the normal AN-2 path (so the subject derives from the real router),
// and observes on the live stream that each lane gained exactly its own event
// and the neighbour's lane was undisturbed.
//
// The probe slugs are chosen to COLLIDE under slug normalization — the exact
// shape of the lane-collision breach this package fixed — so a regression to
// slug-keyed lanes fails the drill rather than passing it politely.
//
// Probe EVENTS remain in the log by design: the log is append-only (AN-2), the
// sanctioned Delete primitive is documented as forbidden for production use,
// and two tiny events per operator-triggered drill are the drill's own audit
// trail rather than litter. Probe REGISTRY rows are removed and the removal is
// verified — read-model state cleans up; history does not.

// laneDrillProbePrefix is the reserved synthetic prefix of every drill probe
// tenant. Deliberately identical to the store drill's isolationProbePrefix and
// the doctor's ProbeTenantPrefix so every residue sweep recognises — and
// refuses to ignore — anything a drill leaves behind. Keep the three in
// lockstep.
const laneDrillProbePrefix = "00000000-d0c7"

// LaneProbeEventType is the event type the drill appends under a probe tenant.
// Projections skip unknown types (the skip-or-carry rule), so the probe is
// inert everywhere except the drill that reads its lane placement back.
const LaneProbeEventType = "silo.isolation.probe"

func newLaneProbeTenantID() string {
	tail := uuid.NewString()
	return laneDrillProbePrefix + "-4" + tail[15:]
}

// LaneDrillLog is the slice of the event log the drill needs: the normal
// append path (so subjects derive from the real router) and the read-only
// lane count.
type LaneDrillLog interface {
	Append(ctx context.Context, e events.Event) (events.Event, error)
	LaneSubjectCount(ctx context.Context, lane string) (uint64, error)
}

// LaneDrill runs the event-lane checks against the live deployment.
type LaneDrill struct {
	Registry *PGRegistry
	Router   *Router
	Log      LaneDrillLog
	// laneFor overrides lane derivation so a test can seed a breach (a
	// colliding derivation MUST fail the drill). Nil means the production
	// SubjectLane.
	laneFor func(tenantID, slug string) string
}

// NewLaneDrill builds the drill over the durable registry, its router, and the
// deployment's event log.
func NewLaneDrill(registry *PGRegistry, router *Router, log LaneDrillLog) *LaneDrill {
	return &LaneDrill{Registry: registry, Router: router, Log: log}
}

// Run executes the event-lane checks and reports them in the same shape as the
// store drill so the provider surface serves one merged report. It never
// returns early on a failed CHECK — a failed drill is a result — but it stops
// probing when the substrate itself cannot answer. The return is NAMED so the
// deferred cleanup verification lands in the report the caller receives.
func (d *LaneDrill) Run(ctx context.Context) (checks []corestore.IsolationDrillCheck) {
	fail := func(name, detail string) {
		checks = append(checks, corestore.IsolationDrillCheck{Name: name, Passed: false, Detail: detail})
	}
	pass := func(name, detail string) {
		checks = append(checks, corestore.IsolationDrillCheck{Name: name, Passed: true, Detail: detail})
	}
	if d == nil || d.Registry == nil || d.Router == nil || d.Log == nil {
		fail("event_lane_substrate", "lane drill is missing its registry, router, or event log; refusing to report a pass nothing tested")
		return checks
	}

	probeA, probeB := newLaneProbeTenantID(), newLaneProbeTenantID()
	// Slugs that normalize identically: the load-bearing collision scenario.
	// ID-keyed lanes keep them distinct; a slug-keyed regression collides them.
	slugA, slugB := "isodrill-lane", "isodrill.lane"

	// Verified cleanup of REGISTRY rows runs however the drill exits. Probe
	// events stay in the append-only log by design (see the file comment).
	defer func() {
		_ = d.Registry.Remove(ctx, probeA)
		_ = d.Registry.Remove(ctx, probeB)
		d.Router.Invalidate()
		snapshot, err := d.Registry.Snapshot(ctx)
		if err != nil {
			fail("event_lane_cleanup", "registry cleanup verification failed: "+err.Error())
			return
		}
		residue := 0
		for id := range snapshot {
			if strings.HasPrefix(id, laneDrillProbePrefix) {
				residue++
			}
		}
		if residue > 0 {
			fail("event_lane_cleanup", fmt.Sprintf("%d probe placement(s) survived cleanup under prefix %s*", residue, laneDrillProbePrefix))
			return
		}
		pass("event_lane_cleanup", "probe placements fully removed (verified zero residue); probe events remain in the append-only log as the drill's own audit trail")
	}()

	if err := d.Registry.Place(ctx, probeA, slugA, "siloed", "", TenantActive); err != nil {
		fail("event_lane_substrate", "could not place probe tenant A: "+err.Error())
		return checks
	}
	if err := d.Registry.Place(ctx, probeB, slugB, "siloed", "", TenantActive); err != nil {
		fail("event_lane_substrate", "could not place probe tenant B: "+err.Error())
		return checks
	}
	d.Router.Invalidate()

	laneOf := d.laneFor
	if laneOf == nil {
		laneOf = SubjectLane
	}
	laneA, laneB := laneOf(probeA, slugA), laneOf(probeB, slugB)

	// Check 1 — derived disjointness, under deliberately colliding slugs.
	if laneA == "" || laneB == "" || laneA == laneB {
		fail("event_lane_disjoint", fmt.Sprintf(
			"two distinct probe tenants derived lanes %q and %q under colliding slugs; distinct tenants MUST get distinct event lanes", laneA, laneB))
		// The live checks below would read one shared lane and mislead;
		// disjointness is their precondition, so stop here.
		return checks
	}
	pass("event_lane_disjoint", fmt.Sprintf("distinct probe tenants derived distinct lanes (%q, %q) despite slugs that normalize identically", laneA, laneB))

	baseA, errA := d.Log.LaneSubjectCount(ctx, laneA)
	baseB, errB := d.Log.LaneSubjectCount(ctx, laneB)
	if errA != nil || errB != nil {
		fail("event_lane_substrate", fmt.Sprintf("could not read baseline lane counts (a: %v, b: %v)", errA, errB))
		return checks
	}

	// Append one real enveloped probe event per tenant through the NORMAL
	// path, so the subject derives from the live router — the thing under test.
	if _, err := d.Log.Append(ctx, events.Event{
		Type: LaneProbeEventType, TenantID: probeA,
		Data: []byte(fmt.Sprintf(`{"drill":"event-lane","tenant":%q}`, probeA)),
	}); err != nil {
		fail("event_lane_substrate", "could not append probe event as tenant A: "+err.Error())
		return checks
	}
	afterA_A, errA := d.Log.LaneSubjectCount(ctx, laneA)
	afterA_B, errB := d.Log.LaneSubjectCount(ctx, laneB)
	if errA != nil || errB != nil {
		fail("event_lane_substrate", fmt.Sprintf("could not read lane counts after tenant A's append (a: %v, b: %v)", errA, errB))
		return checks
	}

	// Check 2 — laning is ACTIVE: tenant A's append landed on tenant A's lane.
	// A deployment where laning is silently off appends to the unlaned subject
	// and this count does not move — which must FAIL, not pass by vacuity.
	if afterA_A != baseA+1 {
		fail("event_lane_active", fmt.Sprintf(
			"tenant A's probe append did not land on its own lane (count %d -> %d); per-tenant event laning is not active on the live stream", baseA, afterA_A))
	} else {
		pass("event_lane_active", "a probe append routed through the live router landed on the tenant's own lane subject")
	}

	// Check 3 — cross-lane isolation, A's write direction: B's lane undisturbed.
	if afterA_B != baseB {
		fail("event_lane_cross_isolation", fmt.Sprintf(
			"tenant A's probe append moved tenant B's lane count (%d -> %d); one tenant's events are landing in another's lane", baseB, afterA_B))
		return checks
	}

	if _, err := d.Log.Append(ctx, events.Event{
		Type: LaneProbeEventType, TenantID: probeB,
		Data: []byte(fmt.Sprintf(`{"drill":"event-lane","tenant":%q}`, probeB)),
	}); err != nil {
		fail("event_lane_substrate", "could not append probe event as tenant B: "+err.Error())
		return checks
	}
	afterB_A, errA := d.Log.LaneSubjectCount(ctx, laneA)
	afterB_B, errB := d.Log.LaneSubjectCount(ctx, laneB)
	if errA != nil || errB != nil {
		fail("event_lane_substrate", fmt.Sprintf("could not read lane counts after tenant B's append (a: %v, b: %v)", errA, errB))
		return checks
	}

	// Check 3 (both directions complete) — B's append lands on B's lane and
	// leaves A's untouched.
	switch {
	case afterB_B != baseB+1:
		fail("event_lane_cross_isolation", fmt.Sprintf(
			"tenant B's probe append did not land on its own lane (count %d -> %d)", baseB, afterB_B))
	case afterB_A != afterA_A:
		fail("event_lane_cross_isolation", fmt.Sprintf(
			"tenant B's probe append moved tenant A's lane count (%d -> %d); one tenant's events are landing in another's lane", afterA_A, afterB_A))
	default:
		pass("event_lane_cross_isolation", "each probe tenant's append landed on its own lane and left the neighbour's lane count undisturbed, observed on the live stream in both directions")
	}
	return checks
}
