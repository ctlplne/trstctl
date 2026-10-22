// SPDX-License-Identifier: BUSL-1.1

package agentupgrade

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// RingCandidate is an unassigned, not offboarded agent the planner may place
// in a ring (A69). Only what the choice needs: identity, enrollment age and
// the last heartbeat.
type RingCandidate struct {
	AgentID    string
	Name       string
	Version    string
	EnrolledAt time.Time
	LastSeenAt *time.Time
}

// AutoAssignment is one deterministic placement of candidates into the three
// rings. Every candidate lands in exactly one ring.
type AutoAssignment struct {
	Canary []RingCandidate
	Early  []RingCandidate
	Broad  []RingCandidate
}

const (
	// DefaultAutoCanaryCount is one machine: the smallest ring whose failure
	// still stops a rollout, which is the point of a canary.
	DefaultAutoCanaryCount = 1
	// DefaultAutoEarlyPercent places a tenth of what is left after the canary in
	// the early ring, rounded up so the ring is never empty.
	DefaultAutoEarlyPercent = 10
	// minAutoCandidates is the fewest unassigned agents that can fill three
	// rings. An empty ring halts the campaign by design, so the planner refuses
	// to produce one rather than hand the sweep a rollout that cannot advance.
	minAutoCandidates = 3
)

// ErrAutoRingsTooFew says the fleet is too small to fill three rings; the
// operator assigns by hand or enrolls more agents.
var ErrAutoRingsTooFew = errors.New("agentupgrade: fewer than three unassigned agents; every ring must hold at least one, assign by hand")

// PlanAutoRings places candidates deterministically (A69). Order: agents seen
// within the freshness window first (an agent that has not heartbeated is no
// canary — its silence would halt the rollout before the build was ever
// tried), then the longest-enrolled, then by name. The first canaryCount
// become the canary, the next ceil(earlyPercent% of the rest) the early ring,
// and everything else broad; each ring keeps at least one agent. now and
// fresh decide which heartbeats count as current.
func PlanAutoRings(candidates []RingCandidate, canaryCount, earlyPercent int, now time.Time, fresh time.Duration) (AutoAssignment, error) {
	if canaryCount <= 0 {
		canaryCount = DefaultAutoCanaryCount
	}
	if earlyPercent <= 0 {
		earlyPercent = DefaultAutoEarlyPercent
	}
	if earlyPercent > 90 {
		return AutoAssignment{}, fmt.Errorf("agentupgrade: early_percent %d leaves no broad ring; use at most 90", earlyPercent)
	}
	if len(candidates) < minAutoCandidates {
		return AutoAssignment{}, ErrAutoRingsTooFew
	}
	if canaryCount > len(candidates)-2 {
		return AutoAssignment{}, fmt.Errorf("agentupgrade: canary_count %d leaves fewer than one agent each for early and broad among %d unassigned agents", canaryCount, len(candidates))
	}
	ordered := append([]RingCandidate(nil), candidates...)
	isFresh := func(c RingCandidate) bool {
		return c.LastSeenAt != nil && fresh > 0 && !c.LastSeenAt.Before(now.Add(-fresh))
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		fi, fj := isFresh(ordered[i]), isFresh(ordered[j])
		if fi != fj {
			return fi
		}
		if !ordered[i].EnrolledAt.Equal(ordered[j].EnrolledAt) {
			return ordered[i].EnrolledAt.Before(ordered[j].EnrolledAt)
		}
		if ordered[i].Name != ordered[j].Name {
			return ordered[i].Name < ordered[j].Name
		}
		return ordered[i].AgentID < ordered[j].AgentID
	})
	rest := len(ordered) - canaryCount
	early := (rest*earlyPercent + 99) / 100
	if early < 1 {
		early = 1
	}
	if early > rest-1 {
		early = rest - 1
	}
	out := AutoAssignment{
		Canary: ordered[:canaryCount],
		Early:  ordered[canaryCount : canaryCount+early],
		Broad:  ordered[canaryCount+early:],
	}
	return out, nil
}
