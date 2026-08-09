// SPDX-License-Identifier: MPL-2.0

package events

import (
	"context"
	"fmt"
	"strings"

	"github.com/nats-io/nats.go/jetstream"
)

// LaneSubjectCount reports how many events the ACTIVE stream holds under one
// tenant subject lane — the "events.<lane>.>" subjects a siloed tenant's
// appends are routed to. It is a READ-ONLY probe over stream metadata (a
// filtered StreamInfo, no consumer is created and no message is touched), built
// for the L4 isolation drill: proving live that one tenant's lane holds its
// probe event while a neighbour's lane count is undisturbed is what turns lane
// disjointness from a derivation property into an observed one.
//
// The lane is a single subject token: wildcards, dots, and whitespace are
// refused rather than interpreted, so a caller cannot widen the filter into a
// cross-lane read by construction.
func (l *Log) LaneSubjectCount(ctx context.Context, lane string) (uint64, error) {
	if lane == "" || strings.ContainsAny(lane, ".*>\t ") {
		return 0, fmt.Errorf("events: invalid subject lane %q", lane)
	}
	_, stream, err := l.resolveActiveStream(ctx)
	if err != nil {
		return 0, fmt.Errorf("events: resolve stream for lane count: %w", err)
	}
	info, err := stream.Info(ctx, jetstream.WithSubjectFilter(subjectPrefix+"."+lane+".>"))
	if err != nil {
		return 0, fmt.Errorf("events: lane subject info: %w", err)
	}
	var n uint64
	for _, count := range info.State.Subjects {
		n += count
	}
	return n, nil
}
