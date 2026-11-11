// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"time"

	agentdiscovery "trstctl.com/trstctl/internal/agent/discovery"
	"trstctl.com/trstctl/internal/store"
)

// P7-L2: an MCP server finding comes from a host's MCP client configuration
// report, which is the host's whole inventory each time. A server the host's
// newest report no longer lists is gone from the host: it reads removed_at,
// the time of that report, and leaves the open shadow posture. Its triage is
// kept, and it reads present again if a later report lists it.

// completeInventoryKind reports whether findings of this kind come only from
// sources whose every report lists everything they hold.
func completeInventoryKind(kind string) bool { return kind == agentdiscovery.FindingKindMCPServer }

// removedFromSource is when the newest successful run of each finding's
// source stopped listing it, for findings of complete-inventory kinds; a
// finding still listed is absent from the map.
func (a *API) removedFromSource(ctx context.Context, tenantID string, findings []store.DiscoveryFinding) (map[string]time.Time, error) {
	sources := map[string]bool{}
	for _, f := range findings {
		if completeInventoryKind(f.Kind) {
			sources[f.SourceID] = true
		}
	}
	out := map[string]time.Time{}
	if len(sources) == 0 {
		return out, nil
	}
	ids := make([]string, 0, len(sources))
	for id := range sources {
		ids = append(ids, id)
	}
	latest, err := a.store.LatestSucceededDiscoveryRuns(ctx, tenantID, ids)
	if err != nil {
		return nil, err
	}
	for _, f := range findings {
		if run, ok := latest[f.SourceID]; ok && completeInventoryKind(f.Kind) && run.ID != f.RunID {
			out[f.ID] = run.CompletedAt
		}
	}
	return out, nil
}

// withRemovedFromSource marks the findings their source no longer lists.
func (a *API) withRemovedFromSource(ctx context.Context, tenantID string, findings []store.DiscoveryFinding, items []discoveryFindingResponse) error {
	removed, err := a.removedFromSource(ctx, tenantID, findings)
	if err != nil {
		return err
	}
	for i := range items {
		if at, ok := removed[items[i].ID]; ok {
			at := at
			items[i].RemovedAt = &at
		}
	}
	return nil
}
