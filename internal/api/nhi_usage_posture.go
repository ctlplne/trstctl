// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// Usage-based posture (M1). API tokens and machine login methods carry their
// recorded usage in the NHI inventory, so the stale posture flags a credential
// unused for N days, or used from a new source, with no operator input. A
// source becomes normal once the credential has been used from it on
// nhiUsageNormalDays different days; until then, while the credential also has
// a normal source, the new one is flagged. Missing telemetry is never read as
// non-use: before the first recorded use in a tenant nothing is called unused,
// and a recorded gap in the window suspends the verdict.

const nhiUsageNormalDays = 3

type credentialUsageIndex struct {
	kind    string
	since   *time.Time
	usage   map[string]store.CredentialUsage
	sources map[string][]store.CredentialUsageSource
}

func (a *API) credentialUsageIndex(ctx context.Context, tenantID, kind string, ids []string) (credentialUsageIndex, error) {
	idx := credentialUsageIndex{kind: kind}
	var err error
	if idx.usage, err = a.store.CredentialUsageFor(ctx, tenantID, kind, ids); err != nil {
		return idx, err
	}
	if idx.sources, err = a.store.CredentialUsageSourcesFor(ctx, tenantID, kind, ids); err != nil {
		return idx, err
	}
	if kind == store.CredentialUsageAPIToken {
		idx.since, err = a.store.CredentialUsageTrackingSince(ctx, tenantID)
	}
	return idx, err
}

// annotate adds a credential's recorded usage to its inventory metadata. A
// machine login method's usage is complete from its first login (every login
// is an event), so that is its tracking start.
func (idx credentialUsageIndex) annotate(meta map[string]any, id string) {
	meta["usage_tracked"] = true
	since := idx.since
	u, used := idx.usage[id]
	if idx.kind == store.CredentialUsageMachineAuth && used {
		first := u.FirstUsedAt.UTC()
		since = &first
	}
	if since != nil {
		meta["usage_tracked_since"] = since.UTC()
	}
	if used {
		meta["last_used_at"] = u.LastUsedAt.UTC()
		meta["last_used_source"] = u.LastSource
	}
	if sources := idx.sources[id]; len(sources) > 0 {
		list := make([]map[string]any, 0, len(sources))
		for _, src := range sources {
			list = append(list, map[string]any{
				"source_kind": src.SourceKind, "source": src.Source, "days_seen": src.DaysSeen,
				"first_seen_at": src.FirstSeenAt.UTC(), "last_seen_at": src.LastSeenAt.UTC(),
			})
		}
		meta["usage_sources"] = list
	}
}

type nhiStaleOptions struct {
	unusedDays int
	// gaps are recorded API-token usage gaps in the analysis window.
	gaps []store.CredentialUsageGap
}

func defaultNHIStaleOptions() nhiStaleOptions {
	return nhiStaleOptions{unusedDays: nhiUnusedNoActivityThresholdDays}
}

// nhiUsageUnused reports whether a usage-tracked credential has had no
// recorded use for opts.unusedDays, with the evidence for the verdict.
func nhiUsageUnused(item nhiInventoryItem, meta map[string]any, createdAt time.Time, lastUsed *time.Time, now time.Time, opts nhiStaleOptions) (bool, []string) {
	if expires := firstNHIPostureTimestamp(meta, "expires_at"); expires != nil && !expires.After(now) {
		return false, nil // an expired token cannot be used, so it is not idle
	}
	since := firstNHIPostureTimestamp(meta, "usage_tracked_since")
	if since == nil {
		return false, []string{"usage:not_recorded_yet"}
	}
	ref := createdAt
	if since.After(ref) {
		ref = *since
	}
	if lastUsed != nil && lastUsed.After(ref) {
		ref = *lastUsed
	}
	if daysSince(now, ref) < opts.unusedDays {
		return false, nil
	}
	if item.Source == "access_api_token" {
		for _, gap := range opts.gaps {
			if !gap.To.Before(ref) && !gap.From.After(now) {
				return false, []string{"usage:gap:" + gap.ID}
			}
		}
	}
	return true, []string{"usage:no_recorded_use_since:" + ref.UTC().Format(time.RFC3339)}
}

// nhiUsageNewSources lists the sources a credential is used from that are not
// yet normal, when it also has a normal source to compare them with.
func nhiUsageNewSources(meta map[string]any) []string {
	sources, _ := meta["usage_sources"].([]any)
	established := false
	var fresh []string
	for _, raw := range sources {
		src, _ := raw.(map[string]any)
		name, _ := src["source"].(string)
		days, _ := src["days_seen"].(float64)
		if name == "" {
			continue
		}
		if int(days) >= nhiUsageNormalDays {
			established = true
		} else {
			fresh = append(fresh, name)
		}
	}
	if !established {
		return nil
	}
	return fresh
}
