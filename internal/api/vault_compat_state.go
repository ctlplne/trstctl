// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/events"
)

const (
	vaultMountEnabledEventType  = "vault.compat.mount.enabled"
	vaultMountDisabledEventType = "vault.compat.mount.disabled"
	vaultPolicyPutEventType     = "vault.compat.policy.put"
	vaultPolicyDeletedEventType = "vault.compat.policy.deleted"

	maxVaultPolicyBytes = 256 << 10
)

type vaultCompatMount struct {
	Path        string            `json:"path"`
	Type        string            `json:"type"`
	Description string            `json:"description,omitempty"`
	Options     map[string]string `json:"options,omitempty"`
}

type vaultCompatPolicy struct {
	Name   string `json:"name"`
	Policy string `json:"policy"`
}

type vaultCompatSnapshot struct {
	mounts   map[string]vaultCompatMount
	policies map[string]vaultCompatPolicy
}

// vaultCompatState is an event-log projection for the mutable compatibility
// metadata. It deliberately owns no database and no process-local source of
// truth: every read deterministically replays tenant-filtered events (AN-1/AN-2).
type vaultCompatState struct {
	log *events.Log

	// memo is the shared head-keyed projection cache (F4/V27b) carrying F3's
	// incremental catch-up. The projection itself is still a deterministic
	// replay — the memo only avoids redoing work already reflected at the head.
	memo headMemo[vaultCompatSnapshot]
}

func newVaultCompatState(log *events.Log) *vaultCompatState {
	return &vaultCompatState{log: log}
}

// snapshot returns the tenant's compatibility projection.
//
// It is memoized against the event log's head sequence because it sits INSIDE
// the authorization path of every Vault-compatible request, and it was replaying
// the entire event log from sequence 0 each time. On a deployment with any real
// history that turns every request into an O(all events) scan, and the cost
// grows forever — an availability cliff that arrives silently with age rather
// than with load.
//
// Correctness is unchanged: the cache is keyed on the log head, so any appended
// event invalidates it. Reusing a projection while the log has not moved cannot
// observe a different state than replaying would.
func (s *vaultCompatState) snapshot(ctx context.Context, tenantID string) (vaultCompatSnapshot, error) {
	if s == nil {
		snap, _, err := (&vaultCompatState{}).replaySnapshot(ctx, tenantID)
		return snap, err
	}
	// The head is GLOBAL (one stream), so any tenant's append moves it. The
	// shared memo catches up incrementally from the cached sequence onto a
	// COPY (F3/V27a) — the cached maps are aliased by snapshots already
	// returned to callers — and falls back to a from-zero rebuild on any
	// catch-up failure or head regression.
	return s.memo.get(ctx, s.log, tenantID,
		func(ctx context.Context) (vaultCompatSnapshot, uint64, error) { return s.replaySnapshot(ctx, tenantID) },
		&headMemoHooks[vaultCompatSnapshot]{
			Copy: copyVaultSnapshot,
			Fold: func(state *vaultCompatSnapshot, ev events.Event) error {
				return foldVaultCompatEvent(state, tenantID, ev)
			},
		})
}

// copyVaultSnapshot deep-copies the map structure. The values are plain structs,
// so copying the maps is enough to keep previously returned snapshots immutable.
func copyVaultSnapshot(in vaultCompatSnapshot) vaultCompatSnapshot {
	out := vaultCompatSnapshot{
		mounts:   make(map[string]vaultCompatMount, len(in.mounts)),
		policies: make(map[string]vaultCompatPolicy, len(in.policies)),
	}
	for k, v := range in.mounts {
		out.mounts[k] = v
	}
	for k, v := range in.policies {
		out.policies[k] = v
	}
	return out
}

func (s *vaultCompatState) replaySnapshot(ctx context.Context, tenantID string) (vaultCompatSnapshot, uint64, error) {
	state := vaultCompatSnapshot{
		mounts:   map[string]vaultCompatMount{},
		policies: map[string]vaultCompatPolicy{},
	}
	if s == nil || s.log == nil {
		return state, 0, nil
	}
	var through uint64
	err := s.log.Replay(ctx, 0, func(ev events.Event) error {
		s.memo.scannedEvents.Add(1)
		through = ev.Sequence
		return foldVaultCompatEvent(&state, tenantID, ev)
	})
	return state, through, err
}

// foldVaultCompatEvent applies one event to the projection. Full rebuilds and
// incremental catch-ups fold through this single function, so the two paths
// cannot disagree about an event's meaning.
func foldVaultCompatEvent(state *vaultCompatSnapshot, tenantID string, ev events.Event) error {
	if ev.TenantID != tenantID {
		return nil
	}
	switch ev.Type {
	case vaultMountEnabledEventType:
		var mount vaultCompatMount
		if err := json.Unmarshal(ev.Data, &mount); err != nil {
			return fmt.Errorf("vault mount-enabled event: %w", err)
		}
		if mount.Path == "" || mount.Type == "" {
			return errors.New("vault mount-enabled event is missing path or type")
		}
		state.mounts[mount.Path] = mount
	case vaultMountDisabledEventType:
		var mount vaultCompatMount
		if err := json.Unmarshal(ev.Data, &mount); err != nil {
			return fmt.Errorf("vault mount-disabled event: %w", err)
		}
		if mount.Path == "" {
			return errors.New("vault mount-disabled event is missing path")
		}
		delete(state.mounts, mount.Path)
	case vaultPolicyPutEventType:
		var policy vaultCompatPolicy
		if err := json.Unmarshal(ev.Data, &policy); err != nil {
			return fmt.Errorf("vault policy-put event: %w", err)
		}
		if policy.Name == "" || policy.Policy == "" {
			return errors.New("vault policy-put event is missing name or policy")
		}
		state.policies[policy.Name] = policy
	case vaultPolicyDeletedEventType:
		var policy vaultCompatPolicy
		if err := json.Unmarshal(ev.Data, &policy); err != nil {
			return fmt.Errorf("vault policy-deleted event: %w", err)
		}
		if policy.Name == "" {
			return errors.New("vault policy-deleted event is missing name")
		}
		delete(state.policies, policy.Name)
	}
	return nil
}

func (s *vaultCompatState) append(ctx context.Context, tenantID, eventType string, payload any) (events.Event, error) {
	if s == nil || s.log == nil {
		return events.Event{}, errors.New("vault compatibility event log is not configured")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return events.Event{}, err
	}
	return s.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: data})
}

func normalizeVaultMountPath(raw string) (string, error) {
	path := strings.Trim(strings.TrimSpace(raw), "/")
	if path == "" {
		return "", errors.New("mount path is required")
	}
	if strings.Contains(path, "/") || strings.Contains(path, "..") || strings.ContainsAny(path, "?#\\") {
		return "", errors.New("mount path contains an invalid segment")
	}
	first, _, _ := strings.Cut(path, "/")
	if first == "sys" || first == "auth" {
		return "", errors.New("sys and auth are reserved mount paths")
	}
	return path, nil
}

func normalizeVaultPolicyName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", errors.New("policy name is required")
	}
	if len(name) > 128 || strings.ContainsAny(name, "/\\?#") || name == "root" {
		return "", errors.New("policy name is invalid")
	}
	return name, nil
}

func sortedVaultPolicyNames(policies map[string]vaultCompatPolicy) []string {
	names := make([]string, 0, len(policies))
	for name := range policies {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
