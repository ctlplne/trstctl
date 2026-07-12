// SPDX-License-Identifier: MPL-2.0

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
}

func newVaultCompatState(log *events.Log) *vaultCompatState {
	return &vaultCompatState{log: log}
}

func (s *vaultCompatState) snapshot(ctx context.Context, tenantID string) (vaultCompatSnapshot, error) {
	state := vaultCompatSnapshot{
		mounts:   map[string]vaultCompatMount{},
		policies: map[string]vaultCompatPolicy{},
	}
	if s == nil || s.log == nil {
		return state, nil
	}
	err := s.log.Replay(ctx, 0, func(ev events.Event) error {
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
	})
	return state, err
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
