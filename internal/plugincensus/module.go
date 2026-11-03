// SPDX-License-Identifier: BUSL-1.1

package plugincensus

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Module states a relay reports (A242).
const (
	ModuleStateLoaded           = "loaded"
	ModuleStateAwaitingApproval = "awaiting-approval"
	ModuleStateIncompatible     = "incompatible"
)

// Module is a connector module's manifest metadata, its state on the relay and
// its health (A242). Metadata only: names, enums, numbers and the operator-
// facing descriptions of its setup inputs; never module bytes, keys,
// credentials or an input's value.
type Module struct {
	Version     string        `json:"version"`
	State       string        `json:"state"`
	HostAPIMin  int           `json:"host_api_min"`
	HostAPIMax  int           `json:"host_api_max"`
	Actions     []string      `json:"actions"`
	Idempotency string        `json:"idempotency"`
	Revocation  string        `json:"revocation"`
	Credentials []string      `json:"credentials"`
	Inputs      []ModuleInput `json:"inputs"`
	MemoryPages uint32        `json:"memory_pages"`
	TimeoutMS   int           `json:"timeout_ms"`
	// PendingPermissions is what an approval would add, for a module awaiting
	// one; StateReason says why a module is not loaded.
	PendingPermissions []string     `json:"pending_permissions"`
	StateReason        string       `json:"state_reason,omitempty"`
	Health             ModuleHealth `json:"health"`
}

// ModuleInput is one field of a module's setup form.
type ModuleInput struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Secret      bool   `json:"secret"`
	Description string `json:"description,omitempty"`
}

// ModuleHealth counts a loaded module's calls since the relay started.
type ModuleHealth struct {
	Calls               int64  `json:"calls"`
	Failures            int64  `json:"failures"`
	ConsecutiveFailures int64  `json:"consecutive_failures"`
	LastFailure         string `json:"last_failure,omitempty"`
}

const (
	maxModuleList = 32
	maxReason     = 512
)

var (
	moduleVersion = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)
	moduleField   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	moduleToken   = regexp.MustCompile(`^[A-Za-z0-9:._=/ -]{1,128}$`)
	moduleStates  = map[string]bool{ModuleStateLoaded: true, ModuleStateAwaitingApproval: true, ModuleStateIncompatible: true}
	moduleActions = map[string]bool{"deploy": true, "test": true, "rollback": true, "readback": true, "revoke": true}
	idempotencies = map[string]bool{"replace-by-name": true, "create-new": true, "read-before-write": true}
	revocations   = map[string]bool{"delete": true, "unbind": true, "none": true}
	inputTypes    = map[string]bool{"string": true, "integer": true, "boolean": true}
	failureNames  = regexp.MustCompile(`^[a-z][a-z-]{0,31}$`)
)

// normalizeModule validates m within its bounds and sorts its lists, so the
// signed statement and the control plane's re-normalization agree.
func normalizeModule(m Module) (Module, error) {
	switch {
	case !moduleVersion.MatchString(m.Version):
		return Module{}, errors.New("version is not MAJOR.MINOR.PATCH")
	case !moduleStates[m.State]:
		return Module{}, fmt.Errorf("unknown state %q", m.State)
	case m.HostAPIMin < 1 || m.HostAPIMax < m.HostAPIMin:
		return Module{}, errors.New("host ABI range is invalid")
	case !idempotencies[m.Idempotency] || !revocations[m.Revocation]:
		return Module{}, errors.New("idempotency or revocation is unknown")
	case m.MemoryPages > 1<<16 || m.TimeoutMS < 0 || m.TimeoutMS > 3_600_000:
		return Module{}, errors.New("limits are out of range")
	case len(m.Actions) > maxModuleList || len(m.Credentials) > maxModuleList || len(m.Inputs) > maxModuleList ||
		len(m.PendingPermissions) > maxConstraintsPerGrant:
		return Module{}, errors.New("a list is too long")
	case len(m.StateReason) > maxReason || strings.ContainsAny(m.StateReason, "\r\n\x00"):
		return Module{}, errors.New("state reason is invalid")
	case m.Health.Calls < 0 || m.Health.Failures < 0 || m.Health.ConsecutiveFailures < 0 ||
		(m.Health.LastFailure != "" && !failureNames.MatchString(m.Health.LastFailure)):
		return Module{}, errors.New("health is invalid")
	}
	out := m
	out.Actions = sortedSet(m.Actions)
	for _, action := range out.Actions {
		if !moduleActions[action] {
			return Module{}, fmt.Errorf("unknown action %q", action)
		}
	}
	out.Credentials = sortedSet(m.Credentials)
	out.PendingPermissions = sortedSet(m.PendingPermissions)
	for _, token := range append(append([]string{}, out.Credentials...), out.PendingPermissions...) {
		if !moduleToken.MatchString(token) {
			return Module{}, fmt.Errorf("invalid token %q", token)
		}
	}
	out.Inputs = make([]ModuleInput, len(m.Inputs))
	seen := map[string]bool{}
	for i, in := range m.Inputs {
		if !moduleField.MatchString(in.Name) || !inputTypes[in.Type] || seen[in.Name] ||
			len(in.Description) > maxReason || strings.ContainsAny(in.Description, "\r\n\x00") {
			return Module{}, fmt.Errorf("input %q is invalid", in.Name)
		}
		seen[in.Name] = true
		out.Inputs[i] = in
	}
	sort.Slice(out.Inputs, func(a, b int) bool { return out.Inputs[a].Name < out.Inputs[b].Name })
	return out, nil
}

// sortedSet returns a sorted, de-duplicated, never-nil copy.
func sortedSet(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !containsString(out, v) {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func containsString(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}
