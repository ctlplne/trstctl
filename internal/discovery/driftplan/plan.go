// SPDX-License-Identifier: MPL-2.0

// Package driftplan owns the validated, normalized execution contract for a
// credential-drift discovery source. The effect-free API preview and the
// executor both resolve this same plan so "ready" cannot mean something
// different from what the queued worker will accept.
package driftplan

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/agent/drift"
)

type config struct {
	Watched []watchedConfig   `json:"watched"`
	Scope   []string          `json:"scope"`
	Policy  map[string]string `json:"policy"`
}

type watchedConfig struct {
	Path        string `json:"path"`
	Class       string `json:"class"`
	Fingerprint string `json:"fingerprint"`
	Mode        string `json:"mode"`
	Restricted  bool   `json:"restricted"`
}

// Plan is the exact non-secret work accepted by drift execution. Paths and
// classes are operator configuration; credential bytes never enter this type.
type Plan struct {
	Watched           []drift.Watched
	Scope             []string
	Policy            drift.ClassPolicy
	NormalizedTargets []string
}

// Resolve validates and normalizes a drift source without reading a watched
// path or changing state. It deliberately refuses auto-remediation because the
// served discovery worker has no declared-content custody or rollback seam.
func Resolve(raw json.RawMessage) (Plan, error) {
	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Plan{}, fmt.Errorf("decode drift discovery config: %w", err)
	}
	if len(cfg.Watched) == 0 {
		return Plan{}, errors.New("drift discovery requires at least one watched credential")
	}

	plan := Plan{
		Watched: make([]drift.Watched, 0, len(cfg.Watched)),
		Scope:   cleanUnique(cfg.Scope),
		Policy:  drift.ClassPolicy{},
	}
	for i, item := range cfg.Watched {
		path := strings.TrimSpace(item.Path)
		class := strings.TrimSpace(item.Class)
		fingerprint := strings.TrimSpace(item.Fingerprint)
		if path == "" || class == "" || fingerprint == "" {
			return Plan{}, fmt.Errorf("drift watched[%d] requires path, class, and fingerprint", i)
		}
		mode, err := parseOptionalFileMode(item.Mode)
		if err != nil {
			return Plan{}, fmt.Errorf("drift watched[%d] mode: %w", i, err)
		}
		plan.Watched = append(plan.Watched, drift.Watched{
			Path: path, Class: class, Fingerprint: fingerprint, Mode: mode, Restricted: item.Restricted,
		})
		plan.NormalizedTargets = append(plan.NormalizedTargets, path)
	}

	for rawClass, rawMode := range cfg.Policy {
		class := strings.TrimSpace(rawClass)
		mode := strings.TrimSpace(rawMode)
		if class == "" || mode == "" {
			continue
		}
		switch drift.Mode(mode) {
		case drift.AlertOnly, drift.AlertAndBlock:
			plan.Policy[class] = drift.Mode(mode)
		case drift.AutoRemediate:
			return Plan{}, errors.New("served drift discovery does not auto-remediate; use alert_only or alert_and_block")
		default:
			return Plan{}, fmt.Errorf("unsupported drift policy mode %q", mode)
		}
	}
	return plan, nil
}

func parseOptionalFileMode(raw string) (os.FileMode, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.ParseUint(raw, 8, 32)
	if err != nil {
		return 0, err
	}
	return os.FileMode(value), nil
}

func cleanUnique(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
