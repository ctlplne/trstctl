// SPDX-License-Identifier: MPL-2.0

// Package dependencyobs owns the one metadata-only wire/storage contract for an
// observed workload-to-resource dependency. Agent ingress and graph.Build use
// this same parser so a finding accepted at the door cannot become unreadable
// (and silently disappear) when the readiness graph is built later.
package dependencyobs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	Kind          = "service_dependency"
	maxFieldBytes = 4096
)

// Observation contains public identifiers only. It never carries a bearer,
// endpoint credential, request body, or packet contents.
type Observation struct {
	Workload string `json:"workload"`
	Target   string `json:"target"`
	Protocol string `json:"protocol,omitempty"`
	Host     string `json:"host,omitempty"`
}

// ParseMap validates the agent's pre-JSON metadata. Unknown fields fail closed:
// accepting a field graph.Build does not understand recreates AUD-64 as a green
// ingestion receipt followed by a missing dependency.
func ParseMap(metadata map[string]string, ref string) (Observation, error) {
	for key := range metadata {
		switch key {
		case "workload", "target", "protocol", "host":
		default:
			return Observation{}, fmt.Errorf("unknown field %q", key)
		}
	}
	return validate(Observation{
		Workload: metadata["workload"],
		Target:   metadata["target"],
		Protocol: metadata["protocol"],
		Host:     metadata["host"],
	}, ref)
}

// ParseJSON validates the exact event-projected jsonb shape consumed by the
// graph. A second value and unknown keys are refused rather than ignored.
func ParseJSON(raw json.RawMessage, ref string) (Observation, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var observation Observation
	if err := decoder.Decode(&observation); err != nil {
		return Observation{}, fmt.Errorf("decode metadata: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Observation{}, fmt.Errorf("decode metadata: trailing JSON value")
		}
		return Observation{}, fmt.Errorf("decode metadata: %w", err)
	}
	return validate(observation, ref)
}

func validate(observation Observation, ref string) (Observation, error) {
	observation.Workload = strings.TrimSpace(observation.Workload)
	observation.Target = strings.TrimSpace(observation.Target)
	observation.Protocol = strings.TrimSpace(observation.Protocol)
	observation.Host = strings.TrimSpace(observation.Host)
	ref = strings.TrimSpace(ref)
	if observation.Workload == "" || observation.Target == "" || ref == "" {
		return Observation{}, fmt.Errorf("workload, target, and ref are required")
	}
	for field, value := range map[string]string{
		"workload": observation.Workload,
		"target":   observation.Target,
		"protocol": observation.Protocol,
		"host":     observation.Host,
		"ref":      ref,
	} {
		if !utf8.ValidString(value) || len(value) > maxFieldBytes {
			return Observation{}, fmt.Errorf("%s must be valid UTF-8 and at most %d bytes", field, maxFieldBytes)
		}
	}
	if observation.Target != ref {
		return Observation{}, fmt.Errorf("target %q does not match ref %q", observation.Target, ref)
	}
	return observation, nil
}
