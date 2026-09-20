// SPDX-License-Identifier: BUSL-1.1

// Package nhi normalizes metadata-only non-human identity observations from
// multiple estate surfaces into discovery findings. It never accepts or persists
// credential values; callers pass public identifiers, owner/scope metadata, and
// source provenance only.
package nhi

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	// SourceKind is the served discovery source kind for CAP-NHI-01.
	SourceKind = "nhi_cross_surface"
	// FindingKind is the read-model kind emitted for a discovered non-human identity.
	FindingKind = "non_human_identity"
	// MaxObservations caps a single served source config so one run cannot exhaust
	// the discovery worker lane.
	MaxObservations = 10000
)

var requiredSurfaces = []string{"idp", "cloud", "saas", "on_prem", "code", "ci"}

// Config is the source configuration persisted for a cross-surface NHI discovery
// source. Observations are metadata-only references from external inventories.
type Config struct {
	Observations []Observation `json:"observations"`
}

// Observation is one external NHI reference. ExternalID and System are public
// identifiers such as an IdP app id, cloud role ARN, repo path, or CI environment.
type Observation struct {
	Surface        string   `json:"surface"`
	System         string   `json:"system"`
	ExternalID     string   `json:"external_id"`
	Principal      string   `json:"principal,omitempty"`
	DisplayName    string   `json:"display_name,omitempty"`
	Owner          string   `json:"owner,omitempty"`
	CredentialKind string   `json:"credential_kind,omitempty"`
	Environment    string   `json:"environment,omitempty"`
	FirstSeen      string   `json:"first_seen,omitempty"`
	LastSeen       string   `json:"last_seen,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`
	Tags           []string `json:"tags,omitempty"`
}

// Finding is the normalized discovery finding material emitted by the server.
type Finding struct {
	Ref         string
	Provenance  string
	Fingerprint string
	RiskScore   int
	Metadata    map[string]any
}

// Surfaces returns the required surface denominator in stable order.
func Surfaces() []string {
	return append([]string(nil), requiredSurfaces...)
}

// Findings decodes, validates, and normalizes a source config into discovery
// findings. It requires all six CAP-NHI-01 surfaces in one source, so a served
// source cannot accidentally represent a narrower denominator as category MEET.
func Findings(raw json.RawMessage) ([]Finding, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("decode NHI cross-surface discovery config: %w", err)
	}
	if len(cfg.Observations) == 0 {
		return nil, errors.New("NHI cross-surface discovery requires observations")
	}
	if len(cfg.Observations) > MaxObservations {
		return nil, fmt.Errorf("NHI cross-surface discovery source has %d observations; maximum is %d", len(cfg.Observations), MaxObservations)
	}

	out := make([]Finding, 0, len(cfg.Observations))
	seenSurfaces := map[string]bool{}
	for i, obs := range cfg.Observations {
		finding, surface, err := normalizeObservation(obs)
		if err != nil {
			return nil, fmt.Errorf("NHI observation %d: %w", i, err)
		}
		seenSurfaces[surface] = true
		out = append(out, finding)
	}
	missingSurfaces := make([]string, 0, len(requiredSurfaces))
	for _, surface := range requiredSurfaces {
		if !seenSurfaces[surface] {
			missingSurfaces = append(missingSurfaces, surface)
		}
	}
	if len(missingSurfaces) > 0 {
		return nil, fmt.Errorf(
			"NHI cross-surface discovery requires one metadata-only observation from every surface; missing: %s",
			strings.Join(missingSurfaces, ", "),
		)
	}
	return out, nil
}

// ValidateConfig checks the source config without returning normalized findings.
func ValidateConfig(raw json.RawMessage) error {
	_, err := Findings(raw)
	return err
}

func normalizeObservation(obs Observation) (Finding, string, error) {
	surface := normalizeSurface(obs.Surface)
	if !isRequiredSurface(surface) {
		return Finding{}, "", fmt.Errorf("surface %q must be one of %s", obs.Surface, strings.Join(requiredSurfaces, ", "))
	}
	system := strings.TrimSpace(obs.System)
	externalID := strings.TrimSpace(obs.ExternalID)
	if system == "" || externalID == "" {
		return Finding{}, "", errors.New("system and external_id are required")
	}
	principal := strings.TrimSpace(obs.Principal)
	ref := principal
	if ref == "" {
		ref = system + "/" + externalID
	}
	provenance := SourceKind + ":" + surface + ":" + system + ":" + externalID
	meta := map[string]any{
		"surface":         surface,
		"system":          system,
		"external_id":     externalID,
		"principal":       principal,
		"display_name":    strings.TrimSpace(obs.DisplayName),
		"owner":           strings.TrimSpace(obs.Owner),
		"credential_kind": strings.TrimSpace(obs.CredentialKind),
		"environment":     strings.TrimSpace(obs.Environment),
		"first_seen":      strings.TrimSpace(obs.FirstSeen),
		"last_seen":       strings.TrimSpace(obs.LastSeen),
		"scopes":          cleaned(obs.Scopes),
		"tags":            cleaned(obs.Tags),
	}
	return Finding{
		Ref:         ref,
		Provenance:  provenance,
		Fingerprint: provenance,
		RiskScore:   riskScore(obs),
		Metadata:    meta,
	}, surface, nil
}

func normalizeSurface(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.ReplaceAll(s, "-", "_")
	return s
}

func isRequiredSurface(surface string) bool {
	for _, allowed := range requiredSurfaces {
		if surface == allowed {
			return true
		}
	}
	return false
}

func cleaned(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func riskScore(obs Observation) int {
	score := 35
	if strings.TrimSpace(obs.Owner) == "" {
		score += 20
	}
	kind := strings.ToLower(strings.TrimSpace(obs.CredentialKind))
	if strings.Contains(kind, "key") || strings.Contains(kind, "secret") || strings.Contains(kind, "token") {
		score += 20
	}
	if len(cleaned(obs.Scopes)) > 3 {
		score += 10
	}
	if score > 100 {
		return 100
	}
	return score
}
