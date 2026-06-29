// Package apikey normalizes metadata-only API-key, token, and PAT estate
// observations into discovery findings. Source configs carry references and
// masked fingerprints only; raw credential values are rejected.
package apikey

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// SourceKind is the served discovery source kind for CAP-NHI-04.
	SourceKind = "api_key"
	// MaxObservations caps one source config so one run cannot exhaust the
	// discovery worker lane.
	MaxObservations = 10000
)

// Config is the persisted source configuration for API-key/token discovery.
type Config struct {
	Observations []Observation     `json:"observations"`
	Findings     []json.RawMessage `json:"findings,omitempty"`
}

// Observation is one metadata-only external credential observation.
type Observation struct {
	Surface           string   `json:"surface"`
	System            string   `json:"system"`
	ExternalID        string   `json:"external_id"`
	Principal         string   `json:"principal"`
	Owner             string   `json:"owner,omitempty"`
	DisplayName       string   `json:"display_name,omitempty"`
	CredentialKind    string   `json:"credential_kind"`
	CredentialRef     string   `json:"credential_ref"`
	MaskedFingerprint string   `json:"masked_fingerprint"`
	Scopes            []string `json:"scopes,omitempty"`
	LastSeenAt        string   `json:"last_seen_at,omitempty"`
	ExpiresAt         string   `json:"expires_at,omitempty"`
	RotationAgeDays   *int     `json:"rotation_age_days,omitempty"`
	EvidenceRefs      []string `json:"evidence_refs,omitempty"`
	SourceEventRef    string   `json:"source_event_ref,omitempty"`
	Privileged        bool     `json:"privileged,omitempty"`
}

// Finding is the normalized discovery finding material emitted by the server.
type Finding struct {
	Kind        string
	Ref         string
	Provenance  string
	Fingerprint string
	RiskScore   int
	Metadata    map[string]any
}

// UsesObservationConfig reports whether this source uses the served
// observations schema. Older api_key sources can still use manual findings.
func UsesObservationConfig(raw json.RawMessage) bool {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return false
	}
	return len(cfg.Observations) > 0
}

// Findings decodes, validates, and normalizes a source config into API-key,
// token, and PAT findings.
func Findings(raw json.RawMessage) ([]Finding, error) {
	if containsInlineSecret(raw) {
		return nil, errors.New("api-key discovery config may contain credential references, not inline secret values")
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("decode api-key discovery config: %w", err)
	}
	if len(cfg.Observations) == 0 {
		return nil, errors.New("api-key discovery requires observations")
	}
	if len(cfg.Observations) > MaxObservations {
		return nil, fmt.Errorf("api-key discovery source has %d observations; maximum is %d", len(cfg.Observations), MaxObservations)
	}
	out := make([]Finding, 0, len(cfg.Observations))
	for i, obs := range cfg.Observations {
		f, err := normalizeObservation(obs)
		if err != nil {
			return nil, fmt.Errorf("api-key observation %d: %w", i, err)
		}
		out = append(out, f)
	}
	return out, nil
}

// ValidateConfig checks source config without returning normalized findings.
func ValidateConfig(raw json.RawMessage) error {
	if containsInlineSecret(raw) {
		return errors.New("api-key discovery config may contain credential references, not inline secret values")
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("decode api-key discovery config: %w", err)
	}
	if len(cfg.Observations) == 0 {
		if len(cfg.Findings) > 0 {
			return nil
		}
		return errors.New("api-key discovery requires observations")
	}
	_, err := Findings(raw)
	return err
}

func normalizeObservation(obs Observation) (Finding, error) {
	surface := strings.TrimSpace(obs.Surface)
	system := strings.TrimSpace(obs.System)
	externalID := strings.TrimSpace(obs.ExternalID)
	principal := strings.TrimSpace(obs.Principal)
	credentialKind := normalizeCredentialKind(obs.CredentialKind)
	credentialRef := strings.TrimSpace(obs.CredentialRef)
	if surface == "" || system == "" || externalID == "" {
		return Finding{}, errors.New("surface, system, and external_id are required")
	}
	if principal == "" || credentialKind == "" || credentialRef == "" {
		return Finding{}, errors.New("principal, credential_kind, and credential_ref are required")
	}
	if _, err := parseOptionalRFC3339("last_seen_at", obs.LastSeenAt); err != nil {
		return Finding{}, err
	}
	if _, err := parseOptionalRFC3339("expires_at", obs.ExpiresAt); err != nil {
		return Finding{}, err
	}
	evidenceRefs := cleaned(obs.EvidenceRefs)
	sourceEventRef := strings.TrimSpace(obs.SourceEventRef)
	if len(evidenceRefs) == 0 && sourceEventRef == "" {
		return Finding{}, errors.New("at least one evidence_refs entry or source_event_ref is required")
	}
	scopes := cleaned(obs.Scopes)
	maskedFingerprint := strings.TrimSpace(obs.MaskedFingerprint)
	if maskedFingerprint == "" {
		maskedFingerprint = "ref:" + credentialRef
	}
	provenance := SourceKind + ":" + surface + ":" + system + ":" + externalID
	meta := map[string]any{
		"surface":            surface,
		"system":             system,
		"external_id":        externalID,
		"principal":          principal,
		"owner":              strings.TrimSpace(obs.Owner),
		"display_name":       strings.TrimSpace(obs.DisplayName),
		"credential_kind":    credentialKind,
		"credential_ref":     credentialRef,
		"masked_fingerprint": maskedFingerprint,
		"scopes":             scopes,
		"last_seen_at":       strings.TrimSpace(obs.LastSeenAt),
		"expires_at":         strings.TrimSpace(obs.ExpiresAt),
		"evidence_refs":      evidenceRefs,
		"source_event_ref":   sourceEventRef,
		"privileged":         obs.Privileged,
		"capability":         "CAP-NHI-04",
		"owasp_category":     "NHI4",
	}
	if obs.RotationAgeDays != nil {
		if *obs.RotationAgeDays < 0 {
			return Finding{}, errors.New("rotation_age_days must be non-negative")
		}
		meta["rotation_age_days"] = *obs.RotationAgeDays
	}
	return Finding{
		Kind:        credentialKind,
		Ref:         credentialRef,
		Provenance:  provenance,
		Fingerprint: maskedFingerprint,
		RiskScore:   riskScore(credentialKind, obs.Privileged, obs.ExpiresAt, obs.RotationAgeDays, scopes),
		Metadata:    meta,
	}, nil
}

func normalizeCredentialKind(raw string) string {
	k := strings.ToLower(strings.TrimSpace(raw))
	k = strings.ReplaceAll(k, "-", "_")
	switch k {
	case "access_key", "aws_access_key", "gcp_service_account_key", "service_account_key", "api_key":
		return "api_key"
	case "pat", "personal_access_token":
		return "personal_access_token"
	case "api_token", "bearer_token", "token", "refresh_token", "oauth_refresh_token":
		return "api_token"
	default:
		return k
	}
}

func parseOptionalRFC3339(field, value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	ts, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s must be RFC3339: %w", field, err)
	}
	return ts, nil
}

func riskScore(kind string, privileged bool, expiresAt string, rotationAgeDays *int, scopes []string) int {
	score := 50
	if privileged {
		score += 20
	}
	if strings.TrimSpace(expiresAt) == "" {
		score += 10
	}
	if rotationAgeDays != nil && *rotationAgeDays >= 90 {
		score += 15
	}
	if kind == "personal_access_token" || kind == "api_token" {
		score += 10
	}
	for _, scope := range scopes {
		s := strings.ToLower(scope)
		if strings.Contains(s, "*") || strings.Contains(s, "admin") || strings.Contains(s, "write") || s == "repo" {
			score += 10
			break
		}
	}
	if score > 100 {
		return 100
	}
	return score
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

func containsInlineSecret(raw json.RawMessage) bool {
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return false
	}
	return containsInlineSecretValue(decoded)
}

func containsInlineSecretValue(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for key, val := range x {
			if inlineSecretKey(key) || containsInlineSecretValue(val) {
				return true
			}
		}
	case []any:
		for _, val := range x {
			if containsInlineSecretValue(val) {
				return true
			}
		}
	}
	return false
}

func inlineSecretKey(key string) bool {
	k := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	if strings.Contains(k, "ref") || strings.Contains(k, "name") || strings.Contains(k, "id") ||
		strings.Contains(k, "kind") || strings.Contains(k, "fingerprint") {
		return false
	}
	if strings.Contains(k, "secret") || strings.Contains(k, "password") ||
		strings.Contains(k, "passphrase") || strings.Contains(k, "token") {
		return true
	}
	switch k {
	case "credential", "value", "private_key", "privatekey":
		return true
	default:
		return strings.HasSuffix(k, "_secret") || strings.HasSuffix(k, "_token")
	}
}
