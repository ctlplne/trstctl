// SPDX-License-Identifier: MPL-2.0

// Package compromise normalizes metadata-only compromised-credential signals
// into discovery findings. It covers stolen-token and leaked-credential ITDR
// evidence without accepting credential bodies.
package compromise

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// SourceKind is the served discovery source kind for CAP-ITDR-02.
	SourceKind = "credential_compromise"
	// FindingKind is the read-model kind emitted for compromised credentials.
	FindingKind = "compromised_credential"
	// MaxSignals caps one source config so one run cannot exhaust the discovery
	// worker lane.
	MaxSignals = 10000
)

// Config is the persisted source configuration for compromised-credential
// detection. Signals are metadata-only risk records exported by IdPs, SaaS audit
// logs, secret scanners, honeytokens, EDR/ITDR tools, or threat-intel feeds.
type Config struct {
	Signals []Signal `json:"signals"`
}

// Signal is one external stolen-token or compromised-credential observation.
// CredentialRef is a reference or stable identifier, never the credential value.
type Signal struct {
	Principal      string   `json:"principal"`
	CredentialRef  string   `json:"credential_ref"`
	CredentialKind string   `json:"credential_kind"`
	Provider       string   `json:"provider"`
	Detector       string   `json:"detector"`
	ObservedAt     string   `json:"observed_at"`
	Reason         string   `json:"reason"`
	Confidence     string   `json:"confidence"`
	EvidenceRefs   []string `json:"evidence_refs"`
	SourceEventRef string   `json:"source_event_ref,omitempty"`
	IP             string   `json:"ip,omitempty"`
	Geo            string   `json:"geo,omitempty"`
	UserAgent      string   `json:"user_agent,omitempty"`
	Action         string   `json:"action,omitempty"`
	Owner          string   `json:"owner,omitempty"`
}

// Finding is the normalized discovery finding material emitted by the server.
type Finding struct {
	Ref         string
	Provenance  string
	Fingerprint string
	RiskScore   int
	Metadata    map[string]any
}

// Findings decodes, validates, and normalizes a source config into
// compromised-credential findings. Each finding carries only references,
// timestamps, reason codes, and evidence references.
func Findings(raw json.RawMessage) ([]Finding, error) {
	if containsInlineSecret(raw) {
		return nil, errors.New("compromised-credential discovery config may contain credential references, not inline secret values")
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("decode compromised-credential discovery config: %w", err)
	}
	if len(cfg.Signals) == 0 {
		return nil, errors.New("compromised-credential discovery requires signals")
	}
	if len(cfg.Signals) > MaxSignals {
		return nil, fmt.Errorf("compromised-credential discovery source has %d signals; maximum is %d", len(cfg.Signals), MaxSignals)
	}

	out := make([]Finding, 0, len(cfg.Signals))
	for i, signal := range cfg.Signals {
		finding, err := normalizeSignal(signal)
		if err != nil {
			return nil, fmt.Errorf("compromised-credential signal %d: %w", i, err)
		}
		out = append(out, finding)
	}
	return out, nil
}

// ValidateConfig checks the source config without returning normalized findings.
func ValidateConfig(raw json.RawMessage) error {
	_, err := Findings(raw)
	return err
}

func normalizeSignal(signal Signal) (Finding, error) {
	principal := strings.TrimSpace(signal.Principal)
	credentialRef := strings.TrimSpace(signal.CredentialRef)
	credentialKind := strings.TrimSpace(signal.CredentialKind)
	provider := strings.TrimSpace(signal.Provider)
	detector := strings.TrimSpace(signal.Detector)
	reason := strings.TrimSpace(signal.Reason)
	confidence := strings.ToLower(strings.TrimSpace(signal.Confidence))
	if principal == "" || credentialRef == "" || credentialKind == "" {
		return Finding{}, errors.New("principal, credential_ref, and credential_kind are required")
	}
	if provider == "" || detector == "" {
		return Finding{}, errors.New("provider and detector are required")
	}
	if reason == "" {
		return Finding{}, errors.New("reason is required")
	}
	risk, err := riskScore(confidence, reason)
	if err != nil {
		return Finding{}, err
	}
	if strings.TrimSpace(signal.ObservedAt) == "" {
		return Finding{}, errors.New("observed_at is required")
	}
	observedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(signal.ObservedAt))
	if err != nil {
		return Finding{}, fmt.Errorf("observed_at must be RFC3339: %w", err)
	}
	evidenceRefs := cleaned(signal.EvidenceRefs)
	sourceEventRef := strings.TrimSpace(signal.SourceEventRef)
	if len(evidenceRefs) == 0 && sourceEventRef == "" {
		return Finding{}, errors.New("at least one evidence_refs entry or source_event_ref is required")
	}

	observed := observedAt.Format(time.RFC3339)
	provenance := SourceKind + ":" + provider + ":" + detector + ":" + credentialRef + ":" + observed
	fingerprint := provenance + ":" + reason
	meta := map[string]any{
		"principal":          principal,
		"credential_ref":     credentialRef,
		"credential_kind":    credentialKind,
		"provider":           provider,
		"detector":           detector,
		"observed_at":        observed,
		"reason":             reason,
		"compromise_reasons": []string{reason},
		"confidence":         confidence,
		"evidence_refs":      evidenceRefs,
		"source_event_ref":   sourceEventRef,
		"ip":                 strings.TrimSpace(signal.IP),
		"geo":                normalizeGeo(signal.Geo),
		"user_agent":         strings.TrimSpace(signal.UserAgent),
		"action":             strings.TrimSpace(signal.Action),
		"owner":              strings.TrimSpace(signal.Owner),
		"owasp_category":     "NHI2",
		"capability":         "CAP-ITDR-02",
	}
	return Finding{
		Ref:         credentialRef,
		Provenance:  provenance,
		Fingerprint: fingerprint,
		RiskScore:   risk,
		Metadata:    meta,
	}, nil
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

func normalizeGeo(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}

func riskScore(confidence, reason string) (int, error) {
	score := 0
	switch confidence {
	case "critical":
		score = 98
	case "high":
		score = 90
	case "medium":
		score = 75
	case "low":
		score = 55
	default:
		return 0, errors.New("confidence must be one of low, medium, high, critical")
	}
	r := strings.ToLower(reason)
	if strings.Contains(r, "honeytoken") || strings.Contains(r, "known leak") ||
		strings.Contains(r, "revoked token replay") || strings.Contains(r, "stolen") {
		score += 5
	}
	if score > 100 {
		return 100, nil
	}
	return score, nil
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
	if strings.Contains(k, "ref") || strings.Contains(k, "name") || strings.Contains(k, "id") || strings.HasSuffix(k, "kind") {
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
