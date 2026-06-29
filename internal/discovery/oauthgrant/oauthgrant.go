// Package oauthgrant normalizes metadata-only OAuth application grants into
// discovery findings. It models the SaaS-to-SaaS consent layer and never accepts
// client secrets, refresh tokens, or other credential bodies as finding material.
package oauthgrant

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// SourceKind is the served discovery source kind for CAP-OAUTH-01.
	SourceKind = "oauth_grant"
	// FindingKind is the read-model kind emitted for a discovered OAuth grant.
	FindingKind = "oauth_grant"
	// AbuseFindingKind is the read-model kind emitted for abused OAuth grants.
	AbuseFindingKind = "oauth_grant_abuse"
	// MaxGrants caps a single served source config so one run cannot exhaust the
	// discovery worker lane.
	MaxGrants = 10000
)

// Config is the persisted source configuration for OAuth app/grant discovery.
// Grants are metadata-only references exported from IdPs and SaaS admin APIs.
type Config struct {
	Grants []Grant `json:"grants"`
}

// Grant is one OAuth app authorization. AppID and Resource are public
// identifiers; credential material must stay behind provider-side references and
// never appears in this data model.
type Grant struct {
	Provider    string   `json:"provider"`
	AppID       string   `json:"app_id"`
	AppName     string   `json:"app_name,omitempty"`
	Principal   string   `json:"principal,omitempty"`
	Resource    string   `json:"resource"`
	Scopes      []string `json:"scopes"`
	ConsentType string   `json:"consent_type,omitempty"`
	ThirdParty  bool     `json:"third_party,omitempty"`
	Owner       string   `json:"owner,omitempty"`
	Publisher   string   `json:"publisher,omitempty"`
	// PublisherVerified is a pointer so omitted provider exports do not get
	// treated as explicit unverified-publisher evidence.
	PublisherVerified *bool    `json:"publisher_verified,omitempty"`
	Tenant            string   `json:"tenant,omitempty"`
	CreatedAt         string   `json:"created_at,omitempty"`
	LastUsed          string   `json:"last_used,omitempty"`
	ObservedAt        string   `json:"observed_at,omitempty"`
	RedirectURIs      []string `json:"redirect_uris,omitempty"`
	Tags              []string `json:"tags,omitempty"`
	ThreatSignals     []string `json:"threat_signals,omitempty"`
	EvidenceRefs      []string `json:"evidence_refs,omitempty"`
	SourceEventRef    string   `json:"source_event_ref,omitempty"`
}

// Finding is the normalized discovery finding material emitted by the server.
type Finding struct {
	Ref         string
	Provenance  string
	Fingerprint string
	RiskScore   int
	Metadata    map[string]any
}

// Findings decodes, validates, and normalizes a source config into OAuth grant
// findings. Each grant must include provider, app_id, resource, and at least one
// scope so CAP-OAUTH-01 covers app discovery, grant discovery, and scope discovery.
func Findings(raw json.RawMessage) ([]Finding, error) {
	cfg, err := decodeConfig(raw)
	if err != nil {
		return nil, err
	}

	out := make([]Finding, 0, len(cfg.Grants))
	for i, grant := range cfg.Grants {
		finding, err := normalizeGrant(grant)
		if err != nil {
			return nil, fmt.Errorf("OAuth grant %d: %w", i, err)
		}
		out = append(out, finding)
	}
	return out, nil
}

// AbuseFindings decodes, validates, and normalizes abused OAuth grant detections.
// It reuses the same metadata-only source as CAP-OAUTH-01, but emits only grants
// with concrete abuse evidence so inventory alone does not count as ITDR.
func AbuseFindings(raw json.RawMessage) ([]Finding, error) {
	cfg, err := decodeConfig(raw)
	if err != nil {
		return nil, err
	}
	out := make([]Finding, 0, len(cfg.Grants))
	for i, grant := range cfg.Grants {
		finding, ok, err := normalizeAbuseGrant(grant)
		if err != nil {
			return nil, fmt.Errorf("OAuth grant %d abuse detection: %w", i, err)
		}
		if ok {
			out = append(out, finding)
		}
	}
	return out, nil
}

// ValidateConfig checks the source config without returning normalized findings.
func ValidateConfig(raw json.RawMessage) error {
	if _, err := Findings(raw); err != nil {
		return err
	}
	_, err := AbuseFindings(raw)
	return err
}

func decodeConfig(raw json.RawMessage) (Config, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("decode OAuth grant discovery config: %w", err)
	}
	if len(cfg.Grants) == 0 {
		return Config{}, errors.New("OAuth grant discovery requires grants")
	}
	if len(cfg.Grants) > MaxGrants {
		return Config{}, fmt.Errorf("OAuth grant discovery source has %d grants; maximum is %d", len(cfg.Grants), MaxGrants)
	}
	return cfg, nil
}

func normalizeGrant(grant Grant) (Finding, error) {
	provider := strings.TrimSpace(grant.Provider)
	appID := strings.TrimSpace(grant.AppID)
	resource := strings.TrimSpace(grant.Resource)
	scopes := cleaned(grant.Scopes)
	if provider == "" || appID == "" || resource == "" {
		return Finding{}, errors.New("provider, app_id, and resource are required")
	}
	if len(scopes) == 0 {
		return Finding{}, errors.New("at least one scope is required")
	}

	principal := strings.TrimSpace(grant.Principal)
	ref := principal
	if ref == "" {
		ref = provider + "/" + appID + "/" + resource
	}
	provenance := SourceKind + ":" + provider + ":" + appID + ":" + resource
	meta := map[string]any{
		"provider":         provider,
		"app_id":           appID,
		"app_name":         strings.TrimSpace(grant.AppName),
		"principal":        principal,
		"resource":         resource,
		"scopes":           scopes,
		"consent_type":     strings.TrimSpace(grant.ConsentType),
		"third_party":      grant.ThirdParty,
		"owner":            strings.TrimSpace(grant.Owner),
		"publisher":        strings.TrimSpace(grant.Publisher),
		"tenant":           strings.TrimSpace(grant.Tenant),
		"created_at":       strings.TrimSpace(grant.CreatedAt),
		"last_used":        strings.TrimSpace(grant.LastUsed),
		"observed_at":      strings.TrimSpace(grant.ObservedAt),
		"redirect_uris":    cleaned(grant.RedirectURIs),
		"tags":             cleaned(grant.Tags),
		"threat_signals":   cleaned(grant.ThreatSignals),
		"evidence_refs":    cleaned(grant.EvidenceRefs),
		"source_event_ref": strings.TrimSpace(grant.SourceEventRef),
	}
	if grant.PublisherVerified != nil {
		meta["publisher_verified"] = *grant.PublisherVerified
	}
	return Finding{
		Ref:         ref,
		Provenance:  provenance,
		Fingerprint: provenance,
		RiskScore:   riskScore(grant, scopes),
		Metadata:    meta,
	}, nil
}

func normalizeAbuseGrant(grant Grant) (Finding, bool, error) {
	base, err := normalizeGrant(grant)
	if err != nil {
		return Finding{}, false, err
	}
	scopes, _ := base.Metadata["scopes"].([]string)
	reasons := abuseReasons(grant, scopes)
	if len(reasons) == 0 {
		return Finding{}, false, nil
	}
	observedAt, err := normalizeOptionalRFC3339("observed_at", grant.ObservedAt)
	if err != nil {
		return Finding{}, false, err
	}
	createdAt, err := normalizeOptionalRFC3339("created_at", grant.CreatedAt)
	if err != nil {
		return Finding{}, false, err
	}
	if observedAt == "" {
		observedAt = createdAt
	}
	sourceEventRef := strings.TrimSpace(grant.SourceEventRef)
	evidenceRefs := cleaned(grant.EvidenceRefs)
	provenanceSuffix := observedAt
	if provenanceSuffix == "" {
		provenanceSuffix = sourceEventRef
	}
	if provenanceSuffix == "" {
		provenanceSuffix = base.Fingerprint
	}

	meta := copyMetadata(base.Metadata)
	meta["abuse_reasons"] = reasons
	meta["threat_signals"] = cleaned(grant.ThreatSignals)
	meta["evidence_refs"] = evidenceRefs
	meta["source_event_ref"] = sourceEventRef
	meta["observed_at"] = observedAt
	meta["capability"] = "CAP-ITDR-03"
	meta["detection_kind"] = "malicious_oauth_grant"

	provider := strings.TrimSpace(grant.Provider)
	appID := strings.TrimSpace(grant.AppID)
	resource := strings.TrimSpace(grant.Resource)
	provenance := AbuseFindingKind + ":" + provider + ":" + appID + ":" + resource + ":" + provenanceSuffix
	return Finding{
		Ref:         base.Ref,
		Provenance:  provenance,
		Fingerprint: provenance + ":" + strings.Join(reasons, "+"),
		RiskScore:   abuseRiskScore(reasons),
		Metadata:    meta,
	}, true, nil
}

func copyMetadata(in map[string]any) map[string]any {
	out := make(map[string]any, len(in)+4)
	for k, v := range in {
		out[k] = v
	}
	return out
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

func abuseReasons(grant Grant, scopes []string) []string {
	reasons := make([]string, 0, 6)
	if len(cleaned(grant.ThreatSignals)) > 0 {
		reasons = append(reasons, "provider_threat_signal")
	}
	wildcard := hasDangerousWildcardScope(scopes)
	highPrivilege := wildcard || hasSensitiveScope(scopes)
	if wildcard {
		reasons = append(reasons, "dangerous_wildcard_scope")
	}
	if hasOfflineAccess(scopes) && highPrivilege && isAdminConsent(grant) {
		reasons = append(reasons, "offline_access_high_privilege")
	}
	if grant.PublisherVerified != nil && !*grant.PublisherVerified && highPrivilege {
		reasons = append(reasons, "unverified_publisher_high_privilege")
	}
	if strings.TrimSpace(grant.Owner) == "" && grant.ThirdParty && isAdminConsent(grant) && highPrivilege {
		reasons = append(reasons, "ownerless_admin_consent")
	}
	if hasSuspiciousRedirectURI(grant.RedirectURIs) {
		reasons = append(reasons, "suspicious_redirect_uri")
	}
	return reasons
}

func isAdminConsent(grant Grant) bool {
	return strings.EqualFold(strings.TrimSpace(grant.ConsentType), "admin")
}

func hasDangerousWildcardScope(scopes []string) bool {
	for _, scope := range scopes {
		s := strings.ToLower(strings.TrimSpace(scope))
		if s == "*" || strings.Contains(s, "*") || strings.Contains(s, ".default") || strings.Contains(s, "full_access") {
			return true
		}
	}
	return false
}

func hasOfflineAccess(scopes []string) bool {
	for _, scope := range scopes {
		if strings.EqualFold(strings.TrimSpace(scope), "offline_access") {
			return true
		}
	}
	return false
}

func hasSuspiciousRedirectURI(values []string) bool {
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if strings.Contains(value, "*") {
			return true
		}
		u, err := url.Parse(value)
		if err != nil {
			continue
		}
		if strings.EqualFold(u.Scheme, "http") && !isLoopbackHost(u.Hostname()) {
			return true
		}
	}
	return false
}

func isLoopbackHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func normalizeOptionalRFC3339(field, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return "", fmt.Errorf("%s must be RFC3339: %w", field, err)
	}
	return parsed.Format(time.RFC3339), nil
}

func riskScore(grant Grant, scopes []string) int {
	score := 35
	if grant.ThirdParty {
		score += 20
	}
	if strings.EqualFold(strings.TrimSpace(grant.ConsentType), "admin") {
		score += 20
	}
	if hasSensitiveScope(scopes) {
		score += 10
	}
	if strings.TrimSpace(grant.Owner) == "" {
		score += 15
	}
	if score > 100 {
		return 100
	}
	return score
}

func hasSensitiveScope(scopes []string) bool {
	for _, scope := range scopes {
		s := strings.ToLower(scope)
		if strings.Contains(s, "admin") ||
			strings.Contains(s, "directory") ||
			strings.Contains(s, ".write") ||
			strings.Contains(s, "mail") ||
			strings.Contains(s, "drive") {
			return true
		}
	}
	return false
}

func abuseRiskScore(reasons []string) int {
	score := 70
	for _, reason := range reasons {
		switch reason {
		case "provider_threat_signal":
			score += 15
		case "dangerous_wildcard_scope", "offline_access_high_privilege":
			score += 10
		case "unverified_publisher_high_privilege", "ownerless_admin_consent", "suspicious_redirect_uri":
			score += 5
		default:
			score += 3
		}
	}
	if score > 100 {
		return 100
	}
	return score
}
