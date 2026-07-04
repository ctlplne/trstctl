// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/store"
)

const rogueCertificateCapability = "CAP-REV-05"

var rogueCertificateCoverage = []string{
	"certificate_inventory",
	"ct_unexpected_issuance",
	"weak_key_algorithm",
	"lifetime_policy",
	"expired_active_certificates",
	"owner_attribution",
	"revocation_recommendations",
}

type rogueCertificatePostureResponse struct {
	Capability         string                    `json:"capability"`
	GeneratedAt        time.Time                 `json:"generated_at"`
	Coverage           []string                  `json:"coverage"`
	Summary            rogueCertificateSummary   `json:"summary"`
	Findings           []rogueCertificateFinding `json:"findings"`
	RecommendedActions []string                  `json:"recommended_actions"`
	EvidenceRefs       []string                  `json:"evidence_refs"`
}

type rogueCertificateSummary struct {
	TotalAnalyzed      int `json:"total_analyzed"`
	Findings           int `json:"findings"`
	Rogue              int `json:"rogue"`
	NonCompliant       int `json:"non_compliant"`
	CTUnexpected       int `json:"ct_unexpected"`
	WeakKey            int `json:"weak_key"`
	LifetimeViolations int `json:"lifetime_violations"`
	ExpiredActive      int `json:"expired_active"`
	OwnerMissing       int `json:"owner_missing"`
	IssuerMissing      int `json:"issuer_missing"`
	Critical           int `json:"critical"`
	High               int `json:"high"`
	Medium             int `json:"medium"`
	Low                int `json:"low"`
	Recommendations    int `json:"recommendations"`
}

type rogueCertificateFinding struct {
	ID             string     `json:"id"`
	CertificateID  string     `json:"certificate_id,omitempty"`
	DiscoveryID    string     `json:"discovery_id,omitempty"`
	SourceID       string     `json:"source_id,omitempty"`
	RunID          string     `json:"run_id,omitempty"`
	Kind           string     `json:"kind"`
	PolicyStatus   string     `json:"policy_status"`
	Subject        string     `json:"subject"`
	Issuer         string     `json:"issuer,omitempty"`
	Serial         string     `json:"serial,omitempty"`
	Fingerprint    string     `json:"fingerprint,omitempty"`
	DNSNames       []string   `json:"dns_names,omitempty"`
	Source         string     `json:"source"`
	OwnerID        string     `json:"owner_id,omitempty"`
	Status         string     `json:"status,omitempty"`
	FindingTypes   []string   `json:"finding_types"`
	Severity       string     `json:"severity"`
	RiskScore      int        `json:"risk_score"`
	LifetimeDays   int        `json:"lifetime_days,omitempty"`
	PolicyMaxDays  int        `json:"policy_max_days,omitempty"`
	LogURL         string     `json:"log_url,omitempty"`
	LogIndex       *int64     `json:"log_index,omitempty"`
	MatchedDomain  string     `json:"matched_domain,omitempty"`
	Recommendation string     `json:"recommendation"`
	EvidenceRefs   []string   `json:"evidence_refs"`
	DiscoveredAt   *time.Time `json:"discovered_at,omitempty"`
	NotBefore      *time.Time `json:"not_before,omitempty"`
	NotAfter       *time.Time `json:"not_after,omitempty"`
}

func (a *API) listRogueCertificates(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	out, err := a.rogueCertificatePosture(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, out)
}

func (a *API) rogueCertificatePosture(ctx context.Context, tenantID string) (rogueCertificatePostureResponse, error) {
	now := time.Now().UTC()
	out := rogueCertificatePostureResponse{
		Capability:  rogueCertificateCapability,
		GeneratedAt: now,
		Coverage:    append([]string(nil), rogueCertificateCoverage...),
		Findings:    []rogueCertificateFinding{},
		RecommendedActions: []string{
			"Investigate CT unexpected-issuance findings and claim expected certificates before dismissing them.",
			"Revoke or replace certificates with weak keys, expired active state, or lifetime outside policy.",
			"Assign owners to external certificates before treating them as sanctioned production credentials.",
		},
		EvidenceRefs: []string{"projection:certificates", "projection:discovery_findings", "outbox:notification.ct"},
	}

	certs, err := a.store.ListCertificatesPage(ctx, tenantID, store.ZeroUUID, nil, 500, nil)
	if err != nil {
		return rogueCertificatePostureResponse{}, err
	}
	out.Summary.TotalAnalyzed += len(certs)
	for _, cert := range certs {
		finding, ok := rogueCertificateFindingForCertificate(cert, now)
		if !ok {
			continue
		}
		out.addRogueCertificateFinding(finding)
	}

	rows, err := a.store.ListDiscoveryFindingsPage(ctx, tenantID, "", store.ZeroUUID, 500)
	if err != nil {
		return rogueCertificatePostureResponse{}, err
	}
	for _, row := range rows {
		if row.Kind != "ct_unexpected_issuance" {
			continue
		}
		out.Summary.TotalAnalyzed++
		out.addRogueCertificateFinding(rogueCertificateFindingForCT(row))
	}

	sort.Slice(out.Findings, func(i, j int) bool {
		left, right := out.Findings[i], out.Findings[j]
		if severityRank(left.Severity) != severityRank(right.Severity) {
			return severityRank(left.Severity) > severityRank(right.Severity)
		}
		if left.RiskScore != right.RiskScore {
			return left.RiskScore > right.RiskScore
		}
		if left.PolicyStatus != right.PolicyStatus {
			return left.PolicyStatus < right.PolicyStatus
		}
		return left.Subject < right.Subject
	})

	return out, nil
}

func (r *rogueCertificatePostureResponse) addRogueCertificateFinding(finding rogueCertificateFinding) {
	r.Findings = append(r.Findings, finding)
	r.Summary.Findings++
	r.Summary.Recommendations++
	if finding.PolicyStatus == "rogue" {
		r.Summary.Rogue++
	} else {
		r.Summary.NonCompliant++
	}
	for _, typ := range finding.FindingTypes {
		switch typ {
		case "ct_unexpected_issuance":
			r.Summary.CTUnexpected++
		case "weak_key_algorithm":
			r.Summary.WeakKey++
		case "lifetime_exceeds_policy":
			r.Summary.LifetimeViolations++
		case "expired_active_certificate":
			r.Summary.ExpiredActive++
		case "owner_missing":
			r.Summary.OwnerMissing++
		case "issuer_missing":
			r.Summary.IssuerMissing++
		}
	}
	switch finding.Severity {
	case "critical":
		r.Summary.Critical++
	case "high":
		r.Summary.High++
	case "medium":
		r.Summary.Medium++
	default:
		r.Summary.Low++
	}
}

func rogueCertificateFindingForCertificate(cert store.Certificate, now time.Time) (rogueCertificateFinding, bool) {
	if cert.Status == "revoked" || cert.Status == "superseded" {
		return rogueCertificateFinding{}, false
	}
	var types []string
	risk := 0
	if rogueCertificateWeakKey(cert.KeyAlgorithm) {
		types = append(types, "weak_key_algorithm")
		risk = maxInt(risk, 85)
	}
	if cert.NotAfter != nil && cert.NotAfter.Before(now) && firstNonEmpty(cert.Status, "active") == "active" {
		types = append(types, "expired_active_certificate")
		risk = maxInt(risk, 92)
	}
	lifetimeDays := 0
	const maxPublicTLSLifetimeDays = 398
	if cert.NotBefore != nil && cert.NotAfter != nil && cert.NotAfter.After(*cert.NotBefore) {
		lifetimeDays = int(cert.NotAfter.Sub(*cert.NotBefore).Hours() / 24)
		if lifetimeDays > maxPublicTLSLifetimeDays {
			types = append(types, "lifetime_exceeds_policy")
			risk = maxInt(risk, 65)
		}
	}
	if cert.OwnerID == nil || strings.TrimSpace(*cert.OwnerID) == "" {
		types = append(types, "owner_missing")
		risk = maxInt(risk, rogueCertificateOwnerRisk(cert.Source))
	}
	if strings.TrimSpace(cert.Issuer) == "" {
		types = append(types, "issuer_missing")
		risk = maxInt(risk, 55)
	}
	if len(types) == 0 {
		return rogueCertificateFinding{}, false
	}
	ownerID := ""
	if cert.OwnerID != nil {
		ownerID = strings.TrimSpace(*cert.OwnerID)
	}
	severity := rogueCertificateSeverity(risk)
	return rogueCertificateFinding{
		ID:             "certificate:" + cert.ID,
		CertificateID:  cert.ID,
		Kind:           "non_compliant_certificate",
		PolicyStatus:   "non_compliant",
		Subject:        firstNonEmpty(cert.Subject, cert.Fingerprint, cert.ID),
		Issuer:         cert.Issuer,
		Serial:         cert.Serial,
		Fingerprint:    cert.Fingerprint,
		DNSNames:       append([]string(nil), cert.SANs...),
		Source:         firstNonEmpty(cert.Source, "inventory"),
		OwnerID:        ownerID,
		Status:         firstNonEmpty(cert.Status, "active"),
		FindingTypes:   types,
		Severity:       severity,
		RiskScore:      risk,
		LifetimeDays:   lifetimeDays,
		PolicyMaxDays:  maxPublicTLSLifetimeDays,
		Recommendation: rogueCertificateRecommendation(types),
		EvidenceRefs: []string{
			"projection:certificates:" + cert.ID,
			"certificate:fingerprint:" + cert.Fingerprint,
		},
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
	}, true
}

func rogueCertificateFindingForCT(row store.DiscoveryFinding) rogueCertificateFinding {
	meta := map[string]any{}
	_ = json.Unmarshal(row.Metadata, &meta)
	logURL := rogueCertificateMetaString(meta, "log_url")
	index, hasIndex := rogueCertificateMetaInt64(meta, "index")
	subject := firstNonEmpty(rogueCertificateMetaString(meta, "subject"), row.Ref)
	issuer := rogueCertificateMetaString(meta, "issuer")
	serial := rogueCertificateMetaString(meta, "serial")
	sans := rogueCertificateMetaStrings(meta, "sans")
	notAfter := rogueCertificateMetaTime(meta, "not_after")
	discoveredAt := row.DiscoveredAt
	risk := maxInt(row.RiskScore, 90)
	finding := rogueCertificateFinding{
		ID:             "discovery:" + row.ID,
		DiscoveryID:    row.ID,
		SourceID:       row.SourceID,
		RunID:          row.RunID,
		Kind:           "rogue_certificate",
		PolicyStatus:   "rogue",
		Subject:        subject,
		Issuer:         issuer,
		Serial:         serial,
		Fingerprint:    row.Fingerprint,
		DNSNames:       sans,
		Source:         "ct_log",
		Status:         firstNonEmpty(row.TriageStatus, "open"),
		FindingTypes:   []string{"ct_unexpected_issuance", "not_in_inventory"},
		Severity:       rogueCertificateSeverity(risk),
		RiskScore:      risk,
		LogURL:         logURL,
		MatchedDomain:  rogueCertificateMetaString(meta, "matched_domain"),
		Recommendation: "Investigate this Certificate Transparency hit, claim it if sanctioned, or revoke and replace it from an approved CA.",
		EvidenceRefs: []string{
			"projection:discovery_findings:" + row.ID,
			"outbox:notification.ct",
		},
		DiscoveredAt: &discoveredAt,
		NotAfter:     notAfter,
	}
	if hasIndex {
		finding.LogIndex = &index
	}
	if logURL != "" {
		finding.EvidenceRefs = append(finding.EvidenceRefs, "ct_log:"+logURL)
	}
	return finding
}

func rogueCertificateWeakKey(algorithm string) bool {
	algo := strings.ToLower(strings.TrimSpace(algorithm))
	if algo == "" {
		return false
	}
	if strings.Contains(algo, "rsa") && (strings.Contains(algo, "512") || strings.Contains(algo, "1024")) {
		return true
	}
	if strings.Contains(algo, "sha1") || strings.Contains(algo, "md5") || strings.Contains(algo, "dsa") {
		return true
	}
	return false
}

func rogueCertificateOwnerRisk(source string) int {
	source = strings.ToLower(strings.TrimSpace(source))
	if source == "" || source == "issued" {
		return 45
	}
	return 60
}

func rogueCertificateSeverity(risk int) string {
	switch {
	case risk >= 90:
		return "critical"
	case risk >= 70:
		return "high"
	case risk >= 45:
		return "medium"
	default:
		return "low"
	}
}

func rogueCertificateRecommendation(types []string) string {
	if rogueCertificateStringSliceContains(types, "expired_active_certificate") {
		return "Revoke or replace the expired active certificate and remove it from production bindings."
	}
	if rogueCertificateStringSliceContains(types, "weak_key_algorithm") {
		return "Reissue with an approved key algorithm and revoke the weak-key certificate after replacement is deployed."
	}
	if rogueCertificateStringSliceContains(types, "lifetime_exceeds_policy") {
		return "Reissue under a shorter lifetime policy and document the owner before renewal."
	}
	if rogueCertificateStringSliceContains(types, "owner_missing") {
		return "Assign an owner and verify the certificate is sanctioned before treating it as compliant."
	}
	return "Review this certificate against issuance policy and remediate before the next renewal."
}

func rogueCertificateStringSliceContains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func rogueCertificateMetaString(meta map[string]any, key string) string {
	value, ok := meta[key]
	if !ok {
		return ""
	}
	if s, ok := value.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

func rogueCertificateMetaStrings(meta map[string]any, key string) []string {
	value, ok := meta[key]
	if !ok {
		return nil
	}
	switch v := value.(type) {
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return []string{strings.TrimSpace(v)}
	default:
		return nil
	}
}

func rogueCertificateMetaInt64(meta map[string]any, key string) (int64, bool) {
	value, ok := meta[key]
	if !ok {
		return 0, false
	}
	switch v := value.(type) {
	case float64:
		return int64(v), true
	case int64:
		return v, true
	case int:
		return int64(v), true
	default:
		return 0, false
	}
}

func rogueCertificateMetaTime(meta map[string]any, key string) *time.Time {
	raw := rogueCertificateMetaString(meta, key)
	if raw == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return nil
	}
	utc := t.UTC()
	return &utc
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
