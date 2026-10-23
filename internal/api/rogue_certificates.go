// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/keyposture"
	"trstctl.com/trstctl/internal/policy"
	"trstctl.com/trstctl/internal/store"
)

const rogueCertificateCapability = "CAP-REV-05"

var rogueCertificateCoverage = []string{
	"certificate_inventory",
	"ct_unexpected_issuance",
	"weak_key_algorithm",
	"distrusted_issuer",
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
	// Tenant posture rules (A42): the active lifecycle module whose
	// certificate_posture rules were evaluated, how many certificates were
	// evaluated, and how many evaluations failed (those certificates carry no
	// policy verdict rather than a false clean one).
	PolicyModuleSHA256     string `json:"policy_module_sha256,omitempty"`
	PolicyEvaluated        int    `json:"policy_evaluated"`
	PolicyEvaluationErrors int    `json:"policy_evaluation_errors"`
}

type rogueCertificatePolicyViolation struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Reason   string `json:"reason,omitempty"`
	// Remediation is the automatic action the rule asked for (A47): "renew"
	// means the lifecycle scheduler queues a renewal for a managed identity
	// whose served certificate fires the rule.
	Remediation string `json:"remediation,omitempty"`
}

type rogueCertificateSummary struct {
	TotalAnalyzed      int `json:"total_analyzed"`
	Findings           int `json:"findings"`
	Rogue              int `json:"rogue"`
	NonCompliant       int `json:"non_compliant"`
	CTUnexpected       int `json:"ct_unexpected"`
	WeakKey            int `json:"weak_key"`
	DistrustedIssuer   int `json:"distrusted_issuer"`
	LifetimeViolations int `json:"lifetime_violations"`
	ExpiredActive      int `json:"expired_active"`
	OwnerMissing       int `json:"owner_missing"`
	IssuerMissing      int `json:"issuer_missing"`
	Critical           int `json:"critical"`
	High               int `json:"high"`
	Medium             int `json:"medium"`
	Low                int `json:"low"`
	Recommendations    int `json:"recommendations"`
	PolicyViolations   int `json:"policy_violations"`
}

type rogueCertificateFinding struct {
	ID             string   `json:"id"`
	CertificateID  string   `json:"certificate_id,omitempty"`
	DiscoveryID    string   `json:"discovery_id,omitempty"`
	SourceID       string   `json:"source_id,omitempty"`
	RunID          string   `json:"run_id,omitempty"`
	Kind           string   `json:"kind"`
	PolicyStatus   string   `json:"policy_status"`
	Subject        string   `json:"subject"`
	Issuer         string   `json:"issuer,omitempty"`
	Serial         string   `json:"serial,omitempty"`
	Fingerprint    string   `json:"fingerprint,omitempty"`
	DNSNames       []string `json:"dns_names,omitempty"`
	Source         string   `json:"source"`
	OwnerID        string   `json:"owner_id,omitempty"`
	Status         string   `json:"status,omitempty"`
	FindingTypes   []string `json:"finding_types"`
	Severity       string   `json:"severity"`
	RiskScore      int      `json:"risk_score"`
	LifetimeDays   int      `json:"lifetime_days,omitempty"`
	PolicyMaxDays  int      `json:"policy_max_days,omitempty"`
	LogURL         string   `json:"log_url,omitempty"`
	LogIndex       *int64   `json:"log_index,omitempty"`
	MatchedDomain  string   `json:"matched_domain,omitempty"`
	Recommendation string   `json:"recommendation"`
	EvidenceRefs   []string `json:"evidence_refs"`
	// WeakKeyReasons says why the key is weak whatever its algorithm and size
	// (Part 4): a small private scalar, a factorable modulus, a size below the
	// floor, a broken signature hash.
	WeakKeyReasons []string `json:"weak_key_reasons,omitempty"`
	// Distrust names the distrust-list entry this certificate is, or was
	// issued under, and how that was established.
	Distrust *rogueCertificateDistrust `json:"distrust,omitempty"`
	// PolicyViolations are the tenant certificate_posture rules this
	// certificate violates (A42); each also appears in finding_types as
	// customer_policy:<rule>.
	PolicyViolations []rogueCertificatePolicyViolation `json:"policy_violations,omitempty"`
	// InstalledOn lists the connector targets trstctl delivered this leaf to,
	// or restored it on by rollback (an adopted predecessor, A45),
	// and the remediation each can execute (A43): host_purge through the
	// enrolled agent, appliance_takedown through a network relay, or none.
	InstalledOn  []rogueInstalledTarget `json:"installed_on,omitempty"`
	DiscoveredAt *time.Time             `json:"discovered_at,omitempty"`
	NotBefore    *time.Time             `json:"not_before,omitempty"`
	NotAfter     *time.Time             `json:"not_after,omitempty"`
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

	// Discovery findings carry the key verdict their reader computed while the
	// certificate's bytes were at hand (Part 4); an inventory row without bytes
	// borrows it by fingerprint.
	rows, err := a.store.ListDiscoveryFindingsPage(ctx, tenantID, "", store.ZeroUUID, 500)
	if err != nil {
		return rogueCertificatePostureResponse{}, err
	}
	discovered := map[string]keyposture.Verdict{}
	for _, row := range rows {
		meta := map[string]any{}
		if row.Fingerprint == "" || json.Unmarshal(row.Metadata, &meta) != nil {
			continue
		}
		if v := keyposture.FromMetadata(meta); !v.Empty() {
			fp := strings.ToLower(row.Fingerprint)
			discovered[fp] = discovered[fp].Merge(v)
		}
	}
	certs, err := a.store.ListCertificatesPage(ctx, tenantID, store.ZeroUUID, nil, 500, nil)
	if err != nil {
		return rogueCertificatePostureResponse{}, err
	}
	posture, _ := a.gate.Policy.(PosturePolicyEvaluator)
	moduleSHA := ""
	if posture != nil {
		if _, info, err := posture.ActiveModule(ctx, tenantID); err == nil {
			moduleSHA = info.ModuleSHA256
			out.Coverage = append(out.Coverage, "customer_policy")
			out.PolicyModuleSHA256 = moduleSHA
			out.EvidenceRefs = append(out.EvidenceRefs, "policy:module:"+moduleSHA)
		} else {
			posture = nil
			out.PolicyEvaluationErrors++
		}
	}
	out.Summary.TotalAnalyzed += len(certs)
	for _, cert := range certs {
		finding, ok := rogueCertificateFindingForCertificate(cert, now, discovered)
		if ok {
			out.addRogueCertificateFinding(finding)
		}
		if posture == nil || cert.Status == "revoked" || cert.Status == "superseded" {
			continue
		}
		violations, err := posture.EvaluatePosture(ctx, policy.Input{
			Action: policy.ActionCertificatePosture, TenantID: tenantID, Subject: cert.ID,
			Certificate: rogueCertificateFacts(cert, now),
		})
		if err != nil {
			out.PolicyEvaluationErrors++
			continue
		}
		out.PolicyEvaluated++
		if len(violations) == 0 {
			continue
		}
		var existing *rogueCertificateFinding
		if ok {
			existing = &out.Findings[len(out.Findings)-1]
		}
		out.applyRoguePolicyViolations(cert, existing, violations, moduleSHA)
	}

	for _, row := range rows {
		if row.Kind != "ct_unexpected_issuance" {
			continue
		}
		out.Summary.TotalAnalyzed++
		out.addRogueCertificateFinding(rogueCertificateFindingForCT(row))
	}

	if err := a.attachRogueInstalledTargets(ctx, tenantID, out.Findings); err != nil {
		return rogueCertificatePostureResponse{}, err
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
		case "distrusted_issuer":
			r.Summary.DistrustedIssuer++
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

// CertificatePostureFacts is the public metadata a tenant posture rule may
// read, shared with the lifecycle scheduler's posture remediation (A47) so the
// listing and the scheduler evaluate the same facts.
func CertificatePostureFacts(cert store.Certificate, now time.Time) *policy.CertificateFacts {
	return rogueCertificateFacts(cert, now)
}

// rogueCertificateFacts is the public metadata a tenant posture rule may read.
func rogueCertificateFacts(cert store.Certificate, now time.Time) *policy.CertificateFacts {
	facts := &policy.CertificateFacts{
		ID: cert.ID, Subject: cert.Subject, Issuer: cert.Issuer, Serial: cert.Serial, Fingerprint: cert.Fingerprint,
		DNSNames: append([]string(nil), cert.SANs...), KeyAlgorithm: cert.KeyAlgorithm,
		NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, Status: firstNonEmpty(cert.Status, "active"),
		Source: firstNonEmpty(cert.Source, "inventory"), CAID: cert.CAID, DeploymentLocation: cert.DeploymentLocation,
	}
	if cert.OwnerID != nil {
		facts.OwnerID = strings.TrimSpace(*cert.OwnerID)
	}
	if cert.NotBefore != nil && cert.NotAfter != nil && cert.NotAfter.After(*cert.NotBefore) {
		facts.LifetimeDays = int(cert.NotAfter.Sub(*cert.NotBefore).Hours() / 24)
	}
	if cert.NotAfter != nil {
		facts.DaysUntilExpiry = int(cert.NotAfter.Sub(now).Hours() / 24)
	}
	return facts
}

// applyRoguePolicyViolations records the tenant rules a certificate violates
// (A42): merged into the certificate's existing finding when it already has
// one, else as a policy-only non-compliant finding. The severity rises to the
// strongest rule and never falls; an unknown severity reads as medium.
func (r *rogueCertificatePostureResponse) applyRoguePolicyViolations(cert store.Certificate, existing *rogueCertificateFinding, violations []policy.PostureViolation, moduleSHA string) {
	if len(violations) == 0 {
		return
	}
	risk := 0
	var types []string
	var recorded []rogueCertificatePolicyViolation
	for _, v := range violations {
		severity := v.Severity
		switch severity {
		case "critical", "high", "medium", "low":
		default:
			severity = "medium"
		}
		risk = maxInt(risk, rogueCertificatePolicySeverityRisk(severity))
		types = append(types, "customer_policy:"+v.Rule)
		recorded = append(recorded, rogueCertificatePolicyViolation{Rule: v.Rule, Severity: severity, Reason: v.Reason, Remediation: v.Remediation})
	}
	r.Summary.PolicyViolations += len(recorded)
	evidence := "policy:module:" + moduleSHA
	if existing != nil {
		existing.FindingTypes = append(existing.FindingTypes, types...)
		existing.PolicyViolations = append(existing.PolicyViolations, recorded...)
		existing.EvidenceRefs = append(existing.EvidenceRefs, evidence)
		if risk > existing.RiskScore {
			r.Summary.adjustSeverity(existing.Severity, rogueCertificateSeverity(risk))
			existing.RiskScore = risk
			existing.Severity = rogueCertificateSeverity(risk)
		}
		return
	}
	ownerID := ""
	if cert.OwnerID != nil {
		ownerID = strings.TrimSpace(*cert.OwnerID)
	}
	r.addRogueCertificateFinding(rogueCertificateFinding{
		ID: "certificate:" + cert.ID, CertificateID: cert.ID, Kind: "non_compliant_certificate", PolicyStatus: "non_compliant",
		Subject: firstNonEmpty(cert.Subject, cert.Fingerprint, cert.ID), Issuer: cert.Issuer, Serial: cert.Serial, Fingerprint: cert.Fingerprint,
		DNSNames: append([]string(nil), cert.SANs...), Source: firstNonEmpty(cert.Source, "inventory"), OwnerID: ownerID,
		Status: firstNonEmpty(cert.Status, "active"), FindingTypes: types, Severity: rogueCertificateSeverity(risk), RiskScore: risk,
		Recommendation:   "Replace or revoke this certificate, or revise the tenant posture rule it violates; the rule names its own reason.",
		EvidenceRefs:     []string{"projection:certificates:" + cert.ID, "certificate:fingerprint:" + cert.Fingerprint, evidence},
		PolicyViolations: recorded, NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
	})
}

func rogueCertificatePolicySeverityRisk(severity string) int {
	switch severity {
	case "critical":
		return 95
	case "high":
		return 80
	case "medium":
		return 60
	default:
		return 30
	}
}

// adjustSeverity moves one finding between severity buckets after a merge.
func (s *rogueCertificateSummary) adjustSeverity(from, to string) {
	bump := func(severity string, delta int) {
		switch severity {
		case "critical":
			s.Critical += delta
		case "high":
			s.High += delta
		case "medium":
			s.Medium += delta
		default:
			s.Low += delta
		}
	}
	bump(from, -1)
	bump(to, 1)
}

// rogueCertificateDistrust is how a finding depends on the distrust list.
type rogueCertificateDistrust struct {
	Entry   string `json:"entry"`
	How     string `json:"how"`
	Reason  string `json:"reason,omitempty"`
	Subject string `json:"subject,omitempty"`
}

func rogueDistrustOf(v keyposture.Verdict) *rogueCertificateDistrust {
	if !v.Distrusted() {
		return nil
	}
	return &rogueCertificateDistrust{Entry: v.DistrustEntry, How: v.DistrustHow, Reason: v.DistrustReason, Subject: v.DistrustSubject}
}

// rogueCertificateVerdict rates an inventory certificate (Part 4). With the
// certificate's bytes it is the full rating: its key, its signature hash, and
// the distrust list by key, recorded chain and authority key identifier. A
// row that kept no bytes is rated from its recorded key-algorithm name and
// issuer name. The old check read only the bare algorithm name, so every
// ECDSA certificate matched "dsa" and an RSA-1024 certificate never matched.
func rogueCertificateVerdict(cert store.Certificate, discovered map[string]keyposture.Verdict) keyposture.Verdict {
	raw := cert.CertificatePEM
	if len(raw) == 0 {
		raw = cert.CertificateDER
	}
	found, ok := discovered[strings.ToLower(cert.Fingerprint)]
	if len(raw) > 0 {
		if v, err := keyposture.RateCertificateBytes(raw); err == nil {
			// The bytes rate the certificate; a discovery verdict adds what only
			// an inventory-wide check knows (a prime shared with another key).
			return v.Merge(found)
		}
	}
	// A discovered certificate's reader rated it while its bytes were at hand.
	if ok {
		return found
	}
	return keyposture.RateRecorded(cert.Issuer, cert.KeyAlgorithm)
}

// applyKeyVerdict adds the weak-key and distrust finding types a verdict
// calls for and returns the raised risk.
func applyKeyVerdict(v keyposture.Verdict, types []string, risk int) ([]string, int) {
	if v.Weak() {
		types = append(types, "weak_key_algorithm")
	}
	if v.Distrusted() {
		types = append(types, "distrusted_issuer")
	}
	return types, maxInt(risk, v.RiskFloor())
}

func rogueCertificateFindingForCertificate(cert store.Certificate, now time.Time, discovered map[string]keyposture.Verdict) (rogueCertificateFinding, bool) {
	if cert.Status == "revoked" || cert.Status == "superseded" {
		return rogueCertificateFinding{}, false
	}
	var types []string
	risk := 0
	verdict := rogueCertificateVerdict(cert, discovered)
	types, risk = applyKeyVerdict(verdict, types, risk)
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
		WeakKeyReasons: verdict.WeakReasons,
		Distrust:       rogueDistrustOf(verdict),
		NotBefore:      cert.NotBefore,
		NotAfter:       cert.NotAfter,
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
	// The CT reader rated the certificate while its bytes were at hand (Part 4).
	verdict := keyposture.FromMetadata(meta)
	types, risk := applyKeyVerdict(verdict, []string{"ct_unexpected_issuance", "not_in_inventory"}, risk)
	recommendation := "Investigate this Certificate Transparency hit, claim it if sanctioned, or revoke and replace it from an approved CA."
	if verdict.Distrusted() || verdict.Weak() {
		recommendation = rogueCertificateRecommendation(types)
	}
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
		FindingTypes:   types,
		Severity:       rogueCertificateSeverity(risk),
		RiskScore:      risk,
		LogURL:         logURL,
		MatchedDomain:  rogueCertificateMetaString(meta, "matched_domain"),
		Recommendation: recommendation,
		WeakKeyReasons: verdict.WeakReasons,
		Distrust:       rogueDistrustOf(verdict),
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
	if rogueCertificateStringSliceContains(types, "distrusted_issuer") {
		return "Replace this certificate from a trusted issuer: it is, or chains to, a CA or key on the distrust list. Claim it as a managed identity if it is not one, move it with a migration run, then revoke or remove the old certificate."
	}
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
