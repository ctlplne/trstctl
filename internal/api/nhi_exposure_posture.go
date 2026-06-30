package api

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"
)

var nhiExposureCoverage = []string{
	"managed_identities",
	"discovery_findings",
	"internet_exposure",
	"insecure_transport",
	"weak_authentication",
	"public_callbacks",
	"network_policy",
	"remediation_recommendations",
}

var nhiExposureMarkerFields = []string{
	"internet_exposed",
	"publicly_accessible",
	"public_access",
	"external_access",
	"public_exposure",
}

var nhiExposureStringFields = []string{
	"exposure",
	"exposure_level",
	"network_exposure",
	"network_surface",
	"surface",
	"ingress",
	"deployment_exposure",
}

var nhiExposureEndpointFields = []string{
	"public_endpoint",
	"public_endpoints",
	"endpoint",
	"endpoints",
	"url",
	"urls",
	"service_url",
	"service_urls",
	"host",
	"hosts",
	"dns_name",
	"dns_names",
	"address",
	"addresses",
	"public_ip",
	"public_ips",
}

var nhiExposureCallbackFields = []string{
	"callback_url",
	"callback_urls",
	"redirect_uri",
	"redirect_uris",
	"webhook_url",
	"webhook_urls",
	"reply_url",
	"reply_urls",
}

var nhiTransportSecurityFields = []string{
	"transport_security",
	"tls_mode",
	"tls",
	"protocol",
	"scheme",
}

var nhiAuthModeFields = []string{
	"auth_mode",
	"authentication",
	"authn",
	"access_mode",
	"credential_auth",
}

var nhiNetworkPolicyFields = []string{
	"network_policy",
	"network_policy_status",
	"network_controls",
	"security_group_policy",
	"ingress_policy",
}

var nhiReachabilityFields = []string{
	"allowed_cidrs",
	"source_cidrs",
	"ingress_cidrs",
	"trusted_cidrs",
	"allowed_sources",
	"bind_address",
	"listen_address",
}

type nhiExposurePostureResponse struct {
	Capability  string                      `json:"capability"`
	GeneratedAt time.Time                   `json:"generated_at"`
	Coverage    []string                    `json:"coverage"`
	Summary     nhiExposurePostureSummary   `json:"summary"`
	Findings    []nhiExposurePostureFinding `json:"findings"`
}

type nhiExposurePostureSummary struct {
	TotalAnalyzed        int `json:"total_analyzed"`
	Findings             int `json:"findings"`
	InternetExposed      int `json:"internet_exposed"`
	InsecureTransport    int `json:"insecure_transport"`
	WeakAuthentication   int `json:"weak_authentication"`
	PublicCallbacks      int `json:"public_callbacks"`
	MissingNetworkPolicy int `json:"missing_network_policy"`
	WildcardReachability int `json:"wildcard_reachability"`
	Critical             int `json:"critical"`
	High                 int `json:"high"`
	Medium               int `json:"medium"`
	Low                  int `json:"low"`
	Recommendations      int `json:"recommendations"`
}

type nhiExposurePostureFinding struct {
	InventoryID       string   `json:"inventory_id"`
	Ref               string   `json:"ref,omitempty"`
	Kind              string   `json:"kind"`
	Source            string   `json:"source"`
	DisplayName       string   `json:"display_name"`
	OwnerID           string   `json:"owner_id,omitempty"`
	OwnerStatus       string   `json:"owner_status"`
	Status            string   `json:"status"`
	Severity          string   `json:"severity"`
	RiskScore         int      `json:"risk_score"`
	FindingTypes      []string `json:"finding_types"`
	ExposureLevel     string   `json:"exposure_level"`
	NetworkSurface    string   `json:"network_surface"`
	PublicEndpoints   []string `json:"public_endpoints"`
	CallbackURLs      []string `json:"callback_urls"`
	TransportSecurity string   `json:"transport_security"`
	AuthMode          string   `json:"auth_mode"`
	Environment       string   `json:"environment,omitempty"`
	Recommendation    string   `json:"recommendation"`
	EvidenceRefs      []string `json:"evidence_refs"`
}

func (a *API) listNHIExposurePosture(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	out, err := a.nhiExposurePosture(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, out)
}

func (a *API) nhiExposurePosture(ctx context.Context, tenantID string) (nhiExposurePostureResponse, error) {
	inventory, err := a.nhiInventory(ctx, tenantID)
	if err != nil {
		return nhiExposurePostureResponse{}, err
	}
	out := nhiExposurePostureResponse{
		Capability:  "CAP-POST-04",
		GeneratedAt: time.Now().UTC(),
		Coverage:    append([]string(nil), nhiExposureCoverage...),
		Findings:    []nhiExposurePostureFinding{},
	}
	for _, item := range inventory.Items {
		if !nhiStaleAnalyzable(item) {
			continue
		}
		out.Summary.TotalAnalyzed++
		finding, ok := nhiExposureFindingForItem(item)
		if !ok {
			continue
		}
		out.Findings = append(out.Findings, finding)
		out.Summary.Findings++
		out.Summary.Recommendations++
		if nhiStringSliceContains(finding.FindingTypes, "internet_exposed") {
			out.Summary.InternetExposed++
		}
		if nhiStringSliceContains(finding.FindingTypes, "insecure_transport") {
			out.Summary.InsecureTransport++
		}
		if nhiStringSliceContains(finding.FindingTypes, "weak_authentication") {
			out.Summary.WeakAuthentication++
		}
		if nhiStringSliceContains(finding.FindingTypes, "public_callback") {
			out.Summary.PublicCallbacks++
		}
		if nhiStringSliceContains(finding.FindingTypes, "missing_network_policy") {
			out.Summary.MissingNetworkPolicy++
		}
		if nhiStringSliceContains(finding.FindingTypes, "wildcard_reachability") {
			out.Summary.WildcardReachability++
		}
		switch finding.Severity {
		case "critical":
			out.Summary.Critical++
		case "high":
			out.Summary.High++
		case "medium":
			out.Summary.Medium++
		default:
			out.Summary.Low++
		}
	}
	sort.Slice(out.Findings, func(i, j int) bool {
		a, b := out.Findings[i], out.Findings[j]
		if severityRank(a.Severity) != severityRank(b.Severity) {
			return severityRank(a.Severity) > severityRank(b.Severity)
		}
		if a.RiskScore != b.RiskScore {
			return a.RiskScore > b.RiskScore
		}
		return a.DisplayName < b.DisplayName
	})
	return out, nil
}

func nhiExposureFindingForItem(item nhiInventoryItem) (nhiExposurePostureFinding, bool) {
	meta := decodeNHIInventoryMetadata(item.Metadata)
	publicEndpoints := publicNHIMetadataEndpoints(meta, nhiExposureEndpointFields)
	callbackURLs := publicNHIMetadataEndpoints(meta, nhiExposureCallbackFields)
	explicitPublic := firstNHIMetadataBool(meta, nhiExposureMarkerFields...)
	exposureLevel := firstNHIExposureValue(meta)
	networkSurface := firstNonEmpty(metadataString(meta, "network_surface"), metadataString(meta, "surface"), metadataString(meta, "deployment_location"))
	transportSecurity := firstNonEmpty(firstNHIMetadataString(meta, nhiTransportSecurityFields...), inferNHITransportSecurity(publicEndpoints, callbackURLs))
	authMode := firstNHIMetadataString(meta, nhiAuthModeFields...)
	environment := firstNonEmpty(metadataString(meta, "environment"), metadataString(meta, "env"))

	internetExposed := explicitPublic || len(publicEndpoints) > 0 || isNHIPublicExposure(exposureLevel)
	insecureTransport := isNHIInsecureTransport(transportSecurity, publicEndpoints, callbackURLs)
	weakAuth := isNHIWeakAuthentication(authMode) || firstNHIMetadataBoolFalse(meta, "requires_auth", "authenticated", "authentication_required")
	publicCallback := len(callbackURLs) > 0
	missingNetworkPolicy := isNHIMissingNetworkPolicy(meta)
	wildcardReachability := hasNHIWildcardReachability(meta)
	insecureDeployment := firstNHIMetadataBool(meta, "insecure_deployment", "misconfigured", "misconfiguration")

	var findingTypes []string
	if internetExposed {
		findingTypes = append(findingTypes, "internet_exposed")
	}
	if insecureTransport {
		findingTypes = append(findingTypes, "insecure_transport")
	}
	if weakAuth {
		findingTypes = append(findingTypes, "weak_authentication")
	}
	if publicCallback {
		findingTypes = append(findingTypes, "public_callback")
	}
	if missingNetworkPolicy {
		findingTypes = append(findingTypes, "missing_network_policy")
	}
	if wildcardReachability {
		findingTypes = append(findingTypes, "wildcard_reachability")
	}
	if insecureDeployment {
		findingTypes = append(findingTypes, "insecure_deployment")
	}
	if len(findingTypes) == 0 {
		return nhiExposurePostureFinding{}, false
	}
	if exposureLevel == "" {
		if internetExposed {
			exposureLevel = "internet"
		} else {
			exposureLevel = "internal"
		}
	}
	severity := nhiExposureSeverity(internetExposed, insecureTransport, weakAuth, publicCallback, missingNetworkPolicy, wildcardReachability, insecureDeployment)
	riskScore := item.RiskScore
	if computed := nhiExposureRiskScore(severity, findingTypes); computed > riskScore {
		riskScore = computed
	}
	return nhiExposurePostureFinding{
		InventoryID:       item.ID,
		Ref:               item.Ref,
		Kind:              item.Kind,
		Source:            item.Source,
		DisplayName:       item.DisplayName,
		OwnerID:           item.OwnerID,
		OwnerStatus:       nhiOwnerStatus(item, meta),
		Status:            item.Status,
		Severity:          severity,
		RiskScore:         riskScore,
		FindingTypes:      findingTypes,
		ExposureLevel:     exposureLevel,
		NetworkSurface:    networkSurface,
		PublicEndpoints:   publicEndpoints,
		CallbackURLs:      callbackURLs,
		TransportSecurity: transportSecurity,
		AuthMode:          authMode,
		Environment:       environment,
		Recommendation:    nhiExposureRecommendation(findingTypes),
		EvidenceRefs:      nhiExposureEvidence(item, meta),
	}, true
}

func firstNHIExposureValue(meta map[string]any) string {
	for _, value := range collectNHIPostureStrings(meta, nhiExposureStringFields) {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func firstNHIMetadataString(meta map[string]any, fields ...string) string {
	for _, field := range fields {
		if value := strings.TrimSpace(metadataString(meta, field)); value != "" {
			return value
		}
	}
	return ""
}

func firstNHIMetadataBool(meta map[string]any, fields ...string) bool {
	for _, field := range fields {
		switch value := meta[field].(type) {
		case bool:
			if value {
				return true
			}
		case string:
			if isNHIMetadataTruthy(value) {
				return true
			}
		}
	}
	return false
}

func firstNHIMetadataBoolFalse(meta map[string]any, fields ...string) bool {
	for _, field := range fields {
		switch value := meta[field].(type) {
		case bool:
			if !value {
				return true
			}
		case string:
			v := normalizeNHIPostureString(value)
			if v == "false" || v == "no" || v == "0" || v == "disabled" {
				return true
			}
		}
	}
	return false
}

func isNHIMetadataTruthy(value string) bool {
	switch normalizeNHIPostureString(value) {
	case "true", "yes", "1", "enabled", "public", "internet", "external", "world", "world_reachable", "publicly_accessible":
		return true
	default:
		return false
	}
}

func publicNHIMetadataEndpoints(meta map[string]any, fields []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, raw := range collectNHIPostureStrings(meta, fields) {
		sanitized := sanitizeNHIEndpoint(raw)
		if sanitized == "" || !isPublicNHIEndpoint(sanitized) {
			continue
		}
		key := normalizeNHIPostureString(sanitized)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, sanitized)
	}
	sort.Strings(out)
	return out
}

func sanitizeNHIEndpoint(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if u, err := url.Parse(value); err == nil && u.Host != "" {
		u.User = nil
		u.RawQuery = ""
		u.Fragment = ""
		return u.String()
	}
	return strings.TrimSuffix(value, ".")
}

func isPublicNHIEndpoint(value string) bool {
	host := value
	if u, err := url.Parse(value); err == nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".local") ||
		strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".svc") ||
		strings.HasSuffix(host, ".cluster.local") {
		return false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.IsGlobalUnicast() && !addr.IsPrivate() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast()
	}
	return strings.Contains(host, ".")
}

func isNHIPublicExposure(value string) bool {
	switch normalizeNHIPostureString(value) {
	case "internet", "public", "external", "world", "world_reachable", "publicly_accessible":
		return true
	default:
		return false
	}
}

func inferNHITransportSecurity(endpoints, callbacks []string) string {
	for _, endpoint := range append(append([]string{}, endpoints...), callbacks...) {
		if strings.HasPrefix(strings.ToLower(endpoint), "http://") {
			return "plaintext_http"
		}
	}
	if len(endpoints)+len(callbacks) > 0 {
		return "tls"
	}
	return ""
}

func isNHIInsecureTransport(transport string, endpoints, callbacks []string) bool {
	for _, endpoint := range append(append([]string{}, endpoints...), callbacks...) {
		if strings.HasPrefix(strings.ToLower(endpoint), "http://") {
			return true
		}
	}
	switch normalizeNHIPostureString(transport) {
	case "none", "disabled", "plaintext", "plain_http", "plaintext_http", "http", "tls_disabled", "opportunistic":
		return true
	default:
		return false
	}
}

func isNHIWeakAuthentication(authMode string) bool {
	switch normalizeNHIPostureString(authMode) {
	case "none", "anonymous", "public", "unauthenticated", "disabled", "default", "shared", "shared_secret", "api_key_query", "query_token", "basic_default":
		return true
	default:
		return false
	}
}

func isNHIMissingNetworkPolicy(meta map[string]any) bool {
	if firstNHIMetadataBoolFalse(meta, "network_policy_enforced", "network_policy_present", "ingress_policy_enforced") {
		return true
	}
	for _, value := range collectNHIPostureStrings(meta, nhiNetworkPolicyFields) {
		switch normalizeNHIPostureString(value) {
		case "missing", "none", "disabled", "allow_all", "allow-all", "not_enforced", "unenforced":
			return true
		}
	}
	return false
}

func hasNHIWildcardReachability(meta map[string]any) bool {
	for _, value := range collectNHIPostureStrings(meta, nhiReachabilityFields) {
		switch normalizeNHIPostureString(value) {
		case "*", "0.0.0.0", "0.0.0.0/0", "::", "::/0", "any", "anywhere", "all":
			return true
		}
	}
	return false
}

func nhiExposureSeverity(internetExposed, insecureTransport, weakAuth, publicCallback, missingNetworkPolicy, wildcardReachability, insecureDeployment bool) string {
	switch {
	case internetExposed && weakAuth && (insecureTransport || wildcardReachability):
		return "critical"
	case internetExposed && (weakAuth || insecureTransport || wildcardReachability || missingNetworkPolicy):
		return "high"
	case internetExposed || publicCallback || insecureDeployment:
		return "medium"
	default:
		return "low"
	}
}

func nhiExposureRiskScore(severity string, findingTypes []string) int {
	base := map[string]int{"critical": 94, "high": 82, "medium": 62, "low": 35}[severity]
	score := base + len(findingTypes)*3
	if score > 100 {
		return 100
	}
	return score
}

func nhiExposureRecommendation(types []string) string {
	parts := map[string]bool{}
	for _, typ := range types {
		parts[typ] = true
	}
	switch {
	case parts["internet_exposed"] && parts["weak_authentication"] && parts["insecure_transport"]:
		return "Remove the public route, require strong service-to-service authentication, and re-enable TLS before this NHI is used again."
	case parts["internet_exposed"] && parts["wildcard_reachability"]:
		return "Replace wildcard reachability with explicit CIDR/service allowlists and bind the NHI to a private network path."
	case parts["public_callback"] && parts["insecure_transport"]:
		return "Move callback or webhook URLs to HTTPS endpoints and rotate the linked client secret after the exposure window closes."
	case parts["missing_network_policy"]:
		return "Attach a network policy or security-group rule that limits this NHI to known workloads and owner-approved sources."
	case parts["weak_authentication"]:
		return "Replace anonymous, default, or shared authentication with a managed short-lived credential and owner-bound approval."
	default:
		return "Review the exposed deployment metadata, remove public reachability where possible, and record owner-approved residual risk."
	}
}

func nhiExposureEvidence(item nhiInventoryItem, meta map[string]any) []string {
	evidence := []string{"inventory:" + item.ID}
	for _, fields := range [][]string{
		nhiExposureMarkerFields,
		nhiExposureStringFields,
		nhiExposureEndpointFields,
		nhiExposureCallbackFields,
		nhiTransportSecurityFields,
		nhiAuthModeFields,
		nhiNetworkPolicyFields,
		nhiReachabilityFields,
		{"requires_auth", "authenticated", "authentication_required", "network_policy_enforced", "insecure_deployment", "misconfigured", "misconfiguration"},
	} {
		for _, field := range fields {
			if _, ok := meta[field]; ok {
				evidence = append(evidence, "metadata:"+field)
				break
			}
		}
	}
	return evidence
}
