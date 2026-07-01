package risk

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/store"
)

const highBlastRadiusThreshold = 4

// ContextualPriority is one scored credential with the blast-radius evidence
// and operator action needed to answer "what should I fix first" (CAP-POST-05).
type ContextualPriority struct {
	Rank                   int            `json:"rank"`
	CredentialID           string         `json:"credential_id"`
	Subject                string         `json:"subject"`
	Kind                   string         `json:"kind"`
	Severity               string         `json:"severity"`
	ContextualScore        float64        `json:"contextual_score"`
	BaseScore              float64        `json:"base_score"`
	BlastRadius            int            `json:"blast_radius"`
	ResourceBlastRadius    int            `json:"resource_blast_radius"`
	WorkloadBlastRadius    int            `json:"workload_blast_radius"`
	CredentialBlastRadius  int            `json:"credential_blast_radius"`
	CryptoAssetBlastRadius int            `json:"crypto_asset_blast_radius"`
	WeakCryptoContext      int            `json:"weak_crypto_context"`
	Privilege              PrivilegeClass `json:"privilege"`
	Sensitivity            Sensitivity    `json:"sensitivity"`
	OwnerActive            bool           `json:"owner_active"`
	ExpiresAt              time.Time      `json:"expires_at"`
	Components             Components     `json:"components"`
	PriorityReasons        []string       `json:"priority_reasons"`
	EvidenceRefs           []string       `json:"evidence_refs"`
	RecommendedAction      string         `json:"recommended_action"`
}

// ContextualPriorities scores tenant credentials, then raises priority when a
// credential's graph blast radius reaches resources or weak/quantum crypto
// assets. Reads stay tenant-scoped through the store and graph builder.
func ContextualPriorities(ctx context.Context, st *store.Store, tenantID string) ([]ContextualPriority, error) {
	g, err := graph.Build(ctx, st, tenantID)
	if err != nil {
		return nil, err
	}
	now := time.Now()

	var out []ContextualPriority
	after := store.ZeroUUID
	for {
		page, err := st.ListCertificatesPage(ctx, tenantID, after, nil, pageSize, nil)
		if err != nil {
			return nil, err
		}
		for _, c := range page {
			base := scoreCertificate(g, c, now)
			impact := g.BlastRadius(base.GraphNodeID)
			out = append(out, contextualPriority(base, impact, now))
		}
		if len(page) < pageSize {
			break
		}
		after = page[len(page)-1].ID
	}

	identityPriorities, err := contextualIdentityPriorities(ctx, st, tenantID, g, now)
	if err != nil {
		return nil, err
	}
	out = append(out, identityPriorities...)

	sshKeyPriorities, err := contextualSSHKeyPriorities(ctx, st, tenantID, g, now)
	if err != nil {
		return nil, err
	}
	out = append(out, sshKeyPriorities...)

	discoveryPriorities, err := contextualDiscoveryPriorities(ctx, st, tenantID, g, now)
	if err != nil {
		return nil, err
	}
	out = append(out, discoveryPriorities...)

	SortByContextualPriority(out)
	for i := range out {
		out[i].Rank = i + 1
	}
	return out, nil
}

func contextualIdentityPriorities(ctx context.Context, st *store.Store, tenantID string, g *graph.Graph, now time.Time) ([]ContextualPriority, error) {
	var out []ContextualPriority
	after := store.ZeroUUID
	for {
		page, err := st.ListIdentitiesPage(ctx, tenantID, after, pageSize)
		if err != nil {
			return nil, err
		}
		for _, it := range page {
			if it.Kind == store.KindX509Certificate {
				continue
			}
			base := scoreIdentity(g, it, now)
			out = append(out, contextualPriority(base, g.BlastRadius(base.GraphNodeID), now))
		}
		if len(page) < pageSize {
			return out, nil
		}
		after = page[len(page)-1].ID
	}
}

func contextualSSHKeyPriorities(ctx context.Context, st *store.Store, tenantID string, g *graph.Graph, now time.Time) ([]ContextualPriority, error) {
	var out []ContextualPriority
	after := store.ZeroUUID
	for {
		page, err := st.ListSSHKeysPage(ctx, tenantID, after, pageSize)
		if err != nil {
			return nil, err
		}
		for _, key := range page {
			base := scoreSSHKey(g, key, now)
			out = append(out, contextualPriority(base, g.BlastRadius(base.GraphNodeID), now))
		}
		if len(page) < pageSize {
			return out, nil
		}
		after = page[len(page)-1].ID
	}
}

func contextualDiscoveryPriorities(ctx context.Context, st *store.Store, tenantID string, g *graph.Graph, now time.Time) ([]ContextualPriority, error) {
	var out []ContextualPriority
	after := store.ZeroUUID
	for {
		page, err := st.ListDiscoveryFindingsPage(ctx, tenantID, "", after, pageSize)
		if err != nil {
			return nil, err
		}
		for _, finding := range page {
			base := scoreDiscoveryFinding(g, finding, now)
			out = append(out, contextualPriority(base, g.BlastRadius(base.GraphNodeID), now))
		}
		if len(page) < pageSize {
			return out, nil
		}
		after = page[len(page)-1].ID
	}
}

func scoreIdentity(g *graph.Graph, it store.Identity, now time.Time) CredentialRisk {
	meta := metadataMap(it.Attributes)
	nodeID := "id:" + it.ID
	exposure := credentialExposure(g, nodeID)
	kind := normalizeCredentialKind(string(it.Kind))
	priv := inferNHIPrivilege(kind, meta, exposure)
	sens := inferNHISensitivity(kind, meta)
	ownerActive := strings.TrimSpace(it.OwnerID) != "" && !metadataOwnerOrphaned(meta)
	notBefore := deref(it.NotBefore)
	if notBefore.IsZero() {
		notBefore = it.CreatedAt
	}
	lastRotated := metadataTime(meta, "last_rotated_at", "rotated_at", "last_rotation_at")
	if lastRotated.IsZero() {
		lastRotated = it.CreatedAt
	}
	sc := Compute(Signals{
		Now:         now,
		NotBefore:   notBefore,
		NotAfter:    deref(it.NotAfter),
		Exposure:    exposure,
		Privilege:   priv,
		LastRotated: lastRotated,
		OwnerActive: ownerActive,
		Sensitivity: sens,
	})
	return CredentialRisk{
		CredentialID: it.ID,
		Subject:      firstNonEmptyRisk(it.Name, it.ID),
		Kind:         kind,
		Privilege:    priv,
		Sensitivity:  sens,
		Exposure:     exposure,
		OwnerActive:  ownerActive,
		ExpiresAt:    deref(it.NotAfter),
		Score:        sc.Total,
		Components:   sc.Components,
		GraphNodeID:  nodeID,
		EvidenceRefs: []string{"identity:" + it.ID},
	}
}

func scoreSSHKey(g *graph.Graph, key store.SSHKey, now time.Time) CredentialRisk {
	nodeID := "ssh:" + key.ID
	exposure := credentialExposure(g, nodeID)
	priv := PrivilegeLow
	if key.StandingAccess || exposure >= 4 {
		priv = PrivilegeHigh
	} else if exposure > 0 {
		priv = PrivilegeStandard
	}
	sens := SensitivityLow
	if key.StandingAccess {
		sens = SensitivityHigh
	} else if exposure > 0 {
		sens = SensitivityMedium
	}
	sc := Compute(Signals{
		Now:         now,
		NotBefore:   key.CreatedAt,
		NotAfter:    time.Time{},
		Exposure:    exposure,
		Privilege:   priv,
		LastRotated: time.Time{},
		OwnerActive: !key.Orphaned,
		Sensitivity: sens,
	})
	return CredentialRisk{
		CredentialID: key.ID,
		Subject:      firstNonEmptyRisk(key.Comment, key.Fingerprint, key.ID),
		Kind:         "ssh_key",
		Privilege:    priv,
		Sensitivity:  sens,
		Exposure:     exposure,
		OwnerActive:  !key.Orphaned,
		Score:        sc.Total,
		Components:   sc.Components,
		GraphNodeID:  nodeID,
		EvidenceRefs: []string{"ssh_key:" + key.ID},
	}
}

func scoreDiscoveryFinding(g *graph.Graph, finding store.DiscoveryFinding, now time.Time) CredentialRisk {
	meta := metadataMap(finding.Metadata)
	nodeID := "disc:" + finding.ID
	exposure := credentialExposure(g, nodeID)
	kind := discoveryCredentialKind(finding.Kind, meta)
	priv := inferNHIPrivilege(kind, meta, exposure)
	sens := inferNHISensitivity(kind, meta)
	ownerActive := metadataOwnerActive(meta)
	notBefore := metadataTime(meta, "not_before", "issued_at", "created_at")
	if notBefore.IsZero() {
		notBefore = finding.DiscoveredAt
	}
	notAfter := metadataTime(meta, "not_after", "expires_at", "expiry")
	lastRotated := metadataTime(meta, "last_rotated_at", "rotated_at", "last_rotation_at")
	sc := Compute(Signals{
		Now:         now,
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		Exposure:    exposure,
		Privilege:   priv,
		LastRotated: lastRotated,
		OwnerActive: ownerActive,
		Sensitivity: sens,
	})
	if finding.RiskScore > 0 {
		sc.Total = math.Max(sc.Total, clampScore(float64(finding.RiskScore)))
	}
	return CredentialRisk{
		CredentialID: "discovery:" + finding.ID,
		Subject:      firstNonEmptyRisk(metadataString(meta, "display_name"), metadataString(meta, "principal"), finding.Ref, finding.Fingerprint, finding.ID),
		Kind:         kind,
		Privilege:    priv,
		Sensitivity:  sens,
		Exposure:     exposure,
		OwnerActive:  ownerActive,
		ExpiresAt:    notAfter,
		Score:        sc.Total,
		Components:   sc.Components,
		GraphNodeID:  nodeID,
		EvidenceRefs: []string{"discovery.finding:" + finding.ID},
	}
}

func contextualPriority(base CredentialRisk, impact graph.Impact, now time.Time) ContextualPriority {
	resourceBlast := len(impact.ByKind[graph.KindResource])
	workloadBlast := len(impact.ByKind[graph.KindWorkload])
	credentialBlast := len(impact.ByKind[graph.KindCredential])
	cryptoBlast := len(impact.ByKind[graph.KindCryptoAsset])
	weakCrypto := weakCryptoAssetCount(impact.ByKind[graph.KindCryptoAsset])
	totalBlast := len(impact.Affected)

	reasons := []string{}
	score := base.Score
	if totalBlast >= highBlastRadiusThreshold {
		reasons = append(reasons, "high_blast_radius")
		score += 18
	} else if resourceBlast > 0 {
		reasons = append(reasons, "resource_blast_radius")
		score += 6
	}
	if weakCrypto > 0 {
		reasons = append(reasons, "weak_crypto_context")
		score += 14
	}
	if base.Privilege >= PrivilegeHigh {
		reasons = append(reasons, "privileged_credential")
		score += 8
	}
	if !base.OwnerActive {
		reasons = append(reasons, "orphaned_owner")
		score += 10
	}
	if !base.ExpiresAt.IsZero() && base.ExpiresAt.Sub(now) <= 30*24*time.Hour {
		reasons = append(reasons, "near_expiry")
		score += 10
	}
	if base.Components.Rotation >= 0.75 {
		reasons = append(reasons, "stale_rotation")
		score += 6
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "baseline_risk")
	}

	score = math.Min(100, round1(score))
	evidenceRefs := append([]string(nil), base.EvidenceRefs...)
	if len(evidenceRefs) == 0 {
		evidenceRefs = append(evidenceRefs, "credential:"+base.CredentialID)
	}
	graphNodeID := base.GraphNodeID
	if graphNodeID == "" {
		graphNodeID = "cert:" + base.CredentialID
	}
	evidenceRefs = append(evidenceRefs, "graph:blast-radius:"+graphNodeID)
	if weakCrypto > 0 && impact.Node.ID != "" {
		evidenceRefs = append(evidenceRefs, fmt.Sprintf("cbom:weak-crypto-assets:%d", weakCrypto))
	}

	return ContextualPriority{
		CredentialID:           base.CredentialID,
		Subject:                base.Subject,
		Kind:                   base.Kind,
		Severity:               contextualSeverity(score),
		ContextualScore:        score,
		BaseScore:              round1(base.Score),
		BlastRadius:            totalBlast,
		ResourceBlastRadius:    resourceBlast,
		WorkloadBlastRadius:    workloadBlast,
		CredentialBlastRadius:  credentialBlast,
		CryptoAssetBlastRadius: cryptoBlast,
		WeakCryptoContext:      weakCrypto,
		Privilege:              base.Privilege,
		Sensitivity:            base.Sensitivity,
		OwnerActive:            base.OwnerActive,
		ExpiresAt:              base.ExpiresAt,
		Components:             base.Components,
		PriorityReasons:        reasons,
		EvidenceRefs:           evidenceRefs,
		RecommendedAction:      contextualAction(score, totalBlast, weakCrypto, base.OwnerActive),
	}
}

func weakCryptoAssetCount(nodes []graph.Node) int {
	count := 0
	for _, n := range nodes {
		if n.Attrs["quantum_vulnerable"] == "true" || n.Attrs["out_of_policy"] == "true" || n.Attrs["strength"] == "weak" {
			count++
		}
	}
	return count
}

func contextualSeverity(score float64) string {
	switch {
	case score >= 85:
		return "critical"
	case score >= 70:
		return "high"
	case score >= 50:
		return "medium"
	default:
		return "low"
	}
}

func contextualAction(score float64, blastRadius, weakCrypto int, ownerActive bool) string {
	switch {
	case score >= 85 || (blastRadius >= highBlastRadiusThreshold && weakCrypto > 0):
		return "Rotate and redeploy before lower-blast-radius work; review affected resources and weak crypto assets first."
	case !ownerActive:
		return "Assign an owner, then rotate or revoke according to the credential graph blast radius."
	case blastRadius >= highBlastRadiusThreshold:
		return "Schedule priority rotation and validate every affected graph node after deployment."
	default:
		return "Track in normal rotation order and keep graph evidence attached to the work item."
	}
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

func clampScore(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 100:
		return 100
	default:
		return v
	}
}

func metadataMap(raw json.RawMessage) map[string]any {
	var out map[string]any
	if len(raw) == 0 {
		return map[string]any{}
	}
	if err := json.Unmarshal(raw, &out); err != nil || out == nil {
		return map[string]any{}
	}
	return out
}

func metadataString(meta map[string]any, key string) string {
	v, ok := meta[key]
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case fmt.Stringer:
		return strings.TrimSpace(t.String())
	default:
		return strings.TrimSpace(fmt.Sprint(t))
	}
}

func metadataStrings(meta map[string]any, keys ...string) []string {
	var out []string
	for _, key := range keys {
		v, ok := meta[key]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case []any:
			for _, item := range t {
				if s := strings.TrimSpace(fmt.Sprint(item)); s != "" {
					out = append(out, s)
				}
			}
		case []string:
			for _, item := range t {
				if s := strings.TrimSpace(item); s != "" {
					out = append(out, s)
				}
			}
		case string:
			for _, item := range strings.Split(t, ",") {
				if s := strings.TrimSpace(item); s != "" {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

func metadataTime(meta map[string]any, keys ...string) time.Time {
	for _, key := range keys {
		raw := metadataString(meta, key)
		if raw == "" {
			continue
		}
		if ts, err := time.Parse(time.RFC3339, raw); err == nil {
			return ts
		}
	}
	return time.Time{}
}

func metadataOwnerActive(meta map[string]any) bool {
	if metadataOwnerOrphaned(meta) {
		return false
	}
	for _, key := range []string{"owner_id", "owner", "owner_ref", "team", "service_owner"} {
		if metadataString(meta, key) != "" {
			return true
		}
	}
	return false
}

func metadataOwnerOrphaned(meta map[string]any) bool {
	state := strings.ToLower(firstNonEmptyRisk(metadataString(meta, "owner_status"), metadataString(meta, "ownership_status")))
	return state == "orphaned" || state == "unowned" || state == "inactive" || state == "missing"
}

func inferNHIPrivilege(kind string, meta map[string]any, exposure int) PrivilegeClass {
	for _, signal := range append([]string{metadataString(meta, "privilege"), metadataString(meta, "access_level"), metadataString(meta, "severity")}, metadataStrings(meta, "granted_scopes", "scopes", "permissions", "roles")...) {
		s := strings.ToLower(signal)
		switch {
		case strings.Contains(s, "root"), strings.Contains(s, "admin"), strings.Contains(s, "owner"), strings.Contains(s, "*"):
			return PrivilegeCritical
		case strings.Contains(s, "write"), strings.Contains(s, "deploy"), strings.Contains(s, "workflow"), strings.Contains(s, "privileged"):
			return PrivilegeHigh
		case strings.Contains(s, "read"), strings.Contains(s, "viewer"):
			return PrivilegeStandard
		}
	}
	switch {
	case exposure >= 8:
		return PrivilegeHigh
	case exposure >= 2:
		return PrivilegeStandard
	}
	switch normalizeCredentialKind(kind) {
	case "api_key", "token", "personal_access_token", "oauth_app", "service_account", "iam_role", "secret", "workload_identity":
		return PrivilegeStandard
	default:
		return PrivilegeLow
	}
}

func inferNHISensitivity(kind string, meta map[string]any) Sensitivity {
	switch strings.ToLower(metadataString(meta, "sensitivity")) {
	case "restricted", "confidential", "critical", "high":
		return SensitivityHigh
	case "internal", "medium":
		return SensitivityMedium
	case "public", "low":
		return SensitivityLow
	}
	switch normalizeCredentialKind(kind) {
	case "secret", "api_key", "token", "personal_access_token", "oauth_app":
		return SensitivityHigh
	case "service_account", "iam_role", "workload_identity", "ssh_key":
		return SensitivityMedium
	default:
		return SensitivityLow
	}
}

func discoveryCredentialKind(kind string, meta map[string]any) string {
	if strings.TrimSpace(kind) == "non_human_identity" {
		return normalizeCredentialKind(metadataString(meta, "credential_kind"))
	}
	if metaKind := metadataString(meta, "credential_kind"); metaKind != "" {
		return normalizeCredentialKind(metaKind)
	}
	switch normalizeCredentialKind(kind) {
	case "cloud_secret", "secret_store":
		return "secret"
	case "cloud_certificate", "ct_log":
		return "certificate"
	case "oauth_grant":
		return "oauth_app"
	default:
		return normalizeCredentialKind(kind)
	}
}

func normalizeCredentialKind(raw string) string {
	k := strings.ToLower(strings.TrimSpace(raw))
	k = strings.ReplaceAll(k, "-", "_")
	switch k {
	case "", "unknown":
		return "credential"
	case "x509", "x509_certificate", "tls_certificate", "certificate":
		return "certificate"
	case "ssh_certificate", "ssh_key":
		return "ssh_key"
	case "pat", "personal_access_token":
		return "personal_access_token"
	default:
		return k
	}
}

func firstNonEmptyRisk(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// SortByContextualPriority orders priorities by contextual score descending,
// then by blast radius and credential id for deterministic API responses.
func SortByContextualPriority(ps []ContextualPriority) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].ContextualScore != ps[j].ContextualScore {
			return ps[i].ContextualScore > ps[j].ContextualScore
		}
		if ps[i].BlastRadius != ps[j].BlastRadius {
			return ps[i].BlastRadius > ps[j].BlastRadius
		}
		return ps[i].CredentialID < ps[j].CredentialID
	})
}
