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

const maxNHIInventoryRowsPerSource = 10000

var nhiInventoryCoverage = []string{
	"certificate",
	"ssh_key",
	"secret",
	"api_key",
	"oauth_app",
	"token",
	"personal_access_token",
	"service_account",
	"iam_role",
	"webhook",
	"workload_identity",
	"agent",
}

type nhiInventoryResponse struct {
	GeneratedAt time.Time          `json:"generated_at"`
	Items       []nhiInventoryItem `json:"items"`
	Summary     map[string]int     `json:"summary"`
	Coverage    []string           `json:"coverage"`
}

type nhiInventoryItem struct {
	ID           string          `json:"id"`
	TenantID     string          `json:"tenant_id"`
	Kind         string          `json:"kind"`
	Source       string          `json:"source"`
	DisplayName  string          `json:"display_name"`
	OwnerID      string          `json:"owner_id,omitempty"`
	Status       string          `json:"status"`
	Ref          string          `json:"ref,omitempty"`
	Provenance   string          `json:"provenance,omitempty"`
	Fingerprint  string          `json:"fingerprint,omitempty"`
	RiskScore    int             `json:"risk_score,omitempty"`
	Metadata     json.RawMessage `json:"metadata"`
	NotBefore    *time.Time      `json:"not_before,omitempty"`
	NotAfter     *time.Time      `json:"not_after,omitempty"`
	DiscoveredAt *time.Time      `json:"discovered_at,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
}

func (a *API) listNHIInventory(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	out, err := a.nhiInventory(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, out)
}

func (a *API) nhiInventory(ctx context.Context, tenantID string) (nhiInventoryResponse, error) {
	out := nhiInventoryResponse{
		GeneratedAt: time.Now().UTC(),
		Summary:     map[string]int{},
		Coverage:    append([]string(nil), nhiInventoryCoverage...),
	}
	add := func(item nhiInventoryItem) {
		item.Kind = normalizeNHIInventoryKind(item.Kind)
		item.DisplayName = strings.TrimSpace(item.DisplayName)
		if item.DisplayName == "" {
			item.DisplayName = item.Ref
		}
		if item.DisplayName == "" {
			item.DisplayName = item.ID
		}
		if len(item.Metadata) == 0 {
			item.Metadata = json.RawMessage(`{}`)
		}
		out.Items = append(out.Items, item)
		out.Summary[item.Kind]++
	}

	identities, err := a.store.ListIdentities(ctx, tenantID)
	if err != nil {
		return out, err
	}
	for _, identity := range identities {
		add(nhiInventoryItem{
			ID:          "identity/" + identity.ID,
			TenantID:    identity.TenantID,
			Kind:        identityKindToNHIKind(identity.Kind),
			Source:      "identity",
			DisplayName: identity.Name,
			OwnerID:     identity.OwnerID,
			Status:      identity.Status,
			Ref:         identity.ID,
			Metadata:    sanitizeNHIInventoryMetadata(identity.Attributes),
			NotBefore:   identity.NotBefore,
			NotAfter:    identity.NotAfter,
			CreatedAt:   identity.CreatedAt,
		})
	}

	certificates, err := a.store.ListCertificatesPage(ctx, tenantID, store.ZeroUUID, nil, maxNHIInventoryRowsPerSource, nil)
	if err != nil {
		return out, err
	}
	for _, cert := range certificates {
		ownerID := ""
		if cert.OwnerID != nil {
			ownerID = *cert.OwnerID
		}
		add(nhiInventoryItem{
			ID:          "certificate/" + cert.ID,
			TenantID:    cert.TenantID,
			Kind:        "certificate",
			Source:      "certificate_inventory",
			DisplayName: firstNonEmpty(cert.Subject, cert.Fingerprint),
			OwnerID:     ownerID,
			Status:      cert.Status,
			Ref:         cert.ID,
			Fingerprint: cert.Fingerprint,
			Metadata: marshalNHIInventoryMetadata(map[string]any{
				"sans":                cert.SANs,
				"issuer":              cert.Issuer,
				"serial":              cert.Serial,
				"key_algorithm":       cert.KeyAlgorithm,
				"deployment_location": cert.DeploymentLocation,
				"inventory_source":    cert.Source,
			}),
			NotBefore: cert.NotBefore,
			NotAfter:  cert.NotAfter,
			CreatedAt: cert.CreatedAt,
		})
	}

	apiTokens, err := a.store.ListAPITokensPage(ctx, tenantID, store.ZeroUUID, "", true, maxNHIInventoryRowsPerSource)
	if err != nil {
		return out, err
	}
	for _, token := range apiTokens {
		status := "active"
		if token.RevokedAt != nil {
			status = "revoked"
		}
		add(nhiInventoryItem{
			ID:          "api-token/" + token.ID,
			TenantID:    token.TenantID,
			Kind:        "token",
			Source:      "access_api_token",
			DisplayName: token.Subject,
			Status:      status,
			Ref:         token.ID,
			Metadata: marshalNHIInventoryMetadata(map[string]any{
				"token_type": "trstctl_api_token",
				"scopes":     token.Scopes,
				"expires_at": token.ExpiresAt,
			}),
			CreatedAt: token.CreatedAt,
		})
	}

	agents, err := a.store.ListAgentsPage(ctx, tenantID, nil, store.ZeroUUID, maxNHIInventoryRowsPerSource)
	if err != nil {
		return out, err
	}
	for _, agent := range agents {
		add(nhiInventoryItem{
			ID:          "agent/" + agent.ID,
			TenantID:    agent.TenantID,
			Kind:        "agent",
			Source:      "agent_fleet",
			DisplayName: agent.Name,
			Status:      agent.Status,
			Ref:         agent.ID,
			Metadata: marshalNHIInventoryMetadata(map[string]any{
				"version":      agent.Version,
				"last_seen_at": agent.LastSeenAt,
			}),
			CreatedAt: agent.CreatedAt,
		})
	}

	findings, err := a.store.ListDiscoveryFindingsPage(ctx, tenantID, "", store.ZeroUUID, maxNHIInventoryRowsPerSource)
	if err != nil {
		return out, err
	}
	for _, finding := range findings {
		meta := decodeNHIInventoryMetadata(finding.Metadata)
		add(nhiInventoryItem{
			ID:           "finding/" + finding.ID,
			TenantID:     finding.TenantID,
			Kind:         discoveryFindingToNHIKind(finding.Kind, meta),
			Source:       "discovery_finding",
			DisplayName:  firstNonEmpty(metadataString(meta, "display_name"), metadataString(meta, "principal"), finding.Ref),
			Status:       finding.TriageStatus,
			Ref:          finding.Ref,
			Provenance:   finding.Provenance,
			Fingerprint:  finding.Fingerprint,
			RiskScore:    finding.RiskScore,
			Metadata:     sanitizeNHIInventoryMetadata(finding.Metadata),
			DiscoveredAt: &finding.DiscoveredAt,
			CreatedAt:    finding.DiscoveredAt,
		})
	}

	sort.Slice(out.Items, func(i, j int) bool {
		a, b := out.Items[i], out.Items[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.DisplayName != b.DisplayName {
			return a.DisplayName < b.DisplayName
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.ID < b.ID
	})
	return out, nil
}

func identityKindToNHIKind(kind store.IdentityKind) string {
	switch kind {
	case store.KindX509Certificate:
		return "certificate"
	case store.KindSSHCertificate, store.KindSSHKey:
		return "ssh_key"
	case store.KindSecret:
		return "secret"
	case store.KindAPIKey:
		return "api_key"
	case store.KindWorkloadIdentity:
		return "workload_identity"
	default:
		return string(kind)
	}
}

func discoveryFindingToNHIKind(kind string, metadata map[string]any) string {
	if strings.TrimSpace(kind) == "non_human_identity" {
		return normalizeNHIInventoryKind(metadataString(metadata, "credential_kind"))
	}
	switch normalizeNHIInventoryKind(kind) {
	case "oauth_grant":
		return "oauth_app"
	case "cloud_secret", "secret_store":
		return "secret"
	case "cloud_certificate", "ct_log":
		return "certificate"
	default:
		return normalizeNHIInventoryKind(kind)
	}
}

func normalizeNHIInventoryKind(raw string) string {
	kind := strings.ToLower(strings.TrimSpace(raw))
	kind = strings.ReplaceAll(kind, "-", "_")
	kind = strings.ReplaceAll(kind, " ", "_")
	switch kind {
	case "", "non_human_identity":
		return "unknown"
	case "cert", "x509", "x509_cert", "x509_certificate", "tls_certificate", "certificate", "cloud_certificate", "ct_log":
		return "certificate"
	case "ssh", "ssh_key", "deploy_key", "private_key", "public_key", "ssh_certificate":
		return "ssh_key"
	case "service_account", "svc_account", "machine_user", "service_principal":
		return "service_account"
	case "oauth", "oauth_app", "oauth_client", "oidc_client", "github_app", "oauth_grant":
		return "oauth_app"
	case "iam_role", "role", "aws_role", "gcp_role", "azure_role":
		return "iam_role"
	case "api_key", "access_key", "access_key_id":
		return "api_key"
	case "pat", "personal_access_token", "token", "bearer_token", "refresh_token", "session_token", "workflow_token":
		return "token"
	case "secret", "cloud_secret", "secret_store", "shared_secret", "client_secret":
		return "secret"
	case "webhook", "webhook_secret":
		return "webhook"
	case "workload_identity", "workflow_identity", "spiffe_id", "svid", "oidc_workload_identity":
		return "workload_identity"
	default:
		return kind
	}
}

func decodeNHIInventoryMetadata(raw json.RawMessage) map[string]any {
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil || out == nil {
		return map[string]any{}
	}
	return out
}

func sanitizeNHIInventoryMetadata(raw json.RawMessage) json.RawMessage {
	meta := decodeNHIInventoryMetadata(raw)
	removeNHIInventorySecrets(meta)
	return marshalNHIInventoryMetadata(meta)
}

func removeNHIInventorySecrets(v any) {
	switch x := v.(type) {
	case map[string]any:
		for key, value := range x {
			if inlineSecretKey(key) {
				delete(x, key)
				continue
			}
			removeNHIInventorySecrets(value)
		}
	case []any:
		for _, value := range x {
			removeNHIInventorySecrets(value)
		}
	}
}

func marshalNHIInventoryMetadata(v map[string]any) json.RawMessage {
	if v == nil {
		return json.RawMessage(`{}`)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return json.RawMessage(b)
}

func metadataString(meta map[string]any, key string) string {
	if value, ok := meta[key].(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
