// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secretscan"
	"trstctl.com/trstctl/internal/secretsync"
	"trstctl.com/trstctl/internal/store"
)

type unvaultedSecretSummaryResponse struct {
	RepositorySources       int `json:"repository_sources"`
	ThirdPartySources       int `json:"third_party_sources"`
	CloudSecretSources      int `json:"cloud_secret_sources"`
	VaultProvidersSupported int `json:"vault_providers_supported"`
	VaultProvidersVisible   int `json:"vault_providers_visible"`
	SyncTargetsConfigured   int `json:"sync_targets_configured"`
	LeakedSecretFindings    int `json:"leaked_secret_findings"`
}

type unvaultedSecretDetectionSourceResponse struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	SourceKind      string   `json:"source_kind"`
	ConfiguredCount int      `json:"configured_count"`
	DetectionMode   string   `json:"detection_mode"`
	SecretHandling  string   `json:"secret_handling"`
	FindingsKind    string   `json:"findings_kind"`
	Capabilities    []string `json:"capabilities"`
	EvidenceRefs    []string `json:"evidence_refs"`
}

type unvaultedSecretVaultProviderResponse struct {
	ID                   string   `json:"id"`
	Name                 string   `json:"name"`
	DiscoveryConfigured  bool     `json:"discovery_configured"`
	DiscoverySourceCount int      `json:"discovery_source_count"`
	SyncSupported        bool     `json:"sync_supported"`
	SyncConfigured       bool     `json:"sync_configured"`
	AugmentationMode     string   `json:"augmentation_mode"`
	Capabilities         []string `json:"capabilities"`
	EvidenceRefs         []string `json:"evidence_refs"`
}

type unvaultedSecretPostureResponse struct {
	Capability             string                                   `json:"capability"`
	Served                 bool                                     `json:"served"`
	GeneratedAt            string                                   `json:"generated_at"`
	Summary                unvaultedSecretSummaryResponse           `json:"summary"`
	DetectionSources       []unvaultedSecretDetectionSourceResponse `json:"detection_sources"`
	VaultProviders         []unvaultedSecretVaultProviderResponse   `json:"vault_providers"`
	ConfiguredVaults       []string                                 `json:"configured_vaults"`
	ConfiguredSyncTargets  []string                                 `json:"configured_sync_targets"`
	Workflow               []string                                 `json:"workflow"`
	SecretHandling         string                                   `json:"secret_handling"`
	ArchitectureControls   []string                                 `json:"architecture_controls"`
	EvidenceRefs           []string                                 `json:"evidence_refs"`
	Residuals              []string                                 `json:"residuals"`
	RecommendedNextActions []string                                 `json:"recommended_next_actions"`
}

type secretSyncRequest struct {
	Name      string `json:"name"`
	Target    string `json:"target"`
	RemoteKey string `json:"remote_key"`
}

type secretSyncResponse struct {
	Name      string `json:"name"`
	Target    string `json:"target"`
	RemoteKey string `json:"remote_key"`
	Enqueued  bool   `json:"enqueued"`
	Delivered bool   `json:"delivered"`
}

type secretSyncTargetResponse struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Platform       string   `json:"platform"`
	Configured     bool     `json:"configured"`
	DeliveryMode   string   `json:"delivery_mode"`
	AuthMode       string   `json:"auth_mode"`
	WireFormat     string   `json:"wire_format"`
	SecretHandling string   `json:"secret_handling"`
	Capabilities   []string `json:"capabilities"`
}

type secretSyncTargetCatalogResponse struct {
	Capability        string                     `json:"capability"`
	Served            bool                       `json:"served"`
	GeneratedAt       string                     `json:"generated_at"`
	Targets           []secretSyncTargetResponse `json:"targets"`
	ConfiguredTargets []string                   `json:"configured_targets"`
	OutboxMode        string                     `json:"outbox_mode"`
	EvidenceRefs      []string                   `json:"evidence_refs"`
	Residuals         []string                   `json:"residuals"`
}

const secretSyncTargetSecretHandling = "sealed outbox value is unsealed only for the delivery attempt; response and audit contain metadata only"

type cloudSecretManagerProviderResponse struct {
	ID                   string   `json:"id"`
	Name                 string   `json:"name"`
	Platform             string   `json:"platform"`
	DiscoverySupported   bool     `json:"discovery_supported"`
	DiscoveryConfigured  bool     `json:"discovery_configured"`
	DiscoverySourceKind  string   `json:"discovery_source_kind,omitempty"`
	DiscoverySourceCount int      `json:"discovery_source_count"`
	DiscoveryReadOps     []string `json:"discovery_read_ops"`
	SyncSupported        bool     `json:"sync_supported"`
	SyncConfigured       bool     `json:"sync_configured"`
	SyncTargetID         string   `json:"sync_target_id,omitempty"`
	SyncWriteOperation   string   `json:"sync_write_operation,omitempty"`
	SecretHandling       string   `json:"secret_handling"`
	Capabilities         []string `json:"capabilities"`
	EvidenceRefs         []string `json:"evidence_refs"`
}

type cloudSecretManagerSummaryResponse struct {
	TotalProviders        int `json:"total_providers"`
	DiscoverySupported    int `json:"discovery_supported"`
	DiscoveryConfigured   int `json:"discovery_configured"`
	SyncSupported         int `json:"sync_supported"`
	SyncConfigured        int `json:"sync_configured"`
	FullyConfigured       int `json:"fully_configured"`
	ConfiguredConnections int `json:"configured_connections"`
}

type cloudSecretManagerIntegrationResponse struct {
	Capability             string                               `json:"capability"`
	Served                 bool                                 `json:"served"`
	GeneratedAt            string                               `json:"generated_at"`
	Summary                cloudSecretManagerSummaryResponse    `json:"summary"`
	Providers              []cloudSecretManagerProviderResponse `json:"providers"`
	ConfiguredProviders    []string                             `json:"configured_providers"`
	ConfiguredSyncTargets  []string                             `json:"configured_sync_targets"`
	DiscoveryMode          string                               `json:"discovery_mode"`
	OutboxMode             string                               `json:"outbox_mode"`
	SecretHandling         string                               `json:"secret_handling"`
	ArchitectureControls   []string                             `json:"architecture_controls"`
	EvidenceRefs           []string                             `json:"evidence_refs"`
	Residuals              []string                             `json:"residuals"`
	RecommendedNextActions []string                             `json:"recommended_next_actions"`
}

type kubernetesSecretOperatorCRDResponse struct {
	Kind        string   `json:"kind"`
	APIGroup    string   `json:"api_group"`
	APIVersion  string   `json:"api_version"`
	Plural      string   `json:"plural"`
	Status      string   `json:"status"`
	Owns        []string `json:"owns"`
	EvidenceRef string   `json:"evidence_ref"`
}

type kubernetesSecretOperatorResponse struct {
	Capability             string                                `json:"capability"`
	Served                 bool                                  `json:"served"`
	GeneratedAt            string                                `json:"generated_at"`
	CRDs                   []kubernetesSecretOperatorCRDResponse `json:"crds"`
	SyncFlow               []string                              `json:"sync_flow"`
	ReloadWorkloads        []string                              `json:"reload_workloads"`
	SecretHandling         string                                `json:"secret_handling"`
	ArchitectureControls   []string                              `json:"architecture_controls"`
	EvidenceRefs           []string                              `json:"evidence_refs"`
	Residuals              []string                              `json:"residuals"`
	RecommendedNextActions []string                              `json:"recommended_next_actions"`
}

type secretWorkloadInjectionCRDResponse struct {
	Kind        string   `json:"kind"`
	APIGroup    string   `json:"api_group"`
	APIVersion  string   `json:"api_version"`
	Plural      string   `json:"plural"`
	Status      string   `json:"status"`
	Owns        []string `json:"owns"`
	EvidenceRef string   `json:"evidence_ref"`
}

type secretWorkloadInjectionModeResponse struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	DeliveredBy    string   `json:"delivered_by"`
	WorkloadChange string   `json:"workload_change"`
	SecretHandling string   `json:"secret_handling"`
	Capabilities   []string `json:"capabilities"`
}

type secretWorkloadInjectionResponse struct {
	Capability             string                                `json:"capability"`
	Served                 bool                                  `json:"served"`
	GeneratedAt            string                                `json:"generated_at"`
	CRD                    secretWorkloadInjectionCRDResponse    `json:"crd"`
	Modes                  []secretWorkloadInjectionModeResponse `json:"modes"`
	WorkloadKinds          []string                              `json:"workload_kinds"`
	SidecarCommand         []string                              `json:"sidecar_command"`
	Annotations            []string                              `json:"annotations"`
	SyncDependency         string                                `json:"sync_dependency"`
	SecretHandling         string                                `json:"secret_handling"`
	ArchitectureControls   []string                              `json:"architecture_controls"`
	EvidenceRefs           []string                              `json:"evidence_refs"`
	Residuals              []string                              `json:"residuals"`
	RecommendedNextActions []string                              `json:"recommended_next_actions"`
}

// syncSecret pushes a stored secret to a configured external target. The secret value
// is read internally, enqueued through the sync outbox first (AN-6), delivered by the
// pusher, and wiped before the metadata-only response is returned.
//
//trstctl:mutation
func (a *API) syncSecret(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	var req secretSyncRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Target = strings.TrimSpace(req.Target)
	req.RemoteKey = strings.TrimSpace(req.RemoteKey)
	if req.Name == "" || req.Target == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "name and target are required"))
		return
	}
	if req.RemoteKey == "" {
		req.RemoteKey = req.Name
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding, err := secretSyncRequestBinding(principal, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.secrets.be.QueueSecretSync != nil {
			existing, lookupErr := a.secrets.be.Store.GetSecretSyncJob(ctx, tenantID, store.DurableSecretSyncJobID(tenantID, idempotencyKey))
			switch {
			case lookupErr == nil:
				if existing.SecretName != req.Name || existing.Target != req.Target || existing.RemoteKey != req.RemoteKey || !crypto.ConstantTimeEqual([]byte(existing.RequestBinding), []byte(binding)) {
					return 0, nil, errStatus(http.StatusConflict, "Idempotency-Key was already used for a different secret sync command")
				}
				// The production command returns after durable enqueue. Preserve that
				// exact public result even if the source has since rotated or the
				// background worker has since delivered the original version.
				return http.StatusOK, secretSyncResponse{
					Name: existing.SecretName, Target: existing.Target, RemoteKey: existing.RemoteKey,
					Enqueued: true, Delivered: false,
				}, nil
			case !store.IsNotFound(lookupErr):
				return 0, nil, lookupErr
			}
		}
		target := a.secrets.syncTargets(tenantID)[req.Target]
		if target == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "secret sync target is not configured")
		}
		if a.secrets.be.QueueSecretSync == nil && a.secrets.be.SecretSyncOutbox == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "secret sync outbox is not configured")
		}
		rec, err := a.secrets.be.Store.GetSecret(ctx, tenantID, req.Name)
		if err != nil {
			if errors.Is(err, store.ErrSecretNotFound) {
				return 0, nil, errStatus(http.StatusNotFound, "no such secret")
			}
			return 0, nil, err
		}
		value, err := a.secrets.open(ctx, tenantID, rec.Sealed, sealAAD(tenantID, req.Name))
		if err != nil {
			return 0, nil, err
		}
		defer secret.Wipe(value)
		delivered := 0
		if a.secrets.be.QueueSecretSync != nil {
			if err := a.secrets.be.QueueSecretSync(ctx, tenantID, req.Name, rec.Version, req.Target, req.RemoteKey, idempotencyKey, binding, value); err != nil {
				if errors.Is(err, store.ErrIdempotencyConflict) {
					return 0, nil, errStatus(http.StatusConflict, "Idempotency-Key was already used for a different secret sync command")
				}
				return 0, nil, err
			}
		} else {
			outbox := a.secrets.be.SecretSyncOutbox(tenantID, req.Target)
			engine := secretsync.New(tenantID, target, outbox, a.secrets.be.Audit)
			if err := engine.Sync(ctx, req.RemoteKey, value); err != nil {
				return 0, nil, err
			}
			var err error
			delivered, err = engine.RunDeliveries(ctx)
			if err != nil {
				return 0, nil, err
			}
		}
		a.auditSecret(ctx, "secret.sync.requested", tenantID, req.Name, rec.Version)
		return http.StatusOK, secretSyncResponse{
			Name: req.Name, Target: req.Target, RemoteKey: req.RemoteKey,
			Enqueued: true, Delivered: delivered > 0,
		}, nil
	})
}

func secretSyncRequestBinding(principal string, req secretSyncRequest) (string, error) {
	canonical := struct {
		Operation string `json:"operation"`
		Principal string `json:"principal"`
		Name      string `json:"name"`
		Target    string `json:"target"`
		RemoteKey string `json:"remote_key"`
	}{Operation: "secret.sync", Principal: principal, Name: req.Name, Target: req.Target, RemoteKey: req.RemoteKey}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(encoded)
	return crypto.SHA256Hex(encoded), nil
}

func (a *API) secretSyncTargets(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	configured := map[string]bool{}
	if a.secrets != nil {
		for target := range a.secrets.syncTargets(tenantID) {
			configured[target] = true
		}
	}
	a.writeJSON(w, http.StatusOK, buildSecretSyncTargetCatalog(time.Now().UTC().Format(time.RFC3339), configured))
}

func (a *API) cloudSecretManagers(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	discoveryCounts, err := a.cloudSecretDiscoveryProviderCounts(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	configuredSync := map[string]bool{}
	if a.secrets != nil {
		for target := range a.secrets.syncTargets(tenantID) {
			configuredSync[target] = true
		}
	}
	a.writeJSON(w, http.StatusOK, buildCloudSecretManagerIntegration(time.Now().UTC().Format(time.RFC3339), discoveryCounts, configuredSync))
}

func (a *API) unvaultedSecrets(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	sources, err := a.secretVisibilitySourceCounts(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	discoveryCounts, err := a.cloudSecretDiscoveryProviderCounts(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	leakedFindings, err := a.discoveryFindingKindCount(r.Context(), tenantID, "leaked_secret")
	if err != nil {
		a.writeError(w, err)
		return
	}
	configuredSync := map[string]bool{}
	if a.secrets != nil {
		for target := range a.secrets.syncTargets(tenantID) {
			configuredSync[target] = true
		}
	}
	a.writeJSON(w, http.StatusOK, buildUnvaultedSecretPosture(time.Now().UTC().Format(time.RFC3339), sources, discoveryCounts, configuredSync, leakedFindings))
}

func (a *API) secretVisibilitySourceCounts(ctx context.Context, tenantID string) (secretVisibilitySourceCounts, error) {
	var counts secretVisibilitySourceCounts
	after := store.ZeroUUID
	const limit = 500
	for {
		rows, err := a.store.ListDiscoverySourcesPage(ctx, tenantID, after, limit)
		if err != nil {
			return counts, err
		}
		for _, src := range rows {
			switch src.Kind {
			case secretscan.RepositorySourceKind:
				counts.Repository++
			case secretscan.ThirdPartySourceKind:
				counts.ThirdParty++
			case "cloud_secret":
				counts.Cloud++
			}
		}
		if len(rows) < limit {
			break
		}
		after = rows[len(rows)-1].ID
	}
	return counts, nil
}

func (a *API) discoveryFindingKindCount(ctx context.Context, tenantID, kind string) (int, error) {
	after := store.ZeroUUID
	count := 0
	const limit = 500
	for {
		rows, err := a.store.ListDiscoveryFindingsPage(ctx, tenantID, "", after, limit)
		if err != nil {
			return 0, err
		}
		for _, f := range rows {
			if f.Kind == kind {
				count++
			}
		}
		if len(rows) < limit {
			break
		}
		after = rows[len(rows)-1].ID
	}
	return count, nil
}

func (a *API) cloudSecretDiscoveryProviderCounts(ctx context.Context, tenantID string) (map[string]int, error) {
	counts := map[string]int{}
	after := store.ZeroUUID
	const limit = 500
	for {
		rows, err := a.store.ListDiscoverySourcesPage(ctx, tenantID, after, limit)
		if err != nil {
			return nil, err
		}
		for _, src := range rows {
			if src.Kind != "cloud_secret" {
				continue
			}
			var cfg struct {
				Providers []struct {
					Provider string `json:"provider"`
				} `json:"providers"`
			}
			if err := json.Unmarshal(src.Config, &cfg); err != nil {
				continue
			}
			seenInSource := map[string]bool{}
			for _, p := range cfg.Providers {
				id := normalizeCloudSecretManagerProvider(p.Provider)
				if id == "" {
					continue
				}
				seenInSource[id] = true
			}
			for id := range seenInSource {
				counts[id]++
			}
		}
		if len(rows) < limit {
			break
		}
		after = rows[len(rows)-1].ID
	}
	return counts, nil
}

func normalizeCloudSecretManagerProvider(provider string) string {
	switch strings.TrimSpace(strings.ToLower(provider)) {
	case "aws-secrets-manager", "aws-sm", "aws":
		return "aws-secrets-manager"
	case "gcp-secret-manager", "gcp-sm", "gcp":
		return "gcp-secret-manager"
	case "azure-key-vault", "azure-kv", "azure":
		return "azure-key-vault"
	case "hashicorp-vault", "vault":
		return "hashicorp-vault"
	default:
		return ""
	}
}

func buildSecretSyncTargetCatalog(generatedAt string, configured map[string]bool) secretSyncTargetCatalogResponse {
	if generatedAt == "" {
		generatedAt = "1970-01-01T00:00:00Z"
	}
	entries := secretsync.ProviderCatalog()
	targets := make([]secretSyncTargetResponse, 0, len(entries))
	configuredTargets := make([]string, 0, len(configured))
	for target := range configured {
		configuredTargets = append(configuredTargets, target)
	}
	sort.Strings(configuredTargets)
	for _, entry := range entries {
		targets = append(targets, secretSyncTargetResponse{
			ID:             entry.ID,
			Name:           entry.Name,
			Platform:       entry.Platform,
			Configured:     configured[entry.ID],
			DeliveryMode:   entry.DeliveryMode,
			AuthMode:       entry.AuthMode,
			WireFormat:     entry.WireFormat,
			SecretHandling: secretSyncTargetSecretHandling,
			Capabilities:   append([]string(nil), entry.Capabilities...),
		})
	}
	return secretSyncTargetCatalogResponse{
		Capability:        "CAP-SECR-03",
		Served:            true,
		GeneratedAt:       generatedAt,
		Targets:           targets,
		ConfiguredTargets: configuredTargets,
		OutboxMode:        "all target writes are queued in the sealed PostgreSQL outbox before delivery",
		EvidenceRefs: []string{
			"internal/secretsync/secretsync.go",
			"internal/secretsync/pushers.go",
			"internal/api/secrets.go",
			"internal/server/secrets_sync_served_test.go",
		},
		Residuals: []string{
			"operator must configure endpoint credentials for each active target",
			"large rollout orchestration and rollback receipts are separate remediation tracks",
		},
	}
}

type cloudSecretManagerProviderSpec struct {
	ID                 string
	Name               string
	Platform           string
	DiscoverySupported bool
	DiscoveryReadOps   []string
	SyncSupported      bool
	SyncTargetID       string
	SyncWriteOperation string
	Capabilities       []string
	EvidenceRefs       []string
}

func cloudSecretManagerProviderSpecs() []cloudSecretManagerProviderSpec {
	return []cloudSecretManagerProviderSpec{
		{
			ID:                 "aws-secrets-manager",
			Name:               "AWS Secrets Manager",
			Platform:           "aws",
			DiscoverySupported: true,
			DiscoveryReadOps:   []string{"secretsmanager.ListSecrets", "secretsmanager.GetSecretValue"},
			SyncSupported:      true,
			SyncTargetID:       "aws-secrets-manager",
			SyncWriteOperation: "secretsmanager.PutSecretValue",
			Capabilities:       []string{"cloud-secret-manager", "metadata-only-discovery", "sealed-outbox-sync", "sigv4", "binary-secret"},
			EvidenceRefs:       []string{"internal/discovery/cloudsecret/awssm/awssm.go", "internal/secretsync/pushers.go"},
		},
		{
			ID:                 "gcp-secret-manager",
			Name:               "GCP Secret Manager",
			Platform:           "gcp",
			DiscoverySupported: true,
			DiscoveryReadOps:   []string{"GET projects.secrets.list", "GET versions/latest:access"},
			SyncSupported:      true,
			SyncTargetID:       "gcp-secret-manager",
			SyncWriteOperation: "projects.secrets.addVersion",
			Capabilities:       []string{"cloud-secret-manager", "metadata-only-discovery", "sealed-outbox-sync", "versioned-secret"},
			EvidenceRefs:       []string{"internal/discovery/cloudsecret/gcpsm/gcpsm.go", "internal/secretsync/pushers.go"},
		},
		{
			ID:                 "azure-key-vault",
			Name:               "Azure Key Vault",
			Platform:           "azure",
			DiscoverySupported: true,
			DiscoveryReadOps:   []string{"GET /secrets", "GET /secrets/{name}"},
			SyncSupported:      true,
			SyncTargetID:       "azure-key-vault",
			SyncWriteOperation: "PUT /secrets/{name}",
			Capabilities:       []string{"cloud-secret-manager", "metadata-only-discovery", "sealed-outbox-sync", "versioned-secret"},
			EvidenceRefs:       []string{"internal/discovery/cloudsecret/azurekv/azurekv.go", "internal/secretsync/pushers.go"},
		},
		{
			ID:                 "hashicorp-vault",
			Name:               "HashiCorp Vault KV",
			Platform:           "vault",
			DiscoverySupported: true,
			DiscoveryReadOps:   []string{"LIST /v1/{mount}/metadata", "GET /v1/{mount}/data"},
			SyncSupported:      false,
			Capabilities:       []string{"cloud-secret-manager", "metadata-only-discovery", "vault-kv-v2"},
			EvidenceRefs:       []string{"internal/discovery/cloudsecret/vaultkv/vaultkv.go"},
		},
	}
}

func buildCloudSecretManagerIntegration(generatedAt string, discoveryCounts map[string]int, configuredSync map[string]bool) cloudSecretManagerIntegrationResponse {
	if generatedAt == "" {
		generatedAt = "1970-01-01T00:00:00Z"
	}
	specs := cloudSecretManagerProviderSpecs()
	providers := make([]cloudSecretManagerProviderResponse, 0, len(specs))
	configuredProviders := make([]string, 0, len(specs))
	configuredSyncTargets := make([]string, 0, len(configuredSync))
	summary := cloudSecretManagerSummaryResponse{TotalProviders: len(specs)}
	for target := range configuredSync {
		if target != "" {
			configuredSyncTargets = append(configuredSyncTargets, target)
		}
	}
	sort.Strings(configuredSyncTargets)
	for _, spec := range specs {
		discoveryCount := discoveryCounts[spec.ID]
		discoveryConfigured := discoveryCount > 0
		syncConfigured := spec.SyncTargetID != "" && configuredSync[spec.SyncTargetID]
		if spec.DiscoverySupported {
			summary.DiscoverySupported++
		}
		if discoveryConfigured {
			summary.DiscoveryConfigured++
			configuredProviders = append(configuredProviders, spec.ID)
		}
		if spec.SyncSupported {
			summary.SyncSupported++
		}
		if syncConfigured {
			summary.SyncConfigured++
		}
		if discoveryConfigured && (!spec.SyncSupported || syncConfigured) {
			summary.FullyConfigured++
		}
		providers = append(providers, cloudSecretManagerProviderResponse{
			ID:                   spec.ID,
			Name:                 spec.Name,
			Platform:             spec.Platform,
			DiscoverySupported:   spec.DiscoverySupported,
			DiscoveryConfigured:  discoveryConfigured,
			DiscoverySourceKind:  "cloud_secret",
			DiscoverySourceCount: discoveryCount,
			DiscoveryReadOps:     append([]string(nil), spec.DiscoveryReadOps...),
			SyncSupported:        spec.SyncSupported,
			SyncConfigured:       syncConfigured,
			SyncTargetID:         spec.SyncTargetID,
			SyncWriteOperation:   spec.SyncWriteOperation,
			SecretHandling:       "secret values are read into []byte for certificate inspection or delivery only, then wiped; responses expose metadata only",
			Capabilities:         append([]string(nil), spec.Capabilities...),
			EvidenceRefs:         append([]string(nil), spec.EvidenceRefs...),
		})
	}
	sort.Strings(configuredProviders)
	summary.ConfiguredConnections = summary.DiscoveryConfigured + summary.SyncConfigured
	return cloudSecretManagerIntegrationResponse{
		Capability:            "CAP-SEC-04",
		Served:                true,
		GeneratedAt:           generatedAt,
		Summary:               summary,
		Providers:             providers,
		ConfiguredProviders:   configuredProviders,
		ConfiguredSyncTargets: configuredSyncTargets,
		DiscoveryMode:         "tenant-scoped cloud_secret sources run through the discovery outbox and call provider read APIs only",
		OutboxMode:            "sync writes are enqueued through the sealed PostgreSQL outbox before provider delivery",
		SecretHandling:        "cloud manager values never appear in API responses, audit events, or UI state; delivery and inspection use []byte and wipe buffers",
		ArchitectureControls:  []string{"AN-1 tenant-scoped source and secret rows", "AN-2 discovery/sync events", "AN-5 sync idempotency", "AN-6 outbox delivery", "AN-8 byte-backed secret handling"},
		EvidenceRefs: []string{
			"internal/api/secrets.go",
			"internal/server/discovery.go",
			"internal/discovery/cloudsecret/awssm/awssm.go",
			"internal/discovery/cloudsecret/gcpsm/gcpsm.go",
			"internal/discovery/cloudsecret/azurekv/azurekv.go",
			"internal/discovery/cloudsecret/vaultkv/vaultkv.go",
			"internal/secretsync/pushers.go",
			"internal/server/secrets_sync_served_test.go",
			"internal/server/discovery_served_test.go",
		},
		Residuals: []string{
			"operator must configure provider credential references before discovery or sync can execute",
			"Vault KV is read-only discovery in core; outbound Vault write sync remains a future provider-specific target",
			"estate-wide policy automation across every vault namespace remains broader than this integration posture",
		},
		RecommendedNextActions: []string{
			"configure cloud_secret sources for AWS, GCP, Azure, and Vault estates",
			"configure sync targets for AWS Secrets Manager, GCP Secret Manager, and Azure Key Vault",
			"review discovery findings before promoting imported secret-manager certificates to managed inventory",
		},
	}
}

func buildUnvaultedSecretPosture(generatedAt string, sourceCounts secretVisibilitySourceCounts, discoveryCounts map[string]int, configuredSync map[string]bool, leakedFindings int) unvaultedSecretPostureResponse {
	if generatedAt == "" {
		generatedAt = "1970-01-01T00:00:00Z"
	}
	detectionSources := []unvaultedSecretDetectionSourceResponse{
		{
			ID:              "repositories",
			Name:            "Git repository secret scanning",
			SourceKind:      secretscan.RepositorySourceKind,
			ConfiguredCount: sourceCounts.Repository,
			DetectionMode:   "webhook or served discovery run invokes the pinned Gitleaks runner against a checkout path or safe clone URL",
			SecretHandling:  "findings persist rule/file/line/fingerprint metadata only; matched secret values stay in the redacted scanner report",
			FindingsKind:    "leaked_secret",
			Capabilities:    []string{"unvaulted-secret-detection", "repository-scan", "redacted-findings", "release-gate"},
			EvidenceRefs:    []string{"internal/secretscan/repository.go", "internal/server/discovery.go", "internal/api/secrets.go"},
		},
		{
			ID:              "third-party-artifacts",
			Name:            "CI/CD, registry, Slack, and Jira artifact scanning",
			SourceKind:      secretscan.ThirdPartySourceKind,
			ConfiguredCount: sourceCounts.ThirdParty,
			DetectionMode:   "served ingest creates metadata-only discovery sources and scans operator-owned artifact paths",
			SecretHandling:  "artifact contents remain in the supplied artifact; findings persist redacted scanner metadata only",
			FindingsKind:    "leaked_secret",
			Capabilities:    []string{"unvaulted-secret-detection", "ci-cd-log", "container-registry", "slack-export", "jira-export"},
			EvidenceRefs:    []string{"internal/secretscan/thirdparty.go", "internal/server/discovery.go", "internal/api/secrets.go"},
		},
	}
	providers := make([]unvaultedSecretVaultProviderResponse, 0, len(cloudSecretManagerProviderSpecs()))
	configuredVaults := make([]string, 0, len(discoveryCounts))
	configuredSyncTargets := make([]string, 0, len(configuredSync))
	summary := unvaultedSecretSummaryResponse{
		RepositorySources:       sourceCounts.Repository,
		ThirdPartySources:       sourceCounts.ThirdParty,
		CloudSecretSources:      sourceCounts.Cloud,
		VaultProvidersSupported: len(cloudSecretManagerProviderSpecs()),
		LeakedSecretFindings:    leakedFindings,
	}
	for target := range configuredSync {
		if target != "" {
			configuredSyncTargets = append(configuredSyncTargets, target)
		}
	}
	sort.Strings(configuredSyncTargets)
	summary.SyncTargetsConfigured = len(configuredSyncTargets)
	for _, spec := range cloudSecretManagerProviderSpecs() {
		discoveryCount := discoveryCounts[spec.ID]
		discoveryConfigured := discoveryCount > 0
		syncConfigured := spec.SyncTargetID != "" && configuredSync[spec.SyncTargetID]
		if discoveryConfigured {
			configuredVaults = append(configuredVaults, spec.ID)
			summary.VaultProvidersVisible++
		}
		caps := append([]string{"vault-augmentation", "multi-vault-visibility"}, spec.Capabilities...)
		mode := "discover vault contents as metadata-only secret-manager findings"
		if spec.SyncSupported {
			mode = "discover vault contents and promote remediated secrets into the configured vault through sealed-outbox sync"
		}
		providers = append(providers, unvaultedSecretVaultProviderResponse{
			ID:                   spec.ID,
			Name:                 spec.Name,
			DiscoveryConfigured:  discoveryConfigured,
			DiscoverySourceCount: discoveryCount,
			SyncSupported:        spec.SyncSupported,
			SyncConfigured:       syncConfigured,
			AugmentationMode:     mode,
			Capabilities:         caps,
			EvidenceRefs:         append([]string(nil), spec.EvidenceRefs...),
		})
	}
	sort.Strings(configuredVaults)
	return unvaultedSecretPostureResponse{ // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
		Capability:            "CAP-SECR-07",
		Served:                true,
		GeneratedAt:           generatedAt,
		Summary:               summary,
		DetectionSources:      detectionSources,
		VaultProviders:        providers,
		ConfiguredVaults:      configuredVaults,
		ConfiguredSyncTargets: configuredSyncTargets,
		Workflow: []string{
			"detect unvaulted secrets from served repository and third-party artifact scans",
			"record leaked_secret findings with redacted scanner metadata only",
			"discover existing vault/cloud-secret-manager coverage across AWS, GCP, Azure, and HashiCorp Vault",
			"augment by syncing remediated trstctl secrets to configured AWS/GCP/Azure secret-manager targets through the sealed outbox",
		},
		SecretHandling: "unvaulted detections persist metadata only; vault values and synced secrets are handled as []byte in scanner/provider boundaries and never returned by this posture route",
		ArchitectureControls: []string{
			"AN-1 tenant-scoped discovery sources, findings, and secret sync rows",
			"AN-2 discovery and sync results are event-backed projections",
			"AN-5 sync mutations are idempotent",
			"AN-6 external vault writes use the sealed outbox before provider delivery",
			"AN-8 scanner/provider secret material is redacted or byte-backed and absent from responses",
		},
		EvidenceRefs: []string{
			"internal/secretscan/gitleaks.go",
			"internal/secretscan/repository.go",
			"internal/secretscan/thirdparty.go",
			"internal/server/discovery.go",
			"internal/discovery/cloudsecret",
			"internal/secretsync/pushers.go",
			"internal/server/secrets_sync_served_test.go",
			"internal/api/secrets.go",
		},
		Residuals: []string{
			"automated pull-request rewrites and developer push-back workflows remain outside this posture route",
			"Vault KV is discovery-only in core until a provider-specific outbound Vault sync target is configured",
			"full organization-wide vault ownership campaigns remain part of broader NHI governance work",
		},
		RecommendedNextActions: []string{
			"wire repository and third-party scan sources for every code, CI, registry, chat, and ticketing surface",
			"configure cloud_secret discovery for each vault and cloud secret-manager estate",
			"sync remediated application secrets into configured AWS/GCP/Azure targets and track leaked_secret findings to closure",
		},
	}
}

func (a *API) kubernetesSecretOperator(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, buildKubernetesSecretOperator(time.Now().UTC().Format(time.RFC3339)))
}

func buildKubernetesSecretOperator(generatedAt string) kubernetesSecretOperatorResponse {
	if generatedAt == "" {
		generatedAt = "1970-01-01T00:00:00Z"
	}
	return kubernetesSecretOperatorResponse{
		Capability:  "CAP-SECR-04",
		Served:      true,
		GeneratedAt: generatedAt,
		CRDs: []kubernetesSecretOperatorCRDResponse{
			{
				Kind:       "TrstctlSecretSync",
				APIGroup:   "trstctl.com",
				APIVersion: "trstctl.com/v1alpha1",
				Plural:     "trstctlsecretsyncs",
				Status:     "served",
				Owns: []string{
					"Kubernetes Secret data",
					"status.phase",
					"status.targetSecret",
					"status.contentHash",
					"status.reloadedWorkloads",
				},
				EvidenceRef: "deploy/operator/crd.yaml",
			},
			{
				Kind:       "TrstctlControlPlane",
				APIGroup:   "trstctl.com",
				APIVersion: "trstctl.com/v1alpha1",
				Plural:     "trstctlcontrolplanes",
				Status:     "served",
				Owns: []string{
					"control-plane Deployment",
					"status.phase",
				},
				EvidenceRef: "deploy/operator/crd.yaml",
			},
		},
		SyncFlow: []string{
			"TrstctlSecretSync.spec.data remoteRef.name resolves through GET /api/v1/secrets/store/{name}?resolve=true",
			"operator writes a Kubernetes Secret with base64 data and trstctl.com/secret-sync-hash metadata",
			"operator records status.phase, targetSecret, syncedKeys, contentHash, and reloadedWorkloads",
		},
		ReloadWorkloads: []string{"Deployment", "StatefulSet", "DaemonSet"},
		SecretHandling:  "operator reads resolved values as bytes, writes only Kubernetes Secret data, wipes resolved buffers, and reports metadata only",
		ArchitectureControls: []string{
			"control-plane token is read from a Kubernetes Secret reference",
			"CRD reconciliation is namespace-scoped and idempotent",
			"workload reload is a pod-template annotation patch, not a pod delete",
		},
		EvidenceRefs: []string{
			"internal/operator/secretsync.go",
			"internal/operator/reconcile_test.go",
			"deploy/operator/crd.yaml",
			"deploy/operator/operator.yaml",
			"internal/server/secrets_sync_served_test.go",
		},
		Residuals: []string{
			"operator still uses a polling reconcile loop rather than a shared informer/workqueue controller",
			"Helm still owns service, ingress, network policy, and signer deployment topology",
			"operator status reports last reconciliation state but not a durable per-delivery history",
		},
		RecommendedNextActions: []string{
			"move the polling loop to informer-backed watch queues before very large cluster counts",
			"add drift/remediation receipts for every reload patch",
			"publish Helm examples for isolated signer and NetworkPolicy defaults",
		},
	}
}

func (a *API) secretWorkloadInjection(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, buildSecretWorkloadInjection(time.Now().UTC().Format(time.RFC3339)))
}

func buildSecretWorkloadInjection(generatedAt string) secretWorkloadInjectionResponse {
	if generatedAt == "" {
		generatedAt = "1970-01-01T00:00:00Z"
	}
	return secretWorkloadInjectionResponse{
		Capability:  "CAP-SECR-05",
		Served:      true,
		GeneratedAt: generatedAt,
		CRD: secretWorkloadInjectionCRDResponse{
			Kind:       "TrstctlSecretInjection",
			APIGroup:   "trstctl.com",
			APIVersion: "trstctl.com/v1alpha1",
			Plural:     "trstctlsecretinjections",
			Status:     "served",
			Owns: []string{
				"app-container file mounts",
				"optional env valueFrom secretKeyRef entries",
				"trstctl-agent secret-injection sidecar",
				"status.phase",
				"status.contentHash",
				"status.injectedWorkloads",
			},
			EvidenceRef: "deploy/operator/crd.yaml",
		},
		Modes: []secretWorkloadInjectionModeResponse{
			{ // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
				ID:             "file",
				Name:           "Shared-volume file injection",
				DeliveredBy:    "TrstctlSecretInjection + trstctl-agent --secret-inject sidecar",
				WorkloadChange: "operator patches pod template with source Secret volume, memory emptyDir, sidecar, and app read-only mount",
				SecretHandling: "sidecar reads Kubernetes Secret volume files as []byte and republishes them into the shared volume with restrictive file mode",
				Capabilities:   []string{"no-code-workload-injection", "sidecar-agent", "file-projection", "rotation-republish"},
			},
			{
				ID:             "env",
				Name:           "Environment reference injection",
				DeliveredBy:    "Kubernetes valueFrom.secretKeyRef patched by the operator",
				WorkloadChange: "operator adds env entries that reference source Secret keys without embedding values in the pod template",
				SecretHandling: "secret value resolution stays inside Kubernetes; trstctl stores only the metadata reference",
				Capabilities:   []string{"no-code-workload-injection", "env-reference", "metadata-only-patch"},
			},
		},
		WorkloadKinds:  []string{"Deployment", "StatefulSet", "DaemonSet"},
		SidecarCommand: []string{"/usr/local/bin/trstctl-agent", "--secret-inject", "--secret-inject-source-dir=/var/run/trstctl/source", "--secret-inject-target-dir=/trstctl/secrets"},
		Annotations: []string{
			"trstctl.com/secret-injection-hash",
			"trstctl.com/secret-injection-name",
			"trstctl.com/secret-injection-source",
		},
		SyncDependency: "TrstctlSecretInjection consumes a Kubernetes Secret, commonly produced by TrstctlSecretSync; it does not read trstctl application-secret values directly.",
		SecretHandling: "the operator reads only Kubernetes Secret metadata/content hash; secret values remain in Kubernetes Secret volumes or valueFrom references, and the sidecar copies bytes without converting them to strings",
		ArchitectureControls: []string{
			"AN-1 namespace-scoped CRDs pair with tenant-scoped trstctl secret resolution in TrstctlSecretSync",
			"AN-5 reconcile is level-based and idempotent",
			"AN-7 injection runs in the workload pod sidecar, isolated from control-plane workers",
			"AN-8 values are byte-backed in the sidecar and absent from API, status, audit, and pod-template metadata",
		},
		EvidenceRefs: []string{
			"internal/operator/secretinjection.go",
			"internal/operator/reconcile_test.go",
			"internal/agent/secretinject/secretinject.go",
			"cmd/trstctl-agent/main.go",
			"deploy/operator/crd.yaml",
			"deploy/operator/operator.yaml",
		},
		Residuals: []string{
			"operator still polls rather than using informer-backed work queues",
			"file injection assumes applications can consume mounted files or env references without app code changes",
			"multi-cluster rollout policy and canary orchestration remain broader deployment automation tracks",
		},
		RecommendedNextActions: []string{
			"sync desired trstctl secrets into a namespace-local Kubernetes Secret with TrstctlSecretSync",
			"declare TrstctlSecretInjection items for the app's expected filenames or env names",
			"watch status.injectedWorkloads and rollout annotations before removing legacy secret mounts",
		},
	}
}
