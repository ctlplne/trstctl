// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/discovery/cloudkeys"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// Replacing a discovered cloud access key with short-lived credentials
// (M3-L4). An operator who finds a stale AWS IAM user key names the tenant's
// AWS dynamic-secret provider and role that replaces it; trstctl sets the key
// Inactive through the finding's own source connection (never a deletion, so
// IAM can activate it again) and marks the finding remediated with the
// replacement as its evidence. Moving the workload onto the role is the
// operator's: the role's leases are what it reads from then on.

// CloudKeyReplaceRequest names the replacement.
type CloudKeyReplaceRequest struct {
	// Provider is the tenant dynamic-secret provider's ID (an aws-sts
	// provider, or its legacy aws-iam name).
	Provider string `json:"provider"`
	// Role is one of the provider's allowed roles.
	Role   string `json:"role"`
	Reason string `json:"reason,omitempty"`
}

type cloudKeyActionResponse struct {
	RequestID   string `json:"request_id"`
	FindingID   string `json:"finding_id"`
	Action      string `json:"action"`
	Provider    string `json:"provider"`
	User        string `json:"user"`
	AccessKeyID string `json:"access_key_id"`
	Replacement string `json:"replacement"`
	Status      string `json:"status"`
}

func (a *API) cloudKeyActionRoutes() []route {
	return []route{
		{method: "POST", path: "/api/v1/discovery/findings/{id}/cloud-key/replace", opID: "replaceCloudAccessKey",
			summary: "Replace a discovered AWS IAM user key with a dynamic-secret role's short-lived credentials, and set the key Inactive",
			handler: a.replaceCloudAccessKey, pathParams: []param{pathUUID("id")}, reqSchema: "CloudKeyReplaceRequest",
			resSchema: "CloudKeyActionResult", successCode: "202", mutation: true, perm: authz.ConnectorsWrite},
	}
}

//trstctl:mutation
func (a *API) replaceCloudAccessKey(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	findingID := r.PathValue("id")
	var request CloudKeyReplaceRequest
	if err := decodeJSON(r, &request); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	request.Provider, request.Role, request.Reason = strings.TrimSpace(request.Provider), strings.TrimSpace(request.Role), strings.TrimSpace(request.Reason)
	if request.Provider == "" || request.Role == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "provider and role name the dynamic-secret role that replaces the key"))
		return
	}
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	binding, err := json.Marshal(struct {
		Domain    string `json:"domain"`
		Actor     string `json:"actor"`
		FindingID string `json:"finding_id"`
		Provider  string `json:"provider"`
		Role      string `json:"role"`
		Reason    string `json:"reason"`
	}{"trstctl.cloud-key-replace.v1", principal.Subject, findingID, request.Provider, request.Role, request.Reason})
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, crypto.SHA256Hex(binding), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errors.New("cloud key action orchestrator is unavailable")
		}
		intent, err := a.cloudKeyReplaceIntent(ctx, tenantID, findingID, request)
		if err != nil {
			return 0, nil, err
		}
		queued, err := a.orch.QueueCloudKeyAction(ctx, tenantID, crypto.SHA256Hex([]byte(tenantID+"\x00"+idempotencyKey)), principal.Subject, intent)
		if errors.Is(err, store.ErrIdempotencyConflict) {
			return 0, nil, errStatus(http.StatusConflict, "the finding changed after review; read it again")
		}
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, cloudKeyActionResponse{
			RequestID: queued.RequestID, FindingID: queued.FindingID, Action: queued.Action, Provider: queued.Provider,
			User: queued.User, AccessKeyID: queued.AccessKeyID, Replacement: queued.Replacement(), Status: orchestrator.OAuthActionQueued,
		}, nil
	})
}

// cloudKeyReplaceIntent checks the finding names an active AWS IAM user key,
// its source still has the IAM connection that found it, and the replacement
// is an AWS dynamic-secret role the caller may use.
func (a *API) cloudKeyReplaceIntent(ctx context.Context, tenantID, findingID string, request CloudKeyReplaceRequest) (orchestrator.CloudKeyActionIntent, error) {
	none := orchestrator.CloudKeyActionIntent{}
	finding, err := a.store.GetDiscoveryFinding(ctx, tenantID, findingID)
	if errors.Is(err, pgx.ErrNoRows) {
		return none, errStatus(http.StatusNotFound, "no such discovery finding")
	}
	if err != nil {
		return none, err
	}
	if finding.Kind != cloudkeys.FindingKind {
		return none, errStatus(http.StatusConflict, "this finding does not name a cloud access key")
	}
	meta := decodeNHIInventoryMetadata(finding.Metadata)
	if metadataString(meta, "provider") != cloudkeys.ProviderAWSIAM {
		return none, errStatus(http.StatusConflict, "only an AWS IAM user key is replaced here; replace other providers' keys in their own consoles")
	}
	user, keyID := metadataString(meta, "user"), metadataString(meta, "access_key_id")
	if user == "" || keyID == "" {
		return none, errStatus(http.StatusConflict, "the finding names no IAM user and key")
	}
	if !strings.EqualFold(metadataString(meta, "status"), "Active") {
		return none, errStatus(http.StatusConflict, "the key is not Active")
	}
	host, ok := strings.CutPrefix(finding.Provenance, cloudkeys.ProviderAWSIAM+":")
	if !ok || host == "" {
		return none, errStatus(http.StatusConflict, "the finding does not name the IAM host that reported it")
	}
	source, err := a.store.GetDiscoverySource(ctx, tenantID, finding.SourceID)
	if err != nil {
		return none, errStatus(http.StatusConflict, "the discovery source that found this key is gone")
	}
	if !sourceHasAWSIAMConnection(source.Config, host) {
		return none, errStatus(http.StatusConflict, "the source that found this key has no aws-iam connection at "+host)
	}
	if a.secrets == nil {
		return none, errStatus(http.StatusConflict, "dynamic secrets are not enabled; configure an aws-sts provider first")
	}
	provider, found := a.secrets.configuredDynamicSecretProvider(tenantID, request.Provider)
	if found {
		visible, err := a.visibleDynamicSecretProviders(ctx, tenantID, []dynamicSecretConfiguredProvider{provider})
		if err != nil {
			return none, err
		}
		found = len(visible) == 1
	}
	if !found {
		return none, errStatus(http.StatusUnprocessableEntity, "no such dynamic-secret provider")
	}
	if provider.Type != "aws-sts" && provider.Type != "aws-iam" {
		return none, errStatus(http.StatusUnprocessableEntity, "the replacement must be an AWS STS provider's role")
	}
	if !provider.Ready {
		return none, errStatus(http.StatusServiceUnavailable, "the dynamic-secret provider is not ready; repair its startup configuration and restart")
	}
	if !slices.Contains(provider.AllowedRoles, request.Role) {
		return none, errStatus(http.StatusUnprocessableEntity, "the provider does not allow role "+request.Role)
	}
	return orchestrator.CloudKeyActionIntent{
		FindingID: finding.ID, SourceID: finding.SourceID, Action: orchestrator.CloudKeyActionDeactivate,
		Provider: cloudkeys.ProviderAWSIAM, Host: host, User: user, AccessKeyID: keyID,
		ReplacementProvider: provider.ID, ReplacementRole: request.Role, Reason: request.Reason,
	}, nil
}

// sourceHasAWSIAMConnection reports whether a cloud_access_key source reads
// an aws-iam connection at host.
func sourceHasAWSIAMConnection(config []byte, host string) bool {
	var cfg struct {
		Providers []struct {
			Provider string `json:"provider"`
			Endpoint string `json:"endpoint"`
		} `json:"providers"`
	}
	if json.Unmarshal(config, &cfg) != nil {
		return false
	}
	for _, p := range cfg.Providers {
		if strings.TrimSpace(p.Provider) != cloudkeys.ProviderAWSIAM {
			continue
		}
		if _, h, err := cloudkeys.AWSIAMEndpoint(p.Endpoint); err == nil && h == host {
			return true
		}
	}
	return false
}
