// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type secretSyncWorkloadIdentitySourceRequest struct {
	Name                     string   `json:"name"`
	Provider                 string   `json:"provider,omitempty"`
	RoleARN                  string   `json:"role_arn"`
	ServiceAccount           string   `json:"service_account,omitempty"`
	Audience                 string   `json:"audience"`
	Subject                  string   `json:"subject"`
	TargetID                 string   `json:"target_id"`
	AllowedRemoteKeyPrefixes []string `json:"allowed_remote_key_prefixes,omitempty"`
	WorkloadProofRef         string   `json:"workload_proof_ref"`
	TrustSourceID            string   `json:"trust_source_id"`
	Enabled                  *bool    `json:"enabled,omitempty"`
}

type secretSyncWorkloadIdentitySourceResponse struct {
	ID                       string   `json:"id"`
	TenantID                 string   `json:"tenant_id"`
	Name                     string   `json:"name"`
	Provider                 string   `json:"provider"`
	RoleARN                  string   `json:"role_arn"`
	ServiceAccount           string   `json:"service_account"`
	Audience                 string   `json:"audience"`
	Subject                  string   `json:"subject"`
	TargetID                 string   `json:"target_id"`
	AllowedRemoteKeyPrefixes []string `json:"allowed_remote_key_prefixes"`
	WorkloadProofRef         string   `json:"workload_proof_ref"`
	TrustSourceID            string   `json:"trust_source_id"`
	Enabled                  bool     `json:"enabled"`
	Status                   string   `json:"status"`
	StatusReason             string   `json:"status_reason"`
	LastExchangeAt           string   `json:"last_exchange_at,omitempty"`
	TokenExpiresAt           string   `json:"token_expires_at,omitempty"`
	LastFailureAt            string   `json:"last_failure_at,omitempty"`
	CreatedAt                string   `json:"created_at"`
	UpdatedAt                string   `json:"updated_at"`
}

type secretSyncWorkloadIdentitySourceListResponse struct {
	Items []secretSyncWorkloadIdentitySourceResponse `json:"items"`
}

//trstctl:mutation
func (a *API) createSecretSyncWorkloadIdentitySource(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		req, err := a.decodeSecretSyncWorkloadIdentitySourceRequest(ctx, tenantID, r)
		if err != nil {
			return 0, nil, err
		}
		id := googleuuid.NewString()
		if err := a.emitSecretSyncWorkloadIdentitySource(ctx, tenantID, id, req); err != nil {
			return 0, nil, err
		}
		source, err := a.store.GetSecretSyncWorkloadIdentitySource(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toSecretSyncWorkloadIdentitySourceResponse(source), nil
	})
}

func (a *API) listSecretSyncWorkloadIdentitySources(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	sources, err := a.store.ListSecretSyncWorkloadIdentitySources(r.Context(), tenantID)
	if err != nil {
		a.writeSecretSyncWorkloadIdentitySourceError(w, err)
		return
	}
	items := make([]secretSyncWorkloadIdentitySourceResponse, 0, len(sources))
	for _, source := range sources {
		items = append(items, toSecretSyncWorkloadIdentitySourceResponse(source))
	}
	a.writeJSON(w, http.StatusOK, secretSyncWorkloadIdentitySourceListResponse{Items: items})
}

func (a *API) getSecretSyncWorkloadIdentitySource(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	source, err := a.store.GetSecretSyncWorkloadIdentitySource(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeSecretSyncWorkloadIdentitySourceError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toSecretSyncWorkloadIdentitySourceResponse(source))
}

//trstctl:mutation
func (a *API) updateSecretSyncWorkloadIdentitySource(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if _, err := a.store.GetSecretSyncWorkloadIdentitySource(ctx, tenantID, id); err != nil {
			return 0, nil, err
		}
		req, err := a.decodeSecretSyncWorkloadIdentitySourceRequest(ctx, tenantID, r)
		if err != nil {
			return 0, nil, err
		}
		if err := a.emitSecretSyncWorkloadIdentitySource(ctx, tenantID, id, req); err != nil {
			return 0, nil, err
		}
		source, err := a.store.GetSecretSyncWorkloadIdentitySource(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, toSecretSyncWorkloadIdentitySourceResponse(source), nil
	})
}

//trstctl:mutation
func (a *API) deleteSecretSyncWorkloadIdentitySource(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if _, err := a.store.GetSecretSyncWorkloadIdentitySource(ctx, tenantID, id); err != nil {
			return 0, nil, err
		}
		data, err := json.Marshal(projections.SecretSyncWorkloadIdentitySourceDeleted{ID: id})
		if err != nil {
			return 0, nil, err
		}
		if err := a.appendAndProjectSecretSyncWorkloadIdentitySource(ctx, tenantID, projections.EventSecretSyncWorkloadIdentityDeleted, data); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

func (a *API) decodeSecretSyncWorkloadIdentitySourceRequest(ctx context.Context, tenantID string, r *http.Request) (secretSyncWorkloadIdentitySourceRequest, error) {
	var req secretSyncWorkloadIdentitySourceRequest
	if err := decodeJSON(r, &req); err != nil {
		return req, errWithStatus(http.StatusBadRequest, err)
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Provider = strings.ToLower(strings.TrimSpace(req.Provider))
	if req.Provider == "" {
		req.Provider = "aws"
	}
	req.RoleARN = strings.TrimSpace(req.RoleARN)
	req.ServiceAccount = strings.TrimSpace(req.ServiceAccount)
	req.Audience = strings.TrimSpace(req.Audience)
	req.Subject = strings.TrimSpace(req.Subject)
	req.TargetID = strings.TrimSpace(req.TargetID)
	req.WorkloadProofRef = strings.TrimSpace(req.WorkloadProofRef)
	req.TrustSourceID = strings.TrimSpace(req.TrustSourceID)
	if req.Enabled == nil {
		on := true
		req.Enabled = &on
	}
	if req.Name == "" || req.Audience == "" || req.Subject == "" ||
		req.TargetID == "" || req.WorkloadProofRef == "" || req.TrustSourceID == "" {
		return req, errStatus(http.StatusBadRequest, "name, audience, subject, target_id, workload_proof_ref, and trust_source_id are required")
	}
	switch req.Provider {
	case "aws":
		if !strings.HasPrefix(req.RoleARN, "arn:aws:iam::") || !strings.Contains(req.RoleARN, ":role/") {
			return req, errStatus(http.StatusBadRequest, "role_arn must be an AWS IAM role ARN")
		}
		if req.ServiceAccount != "" {
			return req, errStatus(http.StatusBadRequest, "service_account is only valid for GCP")
		}
	case "gcp":
		if req.RoleARN != "" {
			return req, errStatus(http.StatusBadRequest, "role_arn is only valid for AWS")
		}
		if req.ServiceAccount != "" &&
			(!strings.HasSuffix(req.ServiceAccount, ".iam.gserviceaccount.com") ||
				strings.Count(req.ServiceAccount, "@") != 1 ||
				strings.ContainsAny(req.ServiceAccount, " \t\r\n")) {
			return req, errStatus(http.StatusBadRequest, "service_account must be a GCP IAM service-account email")
		}
	default:
		return req, errStatus(http.StatusBadRequest, "provider must be aws or gcp")
	}
	if !strings.HasPrefix(req.WorkloadProofRef, "file:") && !strings.HasPrefix(req.WorkloadProofRef, "secret://") {
		return req, errStatus(http.StatusBadRequest, "workload_proof_ref must use file: or secret://; inline proofs are forbidden")
	}
	if strings.Trim(strings.TrimPrefix(strings.TrimPrefix(req.WorkloadProofRef, "file:"), "secret://"), "/") == "" {
		return req, errStatus(http.StatusBadRequest, "workload_proof_ref must identify a non-empty file or tenant secret")
	}
	prefixes := make([]string, 0, len(req.AllowedRemoteKeyPrefixes))
	seen := map[string]bool{}
	for _, prefix := range req.AllowedRemoteKeyPrefixes {
		prefix = strings.TrimSpace(prefix)
		if prefix == "" || strings.ContainsRune(prefix, '\x00') {
			return req, errStatus(http.StatusBadRequest, "allowed_remote_key_prefixes must contain non-empty, NUL-free prefixes")
		}
		if !seen[prefix] {
			seen[prefix] = true
			prefixes = append(prefixes, prefix)
		}
	}
	req.AllowedRemoteKeyPrefixes = prefixes
	trust, err := a.store.GetWorkloadAttesterTrustSource(ctx, tenantID, req.TrustSourceID)
	if err != nil {
		if errors.Is(err, store.ErrWorkloadAttesterTrustSourceNotFound) {
			return req, errStatus(http.StatusBadRequest, "trust_source_id must name a tenant workload attester trust source")
		}
		return req, err
	}
	if !trust.Enabled || trust.RevokedAt != nil {
		return req, errStatus(http.StatusBadRequest, "trust_source_id must be enabled and not revoked")
	}
	switch trust.Method {
	case "k8s_sat", "gcp_iit", "github_oidc":
	default:
		return req, errStatus(http.StatusBadRequest, "trust_source_id must use a JWT/JWKS workload attestation method")
	}
	if trust.Audience != req.Audience {
		return req, errStatus(http.StatusBadRequest, "audience must exactly match the selected trust source")
	}
	return req, nil
}

func (a *API) emitSecretSyncWorkloadIdentitySource(ctx context.Context, tenantID, id string, req secretSyncWorkloadIdentitySourceRequest) error {
	data, err := json.Marshal(projections.SecretSyncWorkloadIdentitySourceUpserted{
		ID: id, Name: req.Name, Provider: req.Provider, RoleARN: req.RoleARN,
		ServiceAccount: req.ServiceAccount,
		Audience:       req.Audience, Subject: req.Subject, TargetID: req.TargetID,
		AllowedRemoteKeyPrefixes: req.AllowedRemoteKeyPrefixes,
		WorkloadProofRef:         req.WorkloadProofRef, TrustSourceID: req.TrustSourceID,
		Enabled: *req.Enabled,
	})
	if err != nil {
		return err
	}
	return a.appendAndProjectSecretSyncWorkloadIdentitySource(ctx, tenantID, projections.EventSecretSyncWorkloadIdentityUpserted, data)
}

func (a *API) appendAndProjectSecretSyncWorkloadIdentitySource(ctx context.Context, tenantID, eventType string, data []byte) error {
	if a.store == nil || a.log == nil {
		return errStatus(http.StatusServiceUnavailable, "secret-sync workload identity management is not configured")
	}
	event, err := a.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: data})
	if err != nil {
		return err
	}
	return projections.New(a.store).Apply(ctx, event)
}

func toSecretSyncWorkloadIdentitySourceResponse(source store.SecretSyncWorkloadIdentitySource) secretSyncWorkloadIdentitySourceResponse {
	out := secretSyncWorkloadIdentitySourceResponse{
		ID: source.ID, TenantID: source.TenantID, Name: source.Name, Provider: source.Provider,
		RoleARN: source.RoleARN, ServiceAccount: source.ServiceAccount,
		Audience: source.Audience, Subject: source.Subject,
		TargetID: source.TargetID, AllowedRemoteKeyPrefixes: append([]string(nil), source.AllowedRemoteKeyPrefixes...),
		WorkloadProofRef: source.WorkloadProofRef, TrustSourceID: source.TrustSourceID,
		Enabled: source.Enabled, Status: source.Status, StatusReason: source.StatusReason,
		CreatedAt: source.CreatedAt.UTC().Format(time.RFC3339), UpdatedAt: source.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if source.LastExchangeAt != nil {
		out.LastExchangeAt = source.LastExchangeAt.UTC().Format(time.RFC3339)
	}
	if source.TokenExpiresAt != nil {
		out.TokenExpiresAt = source.TokenExpiresAt.UTC().Format(time.RFC3339)
	}
	if source.LastFailureAt != nil {
		out.LastFailureAt = source.LastFailureAt.UTC().Format(time.RFC3339)
	}
	return out
}

func (a *API) writeSecretSyncWorkloadIdentitySourceError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrSecretSyncWorkloadIdentitySourceNotFound) {
		a.writeError(w, errStatus(http.StatusNotFound, "secret-sync workload identity source not found"))
		return
	}
	a.writeError(w, err)
}
