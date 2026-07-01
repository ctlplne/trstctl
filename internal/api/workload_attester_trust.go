package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type workloadAttesterTrustSourceRequest struct {
	Name                string          `json:"name"`
	Method              string          `json:"method"`
	Issuer              string          `json:"issuer,omitempty"`
	Audience            string          `json:"audience,omitempty"`
	JWKS                json.RawMessage `json:"jwks,omitempty"`
	RootCertsPEM        []string        `json:"root_certs_pem,omitempty"`
	ExpectedNonceBase64 string          `json:"expected_nonce_base64,omitempty"`
	Enabled             *bool           `json:"enabled,omitempty"`
}

type workloadAttesterTrustSourceRotateRequest struct {
	Issuer              string          `json:"issuer,omitempty"`
	Audience            string          `json:"audience,omitempty"`
	JWKS                json.RawMessage `json:"jwks,omitempty"`
	RootCertsPEM        []string        `json:"root_certs_pem,omitempty"`
	ExpectedNonceBase64 string          `json:"expected_nonce_base64,omitempty"`
	Reason              string          `json:"reason,omitempty"`
}

type workloadAttesterTrustSourceRevokeRequest struct {
	Reason string `json:"reason,omitempty"`
}

type workloadAttesterTrustSourceResponse struct {
	ID                  string          `json:"id"`
	TenantID            string          `json:"tenant_id"`
	Name                string          `json:"name"`
	Method              string          `json:"method"`
	Issuer              string          `json:"issuer,omitempty"`
	Audience            string          `json:"audience,omitempty"`
	JWKS                json.RawMessage `json:"jwks"`
	RootCertsPEM        []string        `json:"root_certs_pem"`
	ExpectedNonceBase64 string          `json:"expected_nonce_base64,omitempty"`
	Enabled             bool            `json:"enabled"`
	RevokedAt           string          `json:"revoked_at,omitempty"`
	RevokedReason       string          `json:"revoked_reason,omitempty"`
	RotationVersion     int             `json:"rotation_version"`
	LastRotatedAt       string          `json:"last_rotated_at,omitempty"`
	CreatedAt           string          `json:"created_at"`
	UpdatedAt           string          `json:"updated_at"`
}

type workloadAttesterTrustSourceListResponse struct {
	Items []workloadAttesterTrustSourceResponse `json:"items"`
}

type workloadAttesterTrustSourceRotatedResponse struct {
	TrustSource workloadAttesterTrustSourceResponse `json:"trust_source"`
}

type workloadAttesterTrustSourceRevokedResponse struct {
	TrustSource workloadAttesterTrustSourceResponse `json:"trust_source"`
}

//trstctl:mutation
func (a *API) createWorkloadAttesterTrustSource(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		req, err := decodeWorkloadAttesterTrustSourceRequest(r)
		if err != nil {
			return 0, nil, err
		}
		id := googleuuid.NewString()
		if err := a.emitWorkloadAttesterTrustSource(ctx, tenantID, id, req, 1); err != nil {
			return 0, nil, err
		}
		rec, err := a.store.GetWorkloadAttesterTrustSource(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toWorkloadAttesterTrustSourceResponse(rec), nil
	})
}

func (a *API) listWorkloadAttesterTrustSources(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	recs, err := a.store.ListWorkloadAttesterTrustSources(r.Context(), tenantID)
	if err != nil {
		a.writeWorkloadAttesterTrustSourceError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, workloadAttesterTrustSourceListResponse{Items: toWorkloadAttesterTrustSourceResponses(recs)})
}

func (a *API) getWorkloadAttesterTrustSource(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	rec, err := a.store.GetWorkloadAttesterTrustSource(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeWorkloadAttesterTrustSourceError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toWorkloadAttesterTrustSourceResponse(rec))
}

//trstctl:mutation
func (a *API) updateWorkloadAttesterTrustSource(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		existing, err := a.store.GetWorkloadAttesterTrustSource(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		req, err := decodeWorkloadAttesterTrustSourceRequest(r)
		if err != nil {
			return 0, nil, err
		}
		if err := a.emitWorkloadAttesterTrustSource(ctx, tenantID, id, req, existing.RotationVersion); err != nil {
			return 0, nil, err
		}
		rec, err := a.store.GetWorkloadAttesterTrustSource(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, toWorkloadAttesterTrustSourceResponse(rec), nil
	})
}

//trstctl:mutation
func (a *API) rotateWorkloadAttesterTrustSource(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		existing, err := a.store.GetWorkloadAttesterTrustSource(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		req, err := decodeWorkloadAttesterTrustSourceRotateRequest(r, existing)
		if err != nil {
			return 0, nil, err
		}
		payload, err := json.Marshal(projections.WorkloadAttesterTrustSourceRotated{
			ID: id, Issuer: req.Issuer, Audience: req.Audience, JWKS: req.JWKS,
			RootCertsPEM: req.RootCertsPEM, ExpectedNonceBase64: req.ExpectedNonceBase64,
			RotationVersion: existing.RotationVersion + 1, Reason: req.Reason,
		})
		if err != nil {
			return 0, nil, err
		}
		if err := a.appendAndProjectWorkloadAttesterTrustSource(ctx, tenantID, projections.EventWorkloadAttesterTrustSourceRotated, payload); err != nil {
			return 0, nil, err
		}
		rec, err := a.store.GetWorkloadAttesterTrustSource(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, workloadAttesterTrustSourceRotatedResponse{TrustSource: toWorkloadAttesterTrustSourceResponse(rec)}, nil
	})
}

//trstctl:mutation
func (a *API) revokeWorkloadAttesterTrustSource(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if _, err := a.store.GetWorkloadAttesterTrustSource(ctx, tenantID, id); err != nil {
			return 0, nil, err
		}
		var req workloadAttesterTrustSourceRevokeRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		payload, err := json.Marshal(projections.WorkloadAttesterTrustSourceRevoked{
			ID: id, Reason: strings.TrimSpace(req.Reason),
		})
		if err != nil {
			return 0, nil, err
		}
		if err := a.appendAndProjectWorkloadAttesterTrustSource(ctx, tenantID, projections.EventWorkloadAttesterTrustSourceRevoked, payload); err != nil {
			return 0, nil, err
		}
		rec, err := a.store.GetWorkloadAttesterTrustSource(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, workloadAttesterTrustSourceRevokedResponse{TrustSource: toWorkloadAttesterTrustSourceResponse(rec)}, nil
	})
}

//trstctl:mutation
func (a *API) deleteWorkloadAttesterTrustSource(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if _, err := a.store.GetWorkloadAttesterTrustSource(ctx, tenantID, id); err != nil {
			return 0, nil, err
		}
		payload, err := json.Marshal(projections.WorkloadAttesterTrustSourceDeleted{ID: id})
		if err != nil {
			return 0, nil, err
		}
		if err := a.appendAndProjectWorkloadAttesterTrustSource(ctx, tenantID, projections.EventWorkloadAttesterTrustSourceDeleted, payload); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

func (a *API) emitWorkloadAttesterTrustSource(ctx context.Context, tenantID, id string, req workloadAttesterTrustSourceRequest, rotationVersion int) error {
	payload, err := json.Marshal(projections.WorkloadAttesterTrustSourceUpserted{
		ID: id, Name: req.Name, Method: req.Method, Issuer: req.Issuer, Audience: req.Audience,
		JWKS: req.JWKS, RootCertsPEM: req.RootCertsPEM, ExpectedNonceBase64: req.ExpectedNonceBase64,
		Enabled: *req.Enabled, RotationVersion: rotationVersion,
	})
	if err != nil {
		return err
	}
	return a.appendAndProjectWorkloadAttesterTrustSource(ctx, tenantID, projections.EventWorkloadAttesterTrustSourceUpserted, payload)
}

func (a *API) appendAndProjectWorkloadAttesterTrustSource(ctx context.Context, tenantID, eventType string, payload []byte) error {
	if a.store == nil || a.log == nil {
		return errStatus(http.StatusServiceUnavailable, "workload attester trust-source management is not configured")
	}
	ev, err := a.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: payload})
	if err != nil {
		return err
	}
	return projections.New(a.store).Apply(ctx, ev)
}

func decodeWorkloadAttesterTrustSourceRequest(r *http.Request) (workloadAttesterTrustSourceRequest, error) {
	var raw json.RawMessage
	if err := decodeJSON(r, &raw); err != nil {
		return workloadAttesterTrustSourceRequest{}, errWithStatus(http.StatusBadRequest, err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return workloadAttesterTrustSourceRequest{}, errStatus(http.StatusBadRequest, "request body must be a JSON object")
	}
	if containsInlineSecret(obj) {
		return workloadAttesterTrustSourceRequest{}, errStatus(http.StatusBadRequest, "workload attester trust sources accept public trust material and references, not inline secrets")
	}
	var req workloadAttesterTrustSourceRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return workloadAttesterTrustSourceRequest{}, errStatus(http.StatusBadRequest, "invalid workload attester trust-source request")
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Method = strings.TrimSpace(req.Method)
	req.Issuer = strings.TrimSpace(req.Issuer)
	req.Audience = strings.TrimSpace(req.Audience)
	req.ExpectedNonceBase64 = strings.TrimSpace(req.ExpectedNonceBase64)
	if req.Name == "" || req.Method == "" {
		return workloadAttesterTrustSourceRequest{}, errStatus(http.StatusBadRequest, "name and method are required")
	}
	if req.Enabled == nil {
		on := true
		req.Enabled = &on
	}
	if err := validateWorkloadAttesterTrustMaterial(req.Method, req.JWKS, req.RootCertsPEM, req.ExpectedNonceBase64); err != nil {
		return workloadAttesterTrustSourceRequest{}, err
	}
	req.JWKS = normalizeJWKSForMethod(req.Method, req.JWKS)
	req.RootCertsPEM = normalizePEMList(req.RootCertsPEM)
	return req, nil
}

func decodeWorkloadAttesterTrustSourceRotateRequest(r *http.Request, existing store.WorkloadAttesterTrustSource) (workloadAttesterTrustSourceRotateRequest, error) {
	var raw json.RawMessage
	if err := decodeJSON(r, &raw); err != nil {
		return workloadAttesterTrustSourceRotateRequest{}, errWithStatus(http.StatusBadRequest, err)
	}
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return workloadAttesterTrustSourceRotateRequest{}, errStatus(http.StatusBadRequest, "request body must be a JSON object")
	}
	if containsInlineSecret(obj) {
		return workloadAttesterTrustSourceRotateRequest{}, errStatus(http.StatusBadRequest, "workload attester trust-source rotation accepts public trust material and references, not inline secrets")
	}
	var req workloadAttesterTrustSourceRotateRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return workloadAttesterTrustSourceRotateRequest{}, errStatus(http.StatusBadRequest, "invalid workload attester trust-source rotation request")
	}
	req.Issuer = coalesceTrimmed(req.Issuer, existing.Issuer)
	req.Audience = coalesceTrimmed(req.Audience, existing.Audience)
	req.ExpectedNonceBase64 = coalesceTrimmed(req.ExpectedNonceBase64, existing.ExpectedNonceBase64)
	if len(req.JWKS) == 0 {
		req.JWKS = existing.JWKS
	}
	if req.RootCertsPEM == nil {
		req.RootCertsPEM = existing.RootCertsPEM
	}
	req.RootCertsPEM = normalizePEMList(req.RootCertsPEM)
	req.Reason = strings.TrimSpace(req.Reason)
	if err := validateWorkloadAttesterTrustMaterial(existing.Method, req.JWKS, req.RootCertsPEM, req.ExpectedNonceBase64); err != nil {
		return workloadAttesterTrustSourceRotateRequest{}, err
	}
	req.JWKS = normalizeJWKSForMethod(existing.Method, req.JWKS)
	return req, nil
}

func validateWorkloadAttesterTrustMaterial(method string, jwks json.RawMessage, roots []string, expectedNonce string) error {
	roots = normalizePEMList(roots)
	switch method {
	case "k8s_sat", "gcp_iit", "github_oidc":
		if len(jwks) == 0 || string(jwks) == "{}" {
			return errStatus(http.StatusBadRequest, "jwks is required for "+method)
		}
		if _, err := crypto.ParseJWKS(jwks); err != nil {
			return errStatus(http.StatusBadRequest, "jwks is invalid: "+err.Error())
		}
	case "aws_iid", "azure_imds":
		if len(roots) == 0 {
			return errStatus(http.StatusBadRequest, "root_certs_pem is required for "+method)
		}
		if err := validatePublicCertPEMList(roots); err != nil {
			return err
		}
	case "tpm":
		if len(roots) == 0 {
			return errStatus(http.StatusBadRequest, "root_certs_pem is required for tpm")
		}
		if err := validatePublicCertPEMList(roots); err != nil {
			return err
		}
		if expectedNonce != "" {
			if _, err := base64.StdEncoding.DecodeString(expectedNonce); err != nil {
				return errStatus(http.StatusBadRequest, "expected_nonce_base64 must be standard base64")
			}
		}
	default:
		return errStatus(http.StatusBadRequest, "method must be one of aws_iid, azure_imds, gcp_iit, github_oidc, k8s_sat, or tpm")
	}
	return nil
}

func validatePublicCertPEMList(certs []string) error {
	certs = normalizePEMList(certs)
	if len(certs) == 0 {
		return errStatus(http.StatusBadRequest, "root_certs_pem must contain at least one public certificate")
	}
	for _, pemText := range certs {
		if strings.Contains(pemText, "PRIVATE KEY") {
			return errStatus(http.StatusBadRequest, "root_certs_pem must contain public certificates, not private keys")
		}
		if _, err := certinfo.Inspect([]byte(pemText)); err != nil {
			return errStatus(http.StatusBadRequest, "root_certs_pem contains an invalid certificate: "+err.Error())
		}
	}
	return nil
}

func normalizeJWKSForMethod(method string, jwks json.RawMessage) json.RawMessage {
	switch method {
	case "k8s_sat", "gcp_iit", "github_oidc":
		if len(jwks) > 0 {
			return jwks
		}
	}
	return json.RawMessage(`{}`)
}

func normalizePEMList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func coalesceTrimmed(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return strings.TrimSpace(fallback)
	}
	return strings.TrimSpace(value)
}

func toWorkloadAttesterTrustSourceResponses(recs []store.WorkloadAttesterTrustSource) []workloadAttesterTrustSourceResponse {
	items := make([]workloadAttesterTrustSourceResponse, 0, len(recs))
	for _, rec := range recs {
		items = append(items, toWorkloadAttesterTrustSourceResponse(rec))
	}
	return items
}

func toWorkloadAttesterTrustSourceResponse(rec store.WorkloadAttesterTrustSource) workloadAttesterTrustSourceResponse {
	jwks := rec.JWKS
	if len(jwks) == 0 {
		jwks = json.RawMessage(`{}`)
	}
	roots := rec.RootCertsPEM
	if roots == nil {
		roots = []string{}
	}
	out := workloadAttesterTrustSourceResponse{
		ID: rec.ID, TenantID: rec.TenantID, Name: rec.Name, Method: rec.Method,
		Issuer: rec.Issuer, Audience: rec.Audience, JWKS: jwks, RootCertsPEM: roots,
		ExpectedNonceBase64: rec.ExpectedNonceBase64, Enabled: rec.Enabled,
		RevokedReason: rec.RevokedReason, RotationVersion: rec.RotationVersion,
		CreatedAt: rec.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt: rec.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
	if rec.RevokedAt != nil {
		out.RevokedAt = rec.RevokedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	if rec.LastRotatedAt != nil {
		out.LastRotatedAt = rec.LastRotatedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	return out
}

func (a *API) writeWorkloadAttesterTrustSourceError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrWorkloadAttesterTrustSourceNotFound) {
		a.writeError(w, errStatus(http.StatusNotFound, "workload attester trust source not found"))
		return
	}
	a.writeError(w, err)
}
