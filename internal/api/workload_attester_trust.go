// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
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
	// SelfAuthenticating (A84): a github_oidc source whose verified token is by
	// itself the bearer credential of attested issuance for this tenant. It
	// requires AllowedOwners, the pin that keeps the rest of GitHub out.
	SelfAuthenticating bool     `json:"self_authenticating,omitempty"`
	AllowedOwners      []string `json:"allowed_owners,omitempty"`
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
	SelfAuthenticating  bool            `json:"self_authenticating"`
	AllowedOwners       []string        `json:"allowed_owners"`
	Enabled             bool            `json:"enabled"`
	AuthorityPending    bool            `json:"authority_pending"`
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

func workloadAttesterTrustRequestBinding(r *http.Request) (string, []byte, error) {
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		return "", nil, err
	}
	return mutationRequestBinding(r, principal)
}

// A projected receipt is the answer after an HTTP result was lost. Reading it
// before the current source lets a deleted source return its original 204 and
// lets an old rotation return its original snapshot after a newer rotation.
func (a *API) replayWorkloadAttesterTrustSource(ctx context.Context, tenantID, sourceID, key,
	requestBinding, eventType string) (store.WorkloadAttesterTrustSource, bool, error) {
	var zero store.WorkloadAttesterTrustSource
	if a.store == nil || a.log == nil {
		return zero, false, errStatus(http.StatusServiceUnavailable,
			"workload attester trust-source management is not configured")
	}
	tenantUUID, err := googleuuid.Parse(tenantID)
	if err != nil {
		return zero, false, errStatus(http.StatusUnauthorized, "missing or invalid tenant")
	}
	eventID := googleuuid.NewSHA1(tenantUUID,
		[]byte("trstctl:workload-attester-trust-command:"+key)).String()
	receipt, err := a.store.WorkloadAttesterTrustReceiptByEventID(ctx, tenantID, eventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return zero, false, nil
	}
	if err != nil {
		return zero, false, err
	}
	if receipt.EventType != eventType || (sourceID != "" && receipt.SourceID != sourceID) ||
		!crypto.ConstantTimeEqual([]byte(receipt.RequestBinding), []byte(requestBinding)) {
		return zero, false, store.ErrIdempotencyConflict
	}
	if eventType == projections.EventWorkloadAttesterTrustSourceDeleted {
		if len(receipt.Snapshot) != 0 {
			return zero, false, errors.New("api: deleted attester trust receipt retained a source")
		}
		return zero, true, nil
	}
	if len(receipt.Snapshot) == 0 {
		return zero, false, errStatus(http.StatusGone,
			"the original trust-source result was erased under a privacy request; its source event was not repeated")
	}
	if err := json.Unmarshal(receipt.Snapshot, &zero); err != nil {
		return zero, false, err
	}
	if zero.TenantID != tenantID || zero.ID != receipt.SourceID {
		return store.WorkloadAttesterTrustSource{}, false, errors.New("api: attester trust receipt differs from source")
	}
	return zero, true, nil
}

//trstctl:mutation
func (a *API) createWorkloadAttesterTrustSource(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	requestBinding, body, err := workloadAttesterTrustRequestBinding(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	defer secret.Wipe(body)
	a.mutateDurableBound(w, r, idempotencyKey, requestBinding, func(ctx context.Context, tenantID string) (int, any, error) {
		if rec, replay, err := a.replayWorkloadAttesterTrustSource(ctx, tenantID, "", idempotencyKey,
			requestBinding, projections.EventWorkloadAttesterTrustSourceUpserted); err != nil {
			return 0, nil, err
		} else if replay {
			return http.StatusCreated, toWorkloadAttesterTrustSourceResponse(rec), nil
		}
		req, err := decodeWorkloadAttesterTrustSourceRequest(r)
		if err != nil {
			return 0, nil, err
		}
		tenantUUID, err := googleuuid.Parse(tenantID)
		if err != nil {
			return 0, nil, errStatus(http.StatusUnauthorized, "missing or invalid tenant")
		}
		// A logical name has one stable aggregate ID. This makes two concurrent
		// creates converge on one event-sourced aggregate even if both pass the
		// read-side availability check before either projection becomes visible.
		id := googleuuid.NewSHA1(tenantUUID,
			[]byte("trstctl:workload-attester-trust-source:"+strings.ToLower(req.Name))).String()
		if err := a.ensureWorkloadAttesterTrustSourceNameAvailable(ctx, tenantID, req.Name, ""); err != nil {
			return 0, nil, err
		}
		if err := a.emitWorkloadAttesterTrustSource(ctx, tenantID, id, idempotencyKey, requestBinding, req, 1); err != nil {
			return 0, nil, err
		}
		rec, err := a.store.GetWorkloadAttesterTrustSource(ctx, tenantID, id)
		if err != nil {
			if errors.Is(err, store.ErrWorkloadAttesterTrustSourceNotFound) {
				return 0, nil, workloadAttesterTrustSourceNameConflict(req.Name)
			}
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
	rec, err := a.store.GetEffectiveWorkloadAttesterTrustSource(r.Context(), tenantID, r.PathValue("id"))
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
	requestBinding, body, err := workloadAttesterTrustRequestBinding(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	defer secret.Wipe(body)
	a.mutateDurableBound(w, r, idempotencyKey, requestBinding, func(ctx context.Context, tenantID string) (int, any, error) {
		if rec, replay, err := a.replayWorkloadAttesterTrustSource(ctx, tenantID, id, idempotencyKey,
			requestBinding, projections.EventWorkloadAttesterTrustSourceUpserted); err != nil {
			return 0, nil, err
		} else if replay {
			return http.StatusOK, toWorkloadAttesterTrustSourceResponse(rec), nil
		}
		existing, err := a.store.GetWorkloadAttesterTrustSource(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		req, err := decodeWorkloadAttesterTrustSourceRequest(r)
		if err != nil {
			return 0, nil, err
		}
		if err := a.ensureWorkloadAttesterTrustSourceNameAvailable(ctx, tenantID, req.Name, id); err != nil {
			return 0, nil, err
		}
		if err := a.emitWorkloadAttesterTrustSource(ctx, tenantID, id, idempotencyKey, requestBinding, req, existing.RotationVersion); err != nil {
			return 0, nil, err
		}
		rec, err := a.store.GetWorkloadAttesterTrustSource(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		if !strings.EqualFold(rec.Name, req.Name) {
			return 0, nil, workloadAttesterTrustSourceNameConflict(req.Name)
		}
		return http.StatusOK, toWorkloadAttesterTrustSourceResponse(rec), nil
	})
}

func (a *API) ensureWorkloadAttesterTrustSourceNameAvailable(ctx context.Context, tenantID, name, allowedID string) error {
	existing, err := a.store.GetWorkloadAttesterTrustSourceByName(ctx, tenantID, name)
	if errors.Is(err, store.ErrWorkloadAttesterTrustSourceNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if existing.ID == allowedID {
		return nil
	}
	return workloadAttesterTrustSourceNameConflict(name)
}

func workloadAttesterTrustSourceNameConflict(name string) error {
	return errStatus(http.StatusConflict,
		"A workload attester trust source named "+strings.TrimSpace(name)+" already exists for this tenant. Choose a different name or update the existing source.")
}

//trstctl:mutation
func (a *API) rotateWorkloadAttesterTrustSource(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	requestBinding, body, err := workloadAttesterTrustRequestBinding(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	defer secret.Wipe(body)
	a.mutateDurableBound(w, r, idempotencyKey, requestBinding, func(ctx context.Context, tenantID string) (int, any, error) {
		if rec, replay, err := a.replayWorkloadAttesterTrustSource(ctx, tenantID, id, idempotencyKey,
			requestBinding, projections.EventWorkloadAttesterTrustSourceRotated); err != nil {
			return 0, nil, err
		} else if replay {
			return http.StatusOK, workloadAttesterTrustSourceRotatedResponse{TrustSource: toWorkloadAttesterTrustSourceResponse(rec)}, nil
		}
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
		if err := a.appendAndProjectWorkloadAttesterTrustSource(ctx, tenantID, id, idempotencyKey, requestBinding,
			projections.EventWorkloadAttesterTrustSourceRotated, payload, false); err != nil {
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
	requestBinding, body, err := workloadAttesterTrustRequestBinding(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	defer secret.Wipe(body)
	a.mutateDurableBound(w, r, idempotencyKey, requestBinding, func(ctx context.Context, tenantID string) (int, any, error) {
		if rec, replay, err := a.replayWorkloadAttesterTrustSource(ctx, tenantID, id, idempotencyKey,
			requestBinding, projections.EventWorkloadAttesterTrustSourceRevoked); err != nil {
			return 0, nil, err
		} else if replay {
			return http.StatusOK, workloadAttesterTrustSourceRevokedResponse{TrustSource: toWorkloadAttesterTrustSourceResponse(rec)}, nil
		}
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
		if err := a.appendAndProjectWorkloadAttesterTrustSource(ctx, tenantID, id, idempotencyKey, requestBinding,
			projections.EventWorkloadAttesterTrustSourceRevoked, payload, true); err != nil {
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
	requestBinding, body, err := workloadAttesterTrustRequestBinding(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	defer secret.Wipe(body)
	a.mutateDurableBound(w, r, idempotencyKey, requestBinding, func(ctx context.Context, tenantID string) (int, any, error) {
		if _, replay, err := a.replayWorkloadAttesterTrustSource(ctx, tenantID, id, idempotencyKey,
			requestBinding, projections.EventWorkloadAttesterTrustSourceDeleted); err != nil {
			return 0, nil, err
		} else if replay {
			return http.StatusNoContent, nil, nil
		}
		if _, err := a.store.GetWorkloadAttesterTrustSource(ctx, tenantID, id); err != nil {
			return 0, nil, err
		}
		payload, err := json.Marshal(projections.WorkloadAttesterTrustSourceDeleted{ID: id})
		if err != nil {
			return 0, nil, err
		}
		if err := a.appendAndProjectWorkloadAttesterTrustSource(ctx, tenantID, id, idempotencyKey, requestBinding,
			projections.EventWorkloadAttesterTrustSourceDeleted, payload, true); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

func (a *API) emitWorkloadAttesterTrustSource(ctx context.Context, tenantID, id, idempotencyKey, requestBinding string, req workloadAttesterTrustSourceRequest, rotationVersion int) error {
	payload, err := json.Marshal(projections.WorkloadAttesterTrustSourceUpserted{
		ID: id, Name: req.Name, Method: req.Method, Issuer: req.Issuer, Audience: req.Audience,
		JWKS: req.JWKS, RootCertsPEM: req.RootCertsPEM, ExpectedNonceBase64: req.ExpectedNonceBase64,
		Enabled: *req.Enabled, RotationVersion: rotationVersion,
		SelfAuthenticating: req.SelfAuthenticating, AllowedOwners: req.AllowedOwners,
	})
	if err != nil {
		return err
	}
	return a.appendAndProjectWorkloadAttesterTrustSource(ctx, tenantID, id, idempotencyKey, requestBinding,
		projections.EventWorkloadAttesterTrustSourceUpserted, payload, !*req.Enabled)
}

func (a *API) appendAndProjectWorkloadAttesterTrustSource(ctx context.Context, tenantID, sourceID, idempotencyKey, requestBinding, eventType string, payload []byte, targetDisabled bool) error {
	if a.store == nil || a.log == nil {
		return errStatus(http.StatusServiceUnavailable, "workload attester trust-source management is not configured")
	}
	tenantUUID, err := googleuuid.Parse(tenantID)
	if err != nil {
		return errStatus(http.StatusUnauthorized, "missing or invalid tenant")
	}
	principal, err := requestPrincipalSubject(ctx)
	if err != nil {
		return err
	}
	if idempotencyKey == "" {
		return errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations")
	}
	bindingMaterial, err := json.Marshal(struct {
		Domain, TenantID, SourceID, IdempotencyKey, EventType, Principal, PayloadSHA256 string
		TargetDisabled                                                                  bool
	}{"trstctl.workload-attester-trust-command.v1", tenantID, sourceID, idempotencyKey,
		eventType, principal, crypto.SHA256Hex(payload), targetDisabled})
	if err != nil {
		return err
	}
	defer secret.Wipe(bindingMaterial)
	eventID := googleuuid.NewSHA1(tenantUUID, []byte("trstctl:workload-attester-trust-command:"+idempotencyKey)).String()
	wanted := events.Event{ID: eventID, Type: eventType, TenantID: tenantID,
		SchemaVersion: events.DefaultSchemaVersion,
		Time:          time.Now().UTC().Truncate(time.Microsecond), Data: payload}
	if actor, ok := events.ActorFromContext(ctx); ok {
		wanted.Actor = &actor
	}
	command, err := a.store.ClaimWorkloadAttesterTrustCommand(ctx, store.WorkloadAttesterTrustCommand{
		SourceID: sourceID, BindingSHA256: crypto.SHA256Hex(bindingMaterial), RequestBinding: requestBinding,
		TargetDisabled: targetDisabled, Event: wanted,
	})
	if err != nil {
		return err
	}
	ev, found, err := a.log.EventByID(ctx, eventID)
	if err != nil {
		return err
	}
	if !found {
		if command.Status != "pending" {
			return errors.New("api: completed attester trust command has no source event")
		}
		ev, err = a.log.Append(ctx, command.Event)
		if err != nil {
			return err
		}
	}
	if ev.ID != eventID || ev.TenantID != tenantID || ev.Type != eventType ||
		ev.SchemaVersion != command.Event.SchemaVersion || !ev.Time.Equal(command.Event.Time) ||
		(command.Status == "pending" && (!crypto.ConstantTimeEqual(ev.Data, command.Event.Data) ||
			!reflect.DeepEqual(ev.Actor, command.Event.Actor))) ||
		(command.Status == "completed" && ev.Sequence != command.Event.Sequence) {
		return store.ErrIdempotencyConflict
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
	req.AllowedOwners = normalizeAllowedOwners(req.AllowedOwners)
	if err := validateSelfAuthenticatingTrustSource(req.Method, req.SelfAuthenticating, req.AllowedOwners); err != nil {
		return workloadAttesterTrustSourceRequest{}, err
	}
	req.JWKS = normalizeJWKSForMethod(req.Method, req.JWKS)
	req.RootCertsPEM = normalizePEMList(req.RootCertsPEM)
	return req, nil
}

// normalizeAllowedOwners lower-cases and de-duplicates GitHub owner pins:
// GitHub treats owner names without regard to case.
func normalizeAllowedOwners(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, v := range values {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// validateSelfAuthenticatingTrustSource (A84) fails closed: only a GitHub OIDC
// token can stand in for an API token, and only for pinned owners. An unpinned
// self-authenticating source would let every repository on GitHub mint under
// this tenant, so it is refused at creation rather than trusted at issuance.
func validateSelfAuthenticatingTrustSource(method string, selfAuthenticating bool, owners []string) error {
	if len(owners) > 0 && method != "github_oidc" {
		return errStatus(http.StatusBadRequest, "allowed_owners applies to github_oidc sources only")
	}
	if !selfAuthenticating {
		return nil
	}
	if method != "github_oidc" {
		return errStatus(http.StatusBadRequest, "self_authenticating is available for github_oidc sources only")
	}
	if len(owners) == 0 {
		return errStatus(http.StatusBadRequest, "a self_authenticating source requires allowed_owners: without the owner pin every repository on GitHub could issue under this tenant")
	}
	return nil
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
	owners := rec.AllowedOwners
	if owners == nil {
		owners = []string{}
	}
	out := workloadAttesterTrustSourceResponse{
		ID: rec.ID, TenantID: rec.TenantID, Name: rec.Name, Method: rec.Method,
		Issuer: rec.Issuer, Audience: rec.Audience, JWKS: jwks, RootCertsPEM: roots,
		ExpectedNonceBase64: rec.ExpectedNonceBase64, Enabled: rec.Enabled,
		SelfAuthenticating: rec.SelfAuthenticating, AllowedOwners: owners,
		AuthorityPending: rec.AuthorityPending,
		RevokedReason:    rec.RevokedReason, RotationVersion: rec.RotationVersion,
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
