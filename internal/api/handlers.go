package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// ---- DTOs -----------------------------------------------------------------

type ownerRequest struct {
	Kind  string `json:"kind"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type ownerResponse struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Kind      string    `json:"kind"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

func toOwnerResponse(o store.Owner) ownerResponse {
	return ownerResponse{ID: o.ID, TenantID: o.TenantID, Kind: string(o.Kind), Name: o.Name, Email: o.Email, CreatedAt: o.CreatedAt}
}

type issuerRequest struct {
	Kind      string   `json:"kind"`
	Name      string   `json:"name"`
	Chain     []string `json:"chain"`
	PublicKey string   `json:"public_key"`
	Internal  bool     `json:"internal"`
}

type issuerResponse struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Kind      string    `json:"kind"`
	Name      string    `json:"name"`
	Chain     []string  `json:"chain"`
	PublicKey string    `json:"public_key"`
	Internal  bool      `json:"internal"`
	Chainless bool      `json:"chainless"`
	CreatedAt time.Time `json:"created_at"`
}

func toIssuerResponse(i store.Issuer) issuerResponse {
	return issuerResponse{
		ID: i.ID, TenantID: i.TenantID, Kind: string(i.Kind), Name: i.Name,
		Chain: i.Chain, PublicKey: i.PublicKey, Internal: i.Internal,
		Chainless: i.Chainless(), CreatedAt: i.CreatedAt,
	}
}

type identityRequest struct {
	Kind       string          `json:"kind"`
	Name       string          `json:"name"`
	OwnerID    string          `json:"owner_id"`
	IssuerID   string          `json:"issuer_id"`
	Attributes json.RawMessage `json:"attributes"`
}

type identityResponse struct {
	ID         string          `json:"id"`
	TenantID   string          `json:"tenant_id"`
	Kind       string          `json:"kind"`
	Name       string          `json:"name"`
	OwnerID    string          `json:"owner_id"`
	IssuerID   *string         `json:"issuer_id"`
	Status     string          `json:"status"`
	NotBefore  *time.Time      `json:"not_before"`
	NotAfter   *time.Time      `json:"not_after"`
	Attributes json.RawMessage `json:"attributes"`
	CreatedAt  time.Time       `json:"created_at"`
}

func toIdentityResponse(it store.Identity) identityResponse {
	attrs := it.Attributes
	if len(attrs) == 0 {
		attrs = json.RawMessage("{}")
	}
	return identityResponse{
		ID: it.ID, TenantID: it.TenantID, Kind: string(it.Kind), Name: it.Name,
		OwnerID: it.OwnerID, IssuerID: it.IssuerID, Status: it.Status,
		NotBefore: it.NotBefore, NotAfter: it.NotAfter, Attributes: attrs, CreatedAt: it.CreatedAt,
	}
}

type transitionRequest struct {
	To     string `json:"to"`
	Reason string `json:"reason"`
}

func validateTransitionRequest(req transitionRequest) error {
	return canonicalizeTransitionRequest(&req)
}

func canonicalizeTransitionRequest(req *transitionRequest) error {
	if orchestrator.State(req.To) != orchestrator.StateRevoked {
		return nil
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		req.Reason = string(crypto.RevocationReasonUnspecified)
		return nil
	}
	if !crypto.IsValidRevocationReason(reason) {
		return errStatus(http.StatusBadRequest, "invalid revocation reason: use an RFC 5280 reason such as keyCompromise or unspecified")
	}
	req.Reason = reason
	return nil
}

type listResponse struct {
	Items      any    `json:"items"`
	NextCursor string `json:"next_cursor"`
}

// ---- owners ---------------------------------------------------------------

//trstctl:mutation
func (a *API) createOwner(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req ownerRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		o, err := a.orch.CreateOwner(ctx, tenantID, req.Kind, req.Name, req.Email)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toOwnerResponse(o), nil
	})
}

func (a *API) getOwner(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	o, err := a.store.GetOwner(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toOwnerResponse(o))
}

func (a *API) listOwners(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, after, err := a.pageParams(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	owners, err := a.store.ListOwnersPage(r.Context(), tenantID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]ownerResponse, 0, len(owners))
	for _, o := range owners {
		items = append(items, toOwnerResponse(o))
	}
	next := ""
	if len(owners) == limit {
		next = encodeCursor(owners[len(owners)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

//trstctl:mutation
func (a *API) updateOwner(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req ownerRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if err := a.orch.UpdateOwner(ctx, tenantID, id, req.Kind, req.Name, req.Email); err != nil {
			return 0, nil, err
		}
		updated, err := a.store.GetOwner(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, toOwnerResponse(updated), nil
	})
}

//trstctl:mutation
func (a *API) deleteOwner(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if err := a.orch.DeleteOwner(ctx, tenantID, id); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

// ---- issuers --------------------------------------------------------------

//trstctl:mutation
func (a *API) createIssuer(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req issuerRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		iss := store.Issuer{TenantID: tenantID, Kind: store.IssuerKind(req.Kind), Name: req.Name, Chain: req.Chain, PublicKey: req.PublicKey, Internal: req.Internal}
		if err := iss.Validate(); err != nil {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, err.Error())
		}
		created, err := a.orch.CreateIssuer(ctx, tenantID, iss)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toIssuerResponse(created), nil
	})
}

func (a *API) getIssuer(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	i, err := a.store.GetIssuer(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toIssuerResponse(i))
}

func (a *API) listIssuers(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, after, err := a.pageParams(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	issuers, err := a.store.ListIssuersPage(r.Context(), tenantID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]issuerResponse, 0, len(issuers))
	for _, i := range issuers {
		items = append(items, toIssuerResponse(i))
	}
	next := ""
	if len(issuers) == limit {
		next = encodeCursor(issuers[len(issuers)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

// ---- identities -----------------------------------------------------------

//trstctl:mutation
func (a *API) createIdentity(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req identityRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if req.OwnerID == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "owner_id is required")
		}
		if _, err := a.store.GetOwner(ctx, tenantID, req.OwnerID); err != nil {
			if store.IsNotFound(err) {
				return 0, nil, errStatus(http.StatusUnprocessableEntity, "owner_id does not reference an existing owner")
			}
			return 0, nil, err
		}
		var issuerID *string
		if req.IssuerID != "" {
			if _, err := a.store.GetIssuer(ctx, tenantID, req.IssuerID); err != nil {
				if store.IsNotFound(err) {
					return 0, nil, errStatus(http.StatusUnprocessableEntity, "issuer_id does not reference an existing issuer")
				}
				return 0, nil, err
			}
			issuerID = &req.IssuerID
		}
		created, err := a.orch.CreateIdentity(ctx, tenantID, store.Identity{
			Kind: store.IdentityKind(req.Kind), Name: req.Name,
			OwnerID: req.OwnerID, IssuerID: issuerID, Attributes: req.Attributes,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toIdentityResponse(created), nil
	})
}

func (a *API) getIdentity(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	it, err := a.store.GetIdentity(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toIdentityResponse(it))
}

func (a *API) listIdentities(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, after, err := a.pageParams(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	idents, err := a.store.ListIdentitiesPage(r.Context(), tenantID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]identityResponse, 0, len(idents))
	for _, it := range idents {
		items = append(items, toIdentityResponse(it))
	}
	next := ""
	if len(idents) == limit {
		next = encodeCursor(idents[len(idents)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

//trstctl:mutation
func (a *API) transitionIdentity(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req transitionRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if err := canonicalizeTransitionRequest(&req); err != nil {
			return 0, nil, err
		}
		// EXC-WIRE-03: enforce the served policy / RA-separation / dual-control gate
		// BEFORE the orchestrator records the transition and enqueues the mint/revoke
		// outbox effect. This is the seam where the authenticated principal is in
		// context, which the RA scope split (certs:issue) and the distinct-approver
		// check require. The gate is fail-closed; the zero gate is a no-op. Doing this
		// inside the idempotency closure means a denial is the recorded result for the
		// key (a replay re-denies, never silently mints — AN-5).
		var resourceAttrs map[string]string
		if a.gate.ABAC != nil {
			var err error
			resourceAttrs, err = a.identityABACResourceAttrs(ctx, tenantID, id)
			if err != nil {
				return 0, nil, err
			}
			resourceAttrs["transition.to"] = req.To
		}
		state := orchestrator.State(req.To)
		gate := a.gate
		if state == orchestrator.StateIssued && a.orch != nil {
			profileReq, err := a.orch.ProfileApprovalRequirement(ctx, tenantID, id)
			if err != nil {
				return 0, nil, err
			}
			gate = gateWithProfileApproval(gate, profileReq)
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		if err := gate.check(ctx, principal, tenantID, id, state, resourceAttrs); err != nil {
			var ge *gateError
			if errors.As(err, &ge) {
				return 0, nil, errStatus(ge.status, ge.detail)
			}
			return 0, nil, err
		}
		// Per-feature telemetry (COVER-009): time the served lifecycle operation
		// (issuance/revocation/deployment) and record a non-sensitive feature/action/
		// outcome signal. The labels come from a closed catalog map, never tenant or
		// credential data.
		start := time.Now()
		terr := a.orch.Transition(ctx, tenantID, id, state, req.Reason)
		if feature, action, ok := transitionFeatureAction(state); ok {
			a.observeFeature(feature, action, start, terr)
		}
		if terr != nil {
			return 0, nil, terr
		}
		updated, err := a.store.GetIdentity(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, toIdentityResponse(updated), nil
	})
}

func (a *API) identityABACResourceAttrs(ctx context.Context, tenantID, id string) (map[string]string, error) {
	it, err := a.store.GetIdentity(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	out := map[string]string{
		"identity.id":     it.ID,
		"identity.kind":   string(it.Kind),
		"identity.name":   it.Name,
		"identity.status": it.Status,
		"owner_id":        it.OwnerID,
	}
	if len(it.Attributes) > 0 {
		var attrs map[string]any
		if err := json.Unmarshal(it.Attributes, &attrs); err == nil {
			flattenABACResource("", attrs, out)
		}
	}
	return out, nil
}

func flattenABACResource(prefix string, attrs map[string]any, out map[string]string) {
	for k, v := range attrs {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch x := v.(type) {
		case map[string]any:
			flattenABACResource(key, x, out)
		case string:
			out[key] = x
		case bool, float64, json.Number:
			out[key] = fmt.Sprint(x)
		}
	}
}
