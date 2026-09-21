// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"context"
	"encoding/json"
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
	Kind            string   `json:"kind"`
	Name            string   `json:"name"`
	Email           string   `json:"email"`
	ApplicationID   string   `json:"application_id"`
	Service         string   `json:"service"`
	BusinessUnit    string   `json:"business_unit"`
	Environment     string   `json:"environment"`
	EscalationChain []string `json:"escalation_chain"`
}

type ownerResponse struct {
	ID                        string     `json:"id"`
	TenantID                  string     `json:"tenant_id"`
	Kind                      string     `json:"kind"`
	Name                      string     `json:"name"`
	Email                     string     `json:"email"`
	CreatedAt                 time.Time  `json:"created_at"`
	ApplicationID             string     `json:"application_id,omitempty"`
	Service                   string     `json:"service,omitempty"`
	BusinessUnit              string     `json:"business_unit,omitempty"`
	Environment               string     `json:"environment,omitempty"`
	EscalationChain           []string   `json:"escalation_chain"`
	OwnershipVerifiedAt       *time.Time `json:"ownership_verified_at,omitempty"`
	OwnershipVerifiedBy       string     `json:"ownership_verified_by,omitempty"`
	OwnershipComplete         bool       `json:"ownership_complete"`
	OwnershipAttested         bool       `json:"ownership_attested"`
	OwnershipCurrent          bool       `json:"ownership_current"`
	OwnershipAttestationDueAt *time.Time `json:"ownership_attestation_due_at,omitempty"`

	// Where this ownership claim came from (I2). Empty means UNKNOWN — the row
	// predates provenance — and is deliberately not rendered as "manual": an
	// unrecorded origin is not evidence that a human said so. Omitted rather
	// than sent empty so a client cannot mistake absence for an answer.
	OwnershipSource           string `json:"ownership_source,omitempty"`
	OwnershipSourceRef        string `json:"ownership_source_ref,omitempty"`
	OwnershipSourceObservedAt string `json:"ownership_source_observed_at,omitempty"`
}

func (a *API) toOwnerResponse(o store.Owner) ownerResponse {
	chain, _ := store.OwnerEscalationChain(o.EscalationChain)
	cadence := a.ownerAttestationCadence()
	out := ownerResponse{
		ID: o.ID, TenantID: o.TenantID, Kind: string(o.Kind), Name: o.Name, Email: o.Email, CreatedAt: o.CreatedAt,
		ApplicationID: o.ApplicationID, Service: o.Service, BusinessUnit: o.BusinessUnit,
		Environment: o.Environment, EscalationChain: chain,
		OwnershipVerifiedAt: o.OwnershipVerifiedAt, OwnershipVerifiedBy: o.OwnershipVerifiedBy,
		OwnershipComplete: o.OwnershipComplete(), OwnershipAttested: o.OwnershipAttested(),
		OwnershipCurrent:          o.OwnershipCurrent(time.Now().UTC(), cadence),
		OwnershipAttestationDueAt: o.OwnershipAttestationDueAt(cadence),
	}
	out.OwnershipSource = o.OwnershipSource
	out.OwnershipSourceRef = o.OwnershipSourceRef
	if o.OwnershipSourceObservedAt != nil {
		out.OwnershipSourceObservedAt = o.OwnershipSourceObservedAt.UTC().Format(time.RFC3339)
	}
	return out
}

func (a *API) ownerAttestationCadence() time.Duration {
	if a.ownershipAttestationCadence > 0 {
		return a.ownershipAttestationCadence
	}
	return store.DefaultOwnershipAttestationCadence
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
	reviewedIdentity *store.Identity
	To               string  `json:"to"`
	Reason           string  `json:"reason"`
	ExpectedVersion  *uint64 `json:"expected_version,omitempty"`
	// SubjectCSRPEM lets the caller supply their own PKCS#10 request on a
	// transition to issued (epic B1). When present the control plane signs that
	// request and generates no key, so the subject private key stays wherever the
	// caller made it and never reaches this process.
	//
	// Absent keeps the legacy behavior — the control plane generates the subject
	// key — which is deprecated, records an `issuance.server_side_keygen` event
	// each time it runs, and is retained for one release train.
	SubjectCSRPEM string `json:"subject_csr_pem,omitempty"`
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
		chain, err := json.Marshal(req.EscalationChain)
		if err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		o, err := a.orch.CreateOwnerRecord(ctx, store.Owner{
			TenantID: tenantID, Kind: store.OwnerKind(req.Kind), Name: req.Name, Email: req.Email,
			ApplicationID: req.ApplicationID, Service: req.Service, BusinessUnit: req.BusinessUnit,
			Environment: req.Environment, EscalationChain: chain,
		})
		if err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		return http.StatusCreated, a.toOwnerResponse(o), nil
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
	a.writeJSON(w, http.StatusOK, a.toOwnerResponse(o))
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
		items = append(items, a.toOwnerResponse(o))
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
		chain, err := json.Marshal(req.EscalationChain)
		if err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		updated, err := a.orch.UpdateOwnerRecord(ctx, store.Owner{
			ID: id, TenantID: tenantID, Kind: store.OwnerKind(req.Kind), Name: req.Name, Email: req.Email,
			ApplicationID: req.ApplicationID, Service: req.Service, BusinessUnit: req.BusinessUnit,
			Environment: req.Environment, EscalationChain: chain,
		})
		if err != nil {
			if store.IsNotFound(err) {
				return 0, nil, err
			}
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		return http.StatusOK, a.toOwnerResponse(updated), nil
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
		ownerID, err := validateOwnerID(req.OwnerID)
		if err != nil {
			return 0, nil, err
		}
		req.OwnerID = ownerID
		if err := validateIdentityRequest(req); err != nil {
			return 0, nil, err
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

func validateIdentityRequest(req identityRequest) error {
	if store.IdentityKind(req.Kind) != store.KindX509Certificate {
		return nil
	}
	return validateWildcardIdentityPolicy(req.Name, req.Attributes)
}

func validateWildcardIdentityPolicy(name string, attrs json.RawMessage) error {
	if !strings.HasPrefix(strings.TrimSpace(name), "*.") {
		return nil
	}
	raw := bytes.TrimSpace(attrs)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		raw = []byte("{}")
	}
	var values map[string]any
	if err := json.Unmarshal(raw, &values); err != nil {
		return errWithStatus(http.StatusBadRequest, err)
	}
	ack, _ := values["wildcard_blast_radius_acknowledged"].(bool)
	if !ack {
		return errStatus(http.StatusBadRequest, "wildcard X.509 identities require wildcard_blast_radius_acknowledged=true")
	}
	method, _ := values["validation_method"].(string)
	if strings.ToLower(strings.TrimSpace(method)) != "dns-01" {
		return errStatus(http.StatusBadRequest, "wildcard X.509 identities require validation_method=dns-01")
	}
	return nil
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
	var req transitionRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if err := canonicalizeTransitionRequest(&req); err != nil {
		a.writeError(w, err)
		return
	}
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	binding, err := identityTransitionRequestBinding(principal.Subject, id, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		return a.executeIdentityTransition(ctx, tenantID, principal, id, req, idempotencyKey)
	})
}

func identityTransitionAttemptDigests(idempotencyKey, csrPEM string) (idempotencyKeyDigest, subjectCSRDigest string) {
	idempotencyKeyDigest = crypto.SHA256Hex([]byte(idempotencyKey))
	if csrPEM != "" {
		subjectCSRDigest = crypto.SHA256Hex([]byte(csrPEM))
	}
	return idempotencyKeyDigest, subjectCSRDigest
}

func identityTransitionApprovalEvidence(idempotencyKeyDigest, subjectCSRDigest, profile string, issuance *store.OperationApprovalIssuanceBinding) ([]string, error) {
	// The approval is one attempt, not a standing permission for every later
	// identical-looking transition. A retry with the same raw AN-5 key maps to the
	// same immutable request; a fresh key has different evidence. Only non-secret
	// digests and the public profile label are durable.
	evidenceRefs := []string{"idempotency-key-sha256:" + idempotencyKeyDigest}
	if issuance != nil {
		bound, err := issuance.EvidenceRefs()
		if err != nil {
			return nil, err
		}
		evidenceRefs = append(evidenceRefs, bound...)
	} else if profile != "" {
		evidenceRefs = append(evidenceRefs, "profile:"+profile)
	}
	if subjectCSRDigest != "" {
		evidenceRefs = append(evidenceRefs, "csr-sha256:"+subjectCSRDigest)
	}
	return evidenceRefs, nil
}

// replayConsumedIdentityTransition closes the receiver-commit/HTTP-result crash
// gap. It finds only an already-consumed approval whose immutable requester/body/
// evidence matches this exact attempt, then asks the orchestrator to validate the
// deterministic consumed event ID. It never turns pending or generic consumed
// authority into a fresh lifecycle mutation.
func (a *API) replayConsumedIdentityTransition(
	ctx context.Context,
	tenantID, identityID, requester string,
	to orchestrator.State,
	reason, idempotencyKey, csrPEM string,
	idempotencyKeyDigest, subjectCSRDigest string,
) (bool, error) {
	if a.orch == nil {
		return false, nil
	}
	action, privileged, ok := privilegedActionFor(to)
	if !ok || !privileged {
		return false, nil
	}
	request, found, err := a.store.ConsumedOperationApprovalForAttempt(ctx, tenantID, store.OperationApprovalAttempt{
		ResourceKind: "identity", ResourceID: identityID,
		Action: string(action), Requester: requester, ToState: string(to),
		Reason: reason, IdempotencyKeyDigest: idempotencyKeyDigest,
		SubjectCSRDigest: subjectCSRDigest,
	})
	if err != nil || !found {
		return false, err
	}
	approval, err := store.OperationApprovalUseFromRequest(request)
	if err != nil {
		return false, err
	}
	if err := a.orch.TransitionWithSubjectCSRAndApproval(ctx, tenantID, identityID, to,
		reason, idempotencyKey, csrPEM, approval); err != nil {
		return false, err
	}
	return true, nil
}

func identityTransitionRequestBinding(principal, identityID string, request transitionRequest) (string, error) {
	raw, err := json.Marshal(struct {
		Domain     string            `json:"domain"`
		Principal  string            `json:"principal"`
		IdentityID string            `json:"identity_id"`
		Request    transitionRequest `json:"request"`
	}{Domain: "trstctl.api.identity-transition.v2", Principal: principal, IdentityID: identityID, Request: request})
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(raw), nil
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

// validateSubjectCSRPEM rejects a caller-supplied certificate request that is not
// a well-formed, self-signed PKCS#10 (epic B1). Parsing goes through the crypto
// boundary (AN-3); this package names no crypto/* itself.
//
// The check is deliberately at the API edge. A CSR that cannot be parsed is a
// caller mistake and belongs in the response to the request that carried it —
// not surfaced minutes later as a failed outbox delivery nobody is watching.
func validateSubjectCSRPEM(csrPEM string) error {
	_, _, err := crypto.ParsePublicCSRPEM([]byte(csrPEM))
	if err != nil {
		return fmt.Errorf("subject_csr_pem: %w", err)
	}
	return nil
}
