// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// A95: the customer's side of Provider emergency access.
//
// A Provider's break-glass grant is approved by two Provider custodians. A
// customer that wants a say sets a policy requiring its own consent; the
// Provider's requests then appear here (projected from the Provider's own
// authority event under this tenant) and the customer's people approve or
// deny each one by grant id. The Provider plane reads the decisions under this
// tenant's RLS before it hands over the emergency result.

type providerAccessPolicyBody struct {
	RequireTenantConsent bool `json:"require_tenant_consent"`
	Approvals            int  `json:"approvals,omitempty"`
}

type providerAccessPolicyResponse struct {
	Configured           bool   `json:"configured"`
	RequireTenantConsent bool   `json:"require_tenant_consent"`
	Approvals            int    `json:"approvals"`
	SetBy                string `json:"set_by,omitempty"`
	SetAt                string `json:"set_at,omitempty"`
	Guidance             string `json:"guidance"`
}

type providerAccessRequestResponse struct {
	GrantID       string `json:"grant_id"`
	OperatorEmail string `json:"operator_email"`
	Reason        string `json:"reason"`
	RequestedAt   string `json:"requested_at"`
	ExpiresAt     string `json:"expires_at"`
	Approvals     int    `json:"approvals"`
	Denied        bool   `json:"denied"`
}

type providerAccessConsentBody struct {
	Approve bool   `json:"approve"`
	Reason  string `json:"reason,omitempty"`
}

type providerAccessConsentResponse struct {
	GrantID   string `json:"grant_id"`
	Subject   string `json:"subject"`
	Approve   bool   `json:"approve"`
	Reason    string `json:"reason,omitempty"`
	DecidedAt string `json:"decided_at"`
}

const providerAccessGuidance = "Provider emergency access is approved by two Provider custodians. With " +
	"require_tenant_consent on, the Provider can use a grant only after this tenant has recorded the " +
	"configured number of distinct approvals and no denial for that grant id; the Provider shares the " +
	"grant id, and each decision is an immutable event in this tenant's own history."

func providerAccessPolicyFrom(p store.ProviderAccessPolicy, found bool) providerAccessPolicyResponse {
	out := providerAccessPolicyResponse{Configured: found, RequireTenantConsent: p.RequireTenantConsent, Approvals: p.Approvals, SetBy: p.SetBy, Guidance: providerAccessGuidance}
	if !found {
		out.Approvals = 2
	}
	if !p.SetAt.IsZero() {
		out.SetAt = p.SetAt.UTC().Format(time.RFC3339)
	}
	return out
}

func (a *API) getProviderAccessPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	policy, found, err := a.store.ProviderAccessPolicyFor(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, providerAccessPolicyFrom(policy, found))
}

//trstctl:mutation
func (a *API) putProviderAccessPolicy(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var body providerAccessPolicyBody
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if body.Approvals < 0 || body.Approvals > 10 {
			return 0, nil, errStatus(http.StatusBadRequest, "approvals must be between 1 and 10")
		}
		set, err := a.orch.SetProviderAccessPolicy(ctx, tenantID, body.RequireTenantConsent, body.Approvals, principalSubject(ctx))
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, providerAccessPolicyFrom(store.ProviderAccessPolicy{TenantID: tenantID, RequireTenantConsent: set.RequireTenantConsent, Approvals: set.Approvals, SetBy: set.SetBy, SetAt: set.SetAt}, true), nil
	})
}

func (a *API) listProviderAccessRequests(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	requests, err := a.store.ProviderAccessRequestsFor(r.Context(), tenantID, time.Now().UTC())
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]providerAccessRequestResponse, 0, len(requests))
	for _, req := range requests {
		item := providerAccessRequestResponse{GrantID: req.GrantID, OperatorEmail: req.OperatorEmail, Reason: req.Reason,
			RequestedAt: req.RequestedAt.UTC().Format(time.RFC3339), ExpiresAt: req.ExpiresAt.UTC().Format(time.RFC3339)}
		consents, err := a.store.ProviderAccessConsentsFor(r.Context(), tenantID, req.GrantID)
		if err != nil {
			a.writeError(w, err)
			return
		}
		for _, c := range consents {
			if c.Approve {
				item.Approvals++
			} else {
				item.Denied = true
			}
		}
		items = append(items, item)
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *API) listProviderAccessConsents(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	consents, err := a.store.ProviderAccessConsentsFor(r.Context(), tenantID, strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]providerAccessConsentResponse, 0, len(consents))
	for _, c := range consents {
		items = append(items, providerAccessConsentResponse{GrantID: c.GrantID, Subject: c.Subject, Approve: c.Approve, Reason: c.Reason, DecidedAt: c.DecidedAt.UTC().Format(time.RFC3339)})
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

//trstctl:mutation
func (a *API) consentProviderAccess(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var body providerAccessConsentBody
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		decided, err := a.orch.ConsentProviderAccess(ctx, tenantID, r.PathValue("id"), principalSubject(ctx), body.Approve, body.Reason)
		switch {
		case errors.Is(err, orchestrator.ErrProviderAccessReasonRequired):
			return 0, nil, errStatus(http.StatusBadRequest, "a denial needs a reason; the Provider reads it")
		case errors.Is(err, orchestrator.ErrProviderAccessClosed):
			return 0, nil, errStatus(http.StatusNotFound, "no open Provider emergency request carries this grant id for this tenant; the Provider's request appears here once recorded and until it expires")
		case errors.Is(err, orchestrator.ErrProviderAccessDecided):
			return 0, nil, errStatus(http.StatusConflict, "this subject already decided on the grant; a decision is recorded once and is not revised")
		case err != nil:
			return 0, nil, err
		}
		return http.StatusCreated, providerAccessConsentResponse{GrantID: decided.GrantID, Subject: decided.Subject, Approve: decided.Approve, Reason: decided.Reason, DecidedAt: decided.DecidedAt.UTC().Format(time.RFC3339)}, nil
	})
}
