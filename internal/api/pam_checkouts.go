// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

// A261 part 2: check-outs of vaulted accounts. A check-out is requested for
// independent review; once approved its requester reveals the account's
// current credential once; checking it in, or its deadline passing, queues
// the rotation that retires that credential.

// PAMCheckoutRequest asks to check out a vaulted target's account.
type PAMCheckoutRequest struct {
	RequestID  string `json:"request_id"`
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	Reason     string `json:"reason"`
	TTLSeconds int    `json:"ttl_seconds"`
	TemplateID string `json:"template_id,omitempty"`
}

// PAMCheckoutRevealRequest reveals an approved check-out with the approval's
// exact ID and intent digest.
type PAMCheckoutRevealRequest struct {
	ApprovalRequestID string `json:"approval_request_id"`
	IntentDigest      string `json:"intent_digest"`
}

// PAMCheckoutReview is a check-out's review: the approval request.
type PAMCheckoutReview struct {
	RequestID         string    `json:"request_id"`
	ApprovalRequestID string    `json:"approval_request_id"`
	IntentDigest      string    `json:"intent_digest"`
	Status            string    `json:"status"`
	ApprovalCount     int       `json:"approval_count"`
	RequiredApprovals int       `json:"required_approvals"`
	ExpiresAt         time.Time `json:"expires_at"`
}

// PAMCheckout is a check-out as recorded; it never holds the credential.
type PAMCheckout struct {
	RequestID         string     `json:"request_id"`
	TargetType        string     `json:"target_type"`
	TargetID          string     `json:"target_id"`
	ProviderID        string     `json:"provider_id"`
	AccountSecret     string     `json:"account_secret"`
	SecretVersion     int        `json:"secret_version"`
	RequestedBy       string     `json:"requested_by"`
	Reason            string     `json:"reason"`
	ApprovalRequestID string     `json:"approval_request_id"`
	RevealedAt        time.Time  `json:"revealed_at"`
	ExpiresAt         time.Time  `json:"expires_at"`
	Status            string     `json:"status"`
	EndedAt           *time.Time `json:"ended_at,omitempty"`
	EndedBy           string     `json:"ended_by,omitempty"`
	RotationCommandID string     `json:"rotation_command_id,omitempty"`
	// Emergency (A272) marks a break-glass release under emergency access:
	// no review, its grant's ID is the request's, every approver notified.
	Emergency bool `json:"emergency,omitempty"`
}

// PAMCheckoutReveal is the one reply that carries the credential.
type PAMCheckoutReveal struct {
	Checkout   PAMCheckout     `json:"checkout"`
	Credential secretJSONBytes `json:"credential"`
}

func (r *PAMCheckoutReveal) wipeSecrets() { r.Credential.wipe() }

// PAMEmergencyCheckout is a break-glass account released once under
// emergency access (A272): the credential (its password and, when the account
// has one, the current TOTP code, never the seed), who holds its hardware
// security keys, and the emergency grant every approver was notified of.
type PAMEmergencyCheckout struct {
	Checkout           PAMCheckout       `json:"checkout"`
	Credential         secretJSONBytes   `json:"credential"`
	HardwareKeyHolders []string          `json:"hardware_key_holders,omitempty"`
	Emergency          PAMEmergencyGrant `json:"emergency"`
}

func (r *PAMEmergencyCheckout) wipeSecrets() { r.Credential.wipe() }

// PAMEmergencyCheckoutService releases break-glass accounts; the served
// broker implements it.
type PAMEmergencyCheckoutService interface {
	OpenPAMEmergencyCheckout(ctx context.Context, tenantID, idempotencyKey, responder string, req PAMCheckoutRequest) (*PAMEmergencyCheckout, error)
}

// PAMCheckoutService is check-out; the served broker implements it.
type PAMCheckoutService interface {
	RequestPAMCheckout(ctx context.Context, tenantID, requester string, req PAMCheckoutRequest) (PAMCheckoutReview, error)
	RevealPAMCheckout(ctx context.Context, tenantID, requester, requestID string, req PAMCheckoutRevealRequest) (*PAMCheckoutReveal, error)
	CheckInPAMCheckout(ctx context.Context, tenantID, actor, requestID string) (PAMCheckout, error)
	ListPAMCheckouts(ctx context.Context, tenantID string) ([]PAMCheckout, error)
	GetPAMCheckout(ctx context.Context, tenantID, requestID string) (PAMCheckout, error)
}

func (a *API) pamCheckoutRoutes() []route {
	request := []param{pathUUID("request_id")}
	return []route{
		{method: "POST", path: "/api/v1/access/checkouts", opID: "requestPAMCheckout", summary: "Request independent review of checking out a vaulted account's credential", handler: a.requestPAMCheckout, reqSchema: "PAMCheckoutRequest", resSchema: "PAMCheckoutReview", successCode: "202", mutation: true, perm: authz.AccessSessionsOpen},
		{method: "POST", path: "/api/v1/access/checkouts/{request_id}/reveal", opID: "revealPAMCheckout", summary: "Reveal an approved check-out's credential once to its requester; checking in or its deadline rotates it", handler: a.revealPAMCheckout, pathParams: request, reqSchema: "PAMCheckoutRevealRequest", resSchema: "PAMCheckoutReveal", successCode: "200", mutation: true, sensitiveResponse: true, perm: authz.AccessSessionsOpen},
		{method: "POST", path: "/api/v1/access/checkouts/{request_id}/checkin", opID: "checkInPAMCheckout", summary: "Check a check-out in (your own with access:sessions.open; anyone's with access:write): the account is rotated so the revealed credential stops working", handler: a.checkInPAMCheckout, pathParams: request, resSchema: "PAMCheckout", successCode: "200", mutation: true, perm: authz.AccessSessionsOpen},
		{method: "GET", path: "/api/v1/access/checkouts", opID: "listPAMCheckouts", summary: "List check-outs of vaulted accounts, newest first", handler: a.listPAMCheckouts, resSchema: "PAMCheckoutList", successCode: "200", perm: authz.AccessRead},
		{method: "GET", path: "/api/v1/access/checkouts/{request_id}", opID: "getPAMCheckout", summary: "Get a check-out", handler: a.getPAMCheckout, pathParams: request, resSchema: "PAMCheckout", successCode: "200", perm: authz.AccessRead},
		{method: "POST", path: "/api/v1/access/emergency-checkouts", opID: "openPAMEmergencyCheckout", summary: "Release a break-glass account's credential once as a named responder, without review: every approver is notified, checking in or its deadline rotates it, and a post-incident review is required", handler: a.openPAMEmergencyCheckout, reqSchema: "PAMCheckoutRequest", resSchema: "PAMEmergencyCheckout", successCode: "201", mutation: true, sensitiveResponse: true, perm: authz.AccessSessionsOpen},
	}
}

//trstctl:mutation
func (a *API) openPAMEmergencyCheckout(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		svc, ok := a.pam.(PAMEmergencyCheckoutService)
		if a.pam == nil || !ok {
			return 0, nil, ErrPAMUnavailable
		}
		var body PAMCheckoutRequest
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		switch {
		case principal.Subject == "":
			return 0, nil, errStatus(http.StatusUnauthorized, "an authenticated responder is required")
		case principal.RunID != "":
			return 0, nil, errStatus(http.StatusForbidden, "an access bundle run cannot open emergency access")
		case principal.Delegated:
			return 0, nil, errStatus(http.StatusForbidden, "a token minted for another principal cannot open emergency access")
		}
		released, err := svc.OpenPAMEmergencyCheckout(ctx, tenantID, r.Header.Get("Idempotency-Key"), principal.Subject, body)
		if err != nil {
			return 0, nil, pamCheckoutNotFound(err)
		}
		return http.StatusCreated, released, nil
	})
}

func (a *API) checkouts() (PAMCheckoutService, error) {
	svc, ok := a.pam.(PAMCheckoutService)
	if a.pam == nil || !ok {
		return nil, ErrPAMUnavailable
	}
	return svc, nil
}

func pamCheckoutNotFound(err error) error {
	if errors.Is(err, store.ErrPAMCheckoutNotFound) {
		return errStatus(http.StatusNotFound, "check-out not found")
	}
	return err
}

//trstctl:mutation
func (a *API) requestPAMCheckout(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		svc, err := a.checkouts()
		if err != nil {
			return 0, nil, err
		}
		var body PAMCheckoutRequest
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		review, err := svc.RequestPAMCheckout(ctx, tenantID, principalSubject(ctx), body)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, review, nil
	})
}

//trstctl:mutation
func (a *API) revealPAMCheckout(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		svc, err := a.checkouts()
		if err != nil {
			return 0, nil, err
		}
		var body PAMCheckoutRevealRequest
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		revealed, err := svc.RevealPAMCheckout(ctx, tenantID, principalSubject(ctx), r.PathValue("request_id"), body)
		if err != nil {
			return 0, nil, pamCheckoutNotFound(err)
		}
		return http.StatusOK, revealed, nil
	})
}

//trstctl:mutation
func (a *API) checkInPAMCheckout(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		svc, err := a.checkouts()
		if err != nil {
			return 0, nil, err
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		if principal.Subject == "" {
			return 0, nil, errStatus(http.StatusUnauthorized, "an authenticated principal is required")
		}
		id := strings.TrimSpace(r.PathValue("request_id"))
		if !principal.Can(authz.AccessWrite, authz.Scope{TenantID: tenantID}) {
			// access:sessions.open checks in the caller's own check-outs only;
			// another principal's needs access:write.
			current, err := svc.GetPAMCheckout(ctx, tenantID, id)
			if err != nil {
				return 0, nil, pamCheckoutNotFound(err)
			}
			if current.RequestedBy != principal.Subject {
				return 0, nil, errStatus(http.StatusForbidden, "access:sessions.open checks in your own check-outs; another principal's needs access:write")
			}
		}
		checkout, err := svc.CheckInPAMCheckout(ctx, tenantID, principal.Subject, id)
		if err != nil {
			return 0, nil, pamCheckoutNotFound(err)
		}
		return http.StatusOK, checkout, nil
	})
}

func (a *API) listPAMCheckouts(w http.ResponseWriter, r *http.Request) {
	svc, err := a.checkouts()
	if err != nil {
		a.writePAMError(w, err)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	items, err := svc.ListPAMCheckouts(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *API) getPAMCheckout(w http.ResponseWriter, r *http.Request) {
	svc, err := a.checkouts()
	if err != nil {
		a.writePAMError(w, err)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	checkout, err := svc.GetPAMCheckout(r.Context(), tenantID, r.PathValue("request_id"))
	if err != nil {
		a.writeError(w, pamCheckoutNotFound(err))
		return
	}
	a.writeJSON(w, http.StatusOK, checkout)
}
