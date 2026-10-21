// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// The ACME External Account Binding operator surface (epic B4).
//
// EAB credentials were configuration and nothing else: an operator could see the
// kids in a config file and had no way to ask what any of them had done, or to
// stop one. A leaked credential meant editing config and restarting, on every
// node, while the credential kept working.
//
// This is the read view and the one operational verb. The read view carries scope,
// quota, window, and what has been taken under each credential — never the HMAC
// key, which stays byte-backed in locked memory where configuration put it (AN-8).
// The verb switches a credential off at runtime so new accounts and new orders
// stop immediately; certificates already issued under it are untouched, because
// a disabled credential is a closed tap, not a revocation.
//
// Rotation is served without minting a secret (A50/A54). Minting an EAB
// credential over HTTP would mean returning a shared MAC secret in a response
// body, so the served rotation takes a reference into the tenant secret store
// instead: the operator writes the successor MAC key there first, then
// `POST .../{kid}/rotate` registers the successor under that reference with the
// predecessor's policy, and the predecessor is disabled here once clients have
// migrated. The policy itself is served too (A53): `PUT .../{kid}/policy`
// replaces a credential's scope, quota, window and profile at runtime. Both are
// recorded in the ACME state log and survive a restart.

// ACMEEABCredential is the served, secret-free view of one external account
// credential.
type ACMEEABCredential struct {
	KeyID              string     `json:"key_id"`
	State              string     `json:"state"`
	Reason             string     `json:"reason,omitempty"`
	AllowedIdentifiers []string   `json:"allowed_identifiers,omitempty"`
	MaxOrders          int        `json:"max_orders,omitempty"`
	NotAfter           *time.Time `json:"not_after,omitempty"`
	AccountsBound      int        `json:"accounts_bound"`
	OrdersCreated      int        `json:"orders_created"`
	OrdersDenied       int        `json:"orders_denied"`
	DisabledInConfig   bool       `json:"disabled_in_config"`
	DisabledByOperator bool       `json:"disabled_by_operator"`
	LastUsedAt         *time.Time `json:"last_used_at,omitempty"`
	// Profile pins the certificate profile every order under the credential is
	// issued with (A55); empty means the tenant default.
	Profile string `json:"profile,omitempty"`
	// HMACKeyRef names the secret-store reference a rotated credential's MAC
	// key was read from (A54). A reference, never the key.
	HMACKeyRef string `json:"hmac_key_ref,omitempty"`
}

// ACMEEABPolicyUpdate is the served policy an operator sets on one credential
// (A53). It replaces the credential's scope, quota, window and profile; an
// absent list means unscoped, zero means no quota, a nil time means no window.
type ACMEEABPolicyUpdate struct {
	AllowedIdentifiers []string   `json:"allowed_identifiers,omitempty"`
	MaxOrders          int        `json:"max_orders,omitempty"`
	NotAfter           *time.Time `json:"not_after,omitempty"`
	Profile            string     `json:"profile,omitempty"`
}

// ACMEEABRotationRequest registers a successor credential (A50/A54). The MAC
// key is a secret:// reference the operator wrote to the tenant secret store
// beforehand; the request never carries the key.
type ACMEEABRotationRequest struct {
	SuccessorKeyID string `json:"successor_key_id"`
	HMACKeyRef     string `json:"hmac_key_ref"`
}

// ACMEEABPosture is the served EAB view for a tenant. Served separates "the ACME
// server is not mounted" from "it is mounted and has no credentials", because an
// operator reading an empty list needs to know which of the two they are looking
// at.
type ACMEEABPosture struct {
	Served      bool                `json:"served"`
	Required    bool                `json:"required"`
	GeneratedAt time.Time           `json:"generated_at"`
	Items       []ACMEEABCredential `json:"items"`
}

// ACMEEABProvider reads the mounted ACME server's credential state for a tenant.
// It is evaluated at request time because API construction intentionally precedes
// protocol construction.
type ACMEEABProvider func(ctx context.Context, tenantID string) (ACMEEABPosture, error)

// ACMEEABDisabler applies the operator's runtime enable/disable decision and
// returns the credential's resulting state. ok is false when no such credential
// is configured on this tenant's mount.
type ACMEEABDisabler func(ctx context.Context, tenantID, keyID string, disabled bool) (ACMEEABCredential, bool, error)

// ACMEEABPolicyUpdater replaces one credential's served policy (A53). ok is
// false when no such credential is on this tenant's mount.
type ACMEEABPolicyUpdater func(ctx context.Context, tenantID, keyID string, update ACMEEABPolicyUpdate) (ACMEEABCredential, bool, error)

// ACMEEABRotator registers a successor credential from a secret reference
// (A50/A54). ok is false when the predecessor is not on this tenant's mount.
type ACMEEABRotator func(ctx context.Context, tenantID, keyID string, req ACMEEABRotationRequest) (ACMEEABCredential, bool, error)

// WithACMEEAB wires the assembled ACME server's external-account-binding state
// into the always-registered routes.
func WithACMEEAB(provider ACMEEABProvider, disabler ACMEEABDisabler, policy ACMEEABPolicyUpdater, rotate ACMEEABRotator) Option {
	return func(c *config) {
		c.acmeEAB = provider
		c.acmeEABDisable = disabler
		c.acmeEABPolicy = policy
		c.acmeEABRotate = rotate
	}
}

//trstctl:mutation
func (a *API) updateACMEEABPolicy(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	keyID := strings.TrimSpace(r.PathValue("kid"))
	var update ACMEEABPolicyUpdate
	if err := decodeJSON(r, &update); err != nil {
		a.writeError(w, err)
		return
	}
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.acmeEABPolicy == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "ACME external account binding state is not assembled")
		}
		if keyID == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "external account credential key id is required")
		}
		if update.MaxOrders < 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "max_orders must be zero (no quota) or positive")
		}
		for _, id := range update.AllowedIdentifiers {
			if strings.TrimSpace(id) == "" {
				return 0, nil, errStatus(http.StatusBadRequest, "allowed_identifiers must not contain an empty identifier")
			}
		}
		credential, ok, err := a.acmeEABPolicy(ctx, tenantID, keyID, update)
		if err != nil {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, err.Error())
		}
		if !ok {
			return 0, nil, errStatus(http.StatusNotFound, "no external account credential with that key id is configured for this tenant")
		}
		return http.StatusOK, credential, nil
	})
}

//trstctl:mutation
func (a *API) rotateACMEEABCredential(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	keyID := strings.TrimSpace(r.PathValue("kid"))
	var req ACMEEABRotationRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, err)
		return
	}
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.acmeEABRotate == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "ACME external account binding state is not assembled")
		}
		if keyID == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "external account credential key id is required")
		}
		if strings.TrimSpace(req.SuccessorKeyID) == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "successor_key_id is required")
		}
		if !strings.HasPrefix(strings.TrimSpace(req.HMACKeyRef), "secret://") {
			return 0, nil, errStatus(http.StatusBadRequest, "hmac_key_ref must be a secret:// reference into the tenant secret store; the key itself is never accepted here")
		}
		credential, ok, err := a.acmeEABRotate(ctx, tenantID, keyID, req)
		if err != nil {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, err.Error())
		}
		if !ok {
			return 0, nil, errStatus(http.StatusNotFound, "no external account credential with that key id is configured for this tenant")
		}
		return http.StatusCreated, credential, nil
	})
}

func (a *API) listACMEEABCredentials(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.acmeEAB == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "ACME external account binding state is not assembled"))
		return
	}
	posture, err := a.acmeEAB(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if posture.Items == nil {
		posture.Items = []ACMEEABCredential{}
	}
	if posture.GeneratedAt.IsZero() {
		posture.GeneratedAt = time.Now().UTC()
	}
	a.writeJSON(w, http.StatusOK, posture)
}

//trstctl:mutation
func (a *API) setACMEEABCredentialDisabled(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	keyID := strings.TrimSpace(r.PathValue("kid"))
	disabled := strings.HasSuffix(r.URL.Path, "/disable")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.acmeEABDisable == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "ACME external account binding state is not assembled")
		}
		if keyID == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "external account credential key id is required")
		}
		credential, ok, err := a.acmeEABDisable(ctx, tenantID, keyID, disabled)
		if err != nil {
			return 0, nil, err
		}
		if !ok {
			return 0, nil, errStatus(http.StatusNotFound, "no external account credential with that key id is configured for this tenant")
		}
		return http.StatusOK, credential, nil
	})
}
