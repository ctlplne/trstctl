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
// Rotation stays a configuration operation. Minting an EAB credential over HTTP
// would mean returning a shared MAC secret in a response body, so the honest
// rotation is: add the new kid to config, and disable the old one here while
// clients migrate. docs/limitations.md says exactly that rather than implying an
// API that mints secrets.

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

// WithACMEEAB wires the assembled ACME server's external-account-binding state
// into the always-registered routes.
func WithACMEEAB(provider ACMEEABProvider, disabler ACMEEABDisabler) Option {
	return func(c *config) {
		c.acmeEAB = provider
		c.acmeEABDisable = disabler
	}
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
