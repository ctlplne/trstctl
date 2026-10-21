// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

// The dedicated ACME admin surface (A52): accounts, orders with their
// authorizations and challenges, operator deactivation, and the exact
// certificate record id so revocation runs through the governed
// /api/v1/certificates/bulk-revoke path rather than a second one here. No
// response carries key material; an account is named by its public RFC 7638
// thumbprint.

// ACMEAccount is the served view of one ACME account on this tenant's mount.
type ACMEAccount struct {
	ID           string   `json:"id"`
	Status       string   `json:"status"`
	Contact      []string `json:"contact,omitempty"`
	EABKeyID     string   `json:"eab_key_id,omitempty"`
	Orders       int      `json:"orders"`
	Certificates int      `json:"certificates"`
}

// ACMEAccountList separates "not served for this tenant" from "served with
// no accounts yet".
type ACMEAccountList struct {
	Served      bool          `json:"served"`
	GeneratedAt time.Time     `json:"generated_at"`
	Items       []ACMEAccount `json:"items"`
}

type ACMEChallenge struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Status string `json:"status"`
}

type ACMEAuthorization struct {
	ID         string          `json:"id"`
	Domain     string          `json:"domain"`
	Status     string          `json:"status"`
	Challenges []ACMEChallenge `json:"challenges"`
	CreatedAt  time.Time       `json:"created_at"`
}

// ACMEOrder is one order. CertificateRecordID is the inventory row of the
// issued leaf, the id /api/v1/certificates/bulk-revoke takes; it is empty
// until issuance is recorded.
type ACMEOrder struct {
	ID                     string              `json:"id"`
	AccountID              string              `json:"account_id"`
	Status                 string              `json:"status"`
	Identifiers            []string            `json:"identifiers"`
	Profile                string              `json:"profile,omitempty"`
	AuthMode               string              `json:"auth_mode,omitempty"`
	Replaces               string              `json:"replaces,omitempty"`
	CertificateID          string              `json:"certificate_id,omitempty"`
	CertificateSerial      string              `json:"certificate_serial,omitempty"`
	CertificateFingerprint string              `json:"certificate_fingerprint,omitempty"`
	CertificateRecordID    string              `json:"certificate_record_id,omitempty"`
	Revoked                bool                `json:"revoked"`
	Authorizations         []ACMEAuthorization `json:"authorizations"`
	CreatedAt              time.Time           `json:"created_at"`
}

type ACMEOrderList struct {
	Served      bool        `json:"served"`
	AccountID   string      `json:"account_id,omitempty"`
	GeneratedAt time.Time   `json:"generated_at"`
	Items       []ACMEOrder `json:"items"`
}

// ErrACMEAccountNotFound is what the seams return for an unknown account id.
var ErrACMEAccountNotFound = errors.New("api: no such ACME account")

type ACMEAccountsProvider func(ctx context.Context, tenantID string) (ACMEAccountList, error)
type ACMEOrdersProvider func(ctx context.Context, tenantID, accountID string) (ACMEOrderList, error)
type ACMEAccountDeactivator func(ctx context.Context, tenantID, accountID string) (ACMEAccount, error)

// WithACMEAdmin wires the mounted ACME server's account and order views and
// the operator deactivation verb.
func WithACMEAdmin(accounts ACMEAccountsProvider, orders ACMEOrdersProvider, deactivate ACMEAccountDeactivator) Option {
	return func(c *config) {
		c.acmeAccounts = accounts
		c.acmeOrders = orders
		c.acmeDeactivateAccount = deactivate
	}
}

func (a *API) listACMEAccounts(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.acmeAccounts == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "ACME admin state is not assembled"))
		return
	}
	list, err := a.acmeAccounts(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if list.Items == nil {
		list.Items = []ACMEAccount{}
	}
	if list.GeneratedAt.IsZero() {
		list.GeneratedAt = time.Now().UTC()
	}
	a.writeJSON(w, http.StatusOK, list)
}

func (a *API) listACMEAccountOrders(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.acmeOrders == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "ACME admin state is not assembled"))
		return
	}
	accountID := strings.TrimSpace(r.PathValue("id"))
	if accountID == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "ACME account id is required"))
		return
	}
	list, err := a.acmeOrders(r.Context(), tenantID, accountID)
	if errors.Is(err, ErrACMEAccountNotFound) {
		a.writeError(w, errStatus(http.StatusNotFound, "no ACME account with that id is served for this tenant"))
		return
	}
	if err != nil {
		a.writeError(w, err)
		return
	}
	if list.Items == nil {
		list.Items = []ACMEOrder{}
	}
	if list.GeneratedAt.IsZero() {
		list.GeneratedAt = time.Now().UTC()
	}
	a.writeJSON(w, http.StatusOK, list)
}

//trstctl:mutation
func (a *API) deactivateACMEAccount(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	accountID := strings.TrimSpace(r.PathValue("id"))
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.acmeDeactivateAccount == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "ACME admin state is not assembled")
		}
		if accountID == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "ACME account id is required")
		}
		account, err := a.acmeDeactivateAccount(ctx, tenantID, accountID)
		if errors.Is(err, ErrACMEAccountNotFound) {
			return 0, nil, errStatus(http.StatusNotFound, "no ACME account with that id is served for this tenant")
		}
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, account, nil
	})
}
