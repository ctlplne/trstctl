// SPDX-License-Identifier: BUSL-1.1

package acme

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"
)

// The operator-facing ACME admin view (A52).
//
// The served protocol workflow has always been complete for clients; what an
// operator could see of it was the readiness plan and a short validation
// activity feed. Nothing let them answer "which accounts exist, what has each
// ordered, where is that order stuck, and can I stop this one". These views
// are read straight from the registration-bound serving state, carry no key
// material (an account is named by its RFC 7638 thumbprint, which is public),
// and the one mutation, deactivation, is the same state event a client's own
// deactivation writes, so a replay reproduces it.

// AccountSummary is the secret-free view of one ACME account.
type AccountSummary struct {
	ID           string   `json:"id"`
	Status       string   `json:"status"`
	Contact      []string `json:"contact,omitempty"`
	EABKeyID     string   `json:"eab_key_id,omitempty"`
	Orders       int      `json:"orders"`
	Certificates int      `json:"certificates"`
}

// ChallengeSummary is one challenge under an authorization. The token is the
// public challenge token, not a secret, but the view omits it anyway: an
// operator reads state here, they do not answer challenges.
type ChallengeSummary struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Status string `json:"status"`
}

// AuthorizationSummary is one identifier's authorization under an order.
type AuthorizationSummary struct {
	ID         string             `json:"id"`
	Domain     string             `json:"domain"`
	Status     string             `json:"status"`
	Challenges []ChallengeSummary `json:"challenges"`
	CreatedAt  time.Time          `json:"created_at"`
}

// OrderSummary is one order with its authorizations and, once issued, the
// identity of the certificate (serial and fingerprint, never the material).
type OrderSummary struct {
	ID                     string                 `json:"id"`
	AccountID              string                 `json:"account_id"`
	Status                 string                 `json:"status"`
	Identifiers            []string               `json:"identifiers"`
	Profile                string                 `json:"profile,omitempty"`
	AuthMode               string                 `json:"auth_mode,omitempty"`
	Replaces               string                 `json:"replaces,omitempty"`
	CertificateID          string                 `json:"certificate_id,omitempty"`
	CertificateSerial      string                 `json:"certificate_serial,omitempty"`
	CertificateFingerprint string                 `json:"certificate_fingerprint,omitempty"`
	Revoked                bool                   `json:"revoked"`
	Authorizations         []AuthorizationSummary `json:"authorizations"`
	CreatedAt              time.Time              `json:"created_at"`
}

// ErrNoSuchAccount is returned when an operator names an account the mount
// does not hold.
var ErrNoSuchAccount = errors.New("acme: no such account")

// AccountsContext lists the mount's accounts under the registration-bound
// view, sorted by id.
func (s *Server) AccountsContext(ctx context.Context) ([]AccountSummary, error) {
	_, release, err := s.beginStateScope(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	s.mu.Lock()
	defer s.mu.Unlock()
	orders, certs := map[string]int{}, map[string]int{}
	for _, o := range s.orders {
		orders[o.accountURL]++
		if o.certID != "" {
			certs[o.accountURL]++
		}
	}
	out := make([]AccountSummary, 0, len(s.accounts))
	for _, acct := range s.accounts {
		out = append(out, AccountSummary{
			ID: acct.id, Status: acct.status, Contact: append([]string(nil), acct.contact...),
			EABKeyID: acct.eabKeyID, Orders: orders[acct.url], Certificates: certs[acct.url],
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Server) accountByIDLocked(accountID string) *account {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return nil
	}
	for _, acct := range s.accounts {
		if acct.id == accountID {
			return acct
		}
	}
	return nil
}

// OrdersContext lists one account's orders, newest first, with their
// authorizations and challenges. An empty accountID lists every order.
func (s *Server) OrdersContext(ctx context.Context, accountID string) ([]OrderSummary, error) {
	_, release, err := s.beginStateScope(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	s.mu.Lock()
	defer s.mu.Unlock()
	accountID = strings.TrimSpace(accountID)
	var onlyURL string
	if accountID != "" {
		acct := s.accountByIDLocked(accountID)
		if acct == nil {
			return nil, ErrNoSuchAccount
		}
		onlyURL = acct.url
	}
	out := make([]OrderSummary, 0, len(s.orders))
	for _, o := range s.orders {
		if onlyURL != "" && o.accountURL != onlyURL {
			continue
		}
		row := OrderSummary{
			ID: o.id, Status: o.status, Identifiers: append([]string(nil), o.domains...),
			Profile: o.profile, AuthMode: string(o.authMode), Replaces: o.replaces,
			CertificateID: o.certID, Authorizations: []AuthorizationSummary{}, CreatedAt: o.createdAt,
		}
		if acct := s.accounts[o.accountURL]; acct != nil {
			row.AccountID = acct.id
		}
		if o.certID != "" {
			if pem := s.certs[o.certID]; len(pem) > 0 {
				if fp := certFingerprint(pem); fp != "" {
					row.CertificateFingerprint = fp
					if ic := s.issued[fp]; ic != nil {
						row.CertificateSerial = ic.serial
					}
					_, row.Revoked = s.revoked[fp]
				}
			}
		}
		for _, id := range o.authzIDs {
			az := s.authzs[id]
			if az == nil {
				continue
			}
			authz := AuthorizationSummary{ID: az.id, Domain: az.domain, Status: az.status, Challenges: []ChallengeSummary{}, CreatedAt: az.createdAt}
			for _, ch := range az.challenges {
				if ch != nil {
					authz.Challenges = append(authz.Challenges, ChallengeSummary{ID: ch.id, Type: ch.typ, Status: ch.status})
				}
			}
			row.Authorizations = append(row.Authorizations, authz)
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

// DeactivateAccountContext retires an account on the operator's authority:
// the same acme.account.upserted event a client's own deactivation writes,
// so new requests under the key are refused, pending orders are cancelled,
// and a replay reproduces both. Issued certificates are untouched;
// revocation stays a separate, governed operation.
func (s *Server) DeactivateAccountContext(ctx context.Context, accountID string) (AccountSummary, error) {
	ctx, release, err := s.beginStateScope(ctx)
	if err != nil {
		return AccountSummary{}, err
	}
	defer release()
	s.mu.Lock()
	acct := s.accountByIDLocked(accountID)
	s.mu.Unlock()
	if acct == nil {
		return AccountSummary{}, ErrNoSuchAccount
	}
	// Admitted requests under this account finish before it retires; the
	// lifecycle lock is taken before the state lock, as the handlers do.
	if acct.lifecycle != nil {
		acct.lifecycle.Lock()
		defer acct.lifecycle.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if acct.status != statusDeactivated {
		updated := *acct
		updated.status = statusDeactivated
		if err := s.appendStateEventLocked(ctx, acmeEventAccountUpserted, accountEventFrom(&updated, 0)); err != nil {
			return AccountSummary{}, err
		}
		acct.status = statusDeactivated
		s.cancelAccountOrdersLocked(acct.url)
	}
	orders, certs := 0, 0
	for _, o := range s.orders {
		if o.accountURL == acct.url {
			orders++
			if o.certID != "" {
				certs++
			}
		}
	}
	return AccountSummary{ID: acct.id, Status: acct.status, Contact: append([]string(nil), acct.contact...),
		EABKeyID: acct.eabKeyID, Orders: orders, Certificates: certs}, nil
}
