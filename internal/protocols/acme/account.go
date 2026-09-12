// SPDX-License-Identifier: MPL-2.0

package acme

import (
	"net/http"
	"net/url"
	"slices"
	"sort"

	"trstctl.com/trstctl/internal/crypto/jose"
)

// updateAccount serves POST-as-GET, contact updates and irreversible client
// deactivation at the advertised account URL (RFC 8555 §§7.3.2, 7.3.6).
// jwsWithAccountLock holds this account's exclusive lifecycle lock. Already
// admitted requests must finish before retirement can succeed; a busy account
// returns a retryable 503 instead of holding a protocol worker waiting for it.
func (s *Server) updateAccount(w http.ResponseWriter, r *http.Request, msg *jose.ACMEMessage, acct *account) {
	if acct == nil || accountPath(acct) != r.URL.Path {
		s.problem(w, r, http.StatusNotFound, "malformed", "no such account")
		return
	}
	var update AccountUpdateRequest
	var err error
	if len(msg.Payload) > 0 {
		update, err = ParseAccountUpdateRequest(msg.Payload)
		if err != nil {
			s.problem(w, r, http.StatusBadRequest, "malformed", err.Error())
			return
		}
	}
	s.mu.Lock()
	updated := *acct
	if update.Contact != nil {
		updated.contact = append([]string(nil), (*update.Contact)...)
	}
	if update.Deactivate {
		updated.status = statusDeactivated
	}
	if updated.status != acct.status || !slices.Equal(updated.contact, acct.contact) {
		payload := accountEventFrom(&updated, 0)
		if err = s.appendStateEventLocked(r.Context(), acmeEventAccountUpserted, payload); err != nil {
			s.mu.Unlock()
			s.problem(w, r, http.StatusInternalServerError, "serverInternal", err.Error())
			return
		}
		acct.contact, acct.status = updated.contact, updated.status
		if acct.status == statusDeactivated {
			s.cancelAccountOrdersLocked(acct.url)
		}
	}
	body := map[string]any{"status": acct.status, "orders": acct.url + "/orders", "contact": append([]string{}, acct.contact...)}
	s.mu.Unlock()
	w.Header().Set("Location", acct.url)
	writeJSON(w, http.StatusOK, body)
}

func accountPath(acct *account) string {
	u, err := url.Parse(acct.url)
	if err != nil {
		return ""
	}
	return u.Path
}

// Pending work is canceled by the same event that deactivates the account. The
// replay path applies the identical transition; completed certificates and their
// authorizations are preserved and revocation remains a separate operation.
func (s *Server) cancelAccountOrdersLocked(accountURL string) {
	for _, o := range s.orders {
		if o.accountURL != accountURL || o.status == statusValid {
			continue
		}
		o.status = "invalid"
		for _, id := range o.authzIDs {
			if az := s.authzs[id]; az != nil {
				az.status = statusDeactivated
				for _, ch := range az.challenges {
					ch.status = "invalid"
				}
			}
		}
	}
}

// accountOrders serves a stable, bounded page of this account's non-invalid
// order URLs. The opaque cursor is the last returned order ID, not an offset.
func (s *Server) accountOrders(w http.ResponseWriter, r *http.Request, msg *jose.ACMEMessage, acct *account) {
	if acct == nil || accountPath(acct)+"/orders" != r.URL.Path {
		s.problem(w, r, http.StatusNotFound, "malformed", "no such account")
		return
	}
	if len(msg.Payload) != 0 {
		s.problem(w, r, http.StatusBadRequest, "malformed", "orders requires POST-as-GET")
		return
	}
	const pageSize = 100
	after := r.URL.Query().Get("after")
	s.mu.Lock()
	ids := make([]string, 0)
	for id, o := range s.orders {
		if o.accountURL == acct.url && o.status != "invalid" && id > after {
			// Keep at most one page plus its lookahead, even when the account
			// has a large history of completed orders.
			index := sort.SearchStrings(ids, id)
			if index > pageSize {
				continue
			}
			ids = slices.Insert(ids, index, id)
			if len(ids) > pageSize+1 {
				ids = ids[:pageSize+1]
			}
		}
	}
	s.mu.Unlock()
	if len(ids) > pageSize {
		ids = ids[:pageSize]
		addLink(w, baseURL(r)+r.URL.Path+"?after="+url.QueryEscape(ids[pageSize-1]), "next")
	}
	orders := make([]string, 0, len(ids))
	for _, id := range ids {
		orders = append(orders, baseURL(r)+"/acme/order/"+id)
	}
	writeJSON(w, http.StatusOK, map[string]any{"orders": orders})
}
