// SPDX-License-Identifier: MPL-2.0

package acme

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"testing/quick"

	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
)

type accountFailingLog struct{ acmeAuthModeLog }

func (*accountFailingLog) Append(context.Context, events.Event) (events.Event, error) {
	return events.Event{}, errors.New("account event store unavailable")
}

func TestAccountRetirementRequiresDurableEvent(t *testing.T) {
	s := New(nil, AcceptAll{})
	s.stateLog, s.stateTenantID = &accountFailingLog{}, "account-tenant"
	acct := &account{url: "http://ca.test/acme/acct/1", status: statusValid, contact: []string{"mailto:owner@example.test"}}
	o := &order{id: "pending", accountURL: acct.url, status: statusPending}
	s.orders[o.id] = o
	w := httptest.NewRecorder()
	s.updateAccount(w, httptest.NewRequest(http.MethodPost, acct.url, nil), &jose.ACMEMessage{Payload: []byte(`{"status":"deactivated","contact":[]}`)}, acct)
	if w.Code != http.StatusInternalServerError || acct.status != statusValid || len(acct.contact) != 1 || o.status != statusPending {
		t.Fatalf("failed event append altered serving state: %d %+v %+v", w.Code, acct, o)
	}
	log := &acmeAuthModeLog{}
	s.stateLog = log
	for range 2 {
		w := httptest.NewRecorder()
		s.updateAccount(w, httptest.NewRequest(http.MethodPost, acct.url, nil), &jose.ACMEMessage{Payload: []byte(`{"contact":[]}`)}, acct)
		if w.Code != http.StatusOK {
			t.Fatalf("contact update failed: %d", w.Code)
		}
	}
	if len(log.events) != 1 || log.events[0].TenantID != "account-tenant" || log.events[0].Type != acmeEventAccountUpserted {
		t.Fatalf("contact retry duplicated or mis-scoped event: %+v", log.events)
	}
}

func TestAccountUpdatesFailClosedAndPreserveServerFields(t *testing.T) {
	for _, payload := range []string{`null`, `[]`, `{"contact":null}`, `{"contact":[null]}`, `{"contact":[17]}`, `{"contact":"mailto:x@example.test"}`, `{"status":17}`, `{"status":"deactivated","contact":null}`} {
		t.Run(payload, func(t *testing.T) {
			s := New(nil, AcceptAll{})
			acct := &account{url: "http://ca.test/acme/acct/1", status: statusValid, contact: []string{"mailto:old@example.test"}, eabKeyID: "scoped-eab"}
			w := httptest.NewRecorder()
			s.updateAccount(w, httptest.NewRequest(http.MethodPost, acct.url, nil), &jose.ACMEMessage{Payload: []byte(payload)}, acct)
			if w.Code != http.StatusBadRequest || acct.status != statusValid || !slices.Equal(acct.contact, []string{"mailto:old@example.test"}) {
				t.Fatalf("malformed update changed account: code=%d account=%+v", w.Code, acct)
			}
		})
	}
	s := New(nil, AcceptAll{})
	acct := &account{url: "http://ca.test/acme/acct/1", status: statusValid, contact: []string{"mailto:old@example.test"}, eabKeyID: "scoped-eab"}
	for _, payload := range []string{"", `{}`, `{"status":"valid","orders":"attacker","externalAccountBinding":{},"extension":"ignored"}`} {
		w := httptest.NewRecorder()
		s.updateAccount(w, httptest.NewRequest(http.MethodPost, acct.url, nil), &jose.ACMEMessage{Payload: []byte(payload)}, acct)
		if w.Code != http.StatusOK || acct.eabKeyID != "scoped-eab" || !slices.Equal(acct.contact, []string{"mailto:old@example.test"}) {
			t.Fatalf("read/ignored update altered account: %d %+v", w.Code, acct)
		}
	}
	w := httptest.NewRecorder()
	s.updateAccount(w, httptest.NewRequest(http.MethodPost, acct.url, nil), &jose.ACMEMessage{Payload: []byte(`{"contact":[]}`)}, acct)
	if w.Code != http.StatusOK || len(acct.contact) != 0 {
		t.Fatalf("explicit empty contact list not applied: %d %v", w.Code, acct.contact)
	}
	for _, caller := range []*account{nil, {url: "http://ca.test/acme/acct/2", status: statusValid}} {
		w := httptest.NewRecorder()
		s.updateAccount(w, httptest.NewRequest(http.MethodPost, acct.url, nil), &jose.ACMEMessage{Payload: []byte(`{"status":"deactivated"}`)}, caller)
		if w.Code != http.StatusNotFound || acct.status != statusValid {
			t.Fatal("non-owner deactivated an account")
		}
	}
}

func TestAccountOrdersPaginationAndIsolation(t *testing.T) {
	s := New(nil, AcceptAll{})
	acct := &account{url: "http://ca.test/acme/acct/1", status: statusValid}
	for i := range 205 {
		id := fmt.Sprintf("%04d", i)
		s.orders[id] = &order{id: id, accountURL: acct.url, status: statusPending}
	}
	s.orders["other"] = &order{id: "other", accountURL: "http://ca.test/acme/acct/2", status: statusPending}
	s.orders["invalid"] = &order{id: "invalid", accountURL: acct.url, status: "invalid"}
	next := acct.url + "/orders"
	seen := make(map[string]bool)
	for page := 0; next != "" && page < 4; page++ {
		w := httptest.NewRecorder()
		s.accountOrders(w, httptest.NewRequest(http.MethodPost, next, nil), &jose.ACMEMessage{}, acct)
		var body struct {
			Orders []string `json:"orders"`
		}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil || len(body.Orders) > 100 {
			t.Fatalf("bad page: %d %s", w.Code, w.Body.String())
		}
		for _, item := range body.Orders {
			if seen[item] || strings.Contains(item, "other") || strings.Contains(item, "invalid") {
				t.Fatalf("duplicate or foreign order: %s", item)
			}
			seen[item] = true
		}
		next = ""
		for _, link := range w.Header().Values("Link") {
			if strings.Contains(link, `rel="next"`) {
				next = strings.Split(strings.TrimPrefix(link, "<"), ">")[0]
			}
		}
	}
	if len(seen) != 205 || next != "" {
		t.Fatalf("pagination returned %d orders, next=%s", len(seen), next)
	}
	w := httptest.NewRecorder()
	s.accountOrders(w, httptest.NewRequest(http.MethodPost, acct.url+"/orders", nil), &jose.ACMEMessage{}, &account{url: "http://ca.test/acme/acct/2"})
	if w.Code != http.StatusNotFound {
		t.Fatal("non-owner enumerated account orders")
	}
}

func TestAccountUpdatePropertyPreservesContactPresence(t *testing.T) {
	if err := quick.Check(func(value string, present, deactivate bool) bool {
		// URL escaping keeps the generated contact ASCII without weakening the
		// property: every escaped string must survive decoding unchanged.
		contacts := []string{"mailto:" + url.QueryEscape(value) + "@example.test"}
		raw := map[string]any{"status": "valid", "orders": "ignored"}
		if present {
			raw["contact"] = contacts
		}
		if deactivate {
			raw["status"] = "deactivated"
		}
		payload, err := json.Marshal(raw)
		if err != nil {
			return false
		}
		got, err := ParseAccountUpdateRequest(payload)
		return err == nil && got.Deactivate == deactivate && ((got.Contact == nil && !present) || (got.Contact != nil && present && slices.Equal(*got.Contact, contacts)))
	}, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatal(err)
	}
}
