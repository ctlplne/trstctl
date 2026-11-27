// SPDX-License-Identifier: BUSL-1.1

package acme

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/jose"
)

func TestAccountContactAdmission(t *testing.T) {
	for _, contact := range []string{
		"mailto:owner@example.test",
		"mailto:owner+alerts@example.test",
	} {
		if _, err := ParseAccountUpdateRequest([]byte(`{"contact":["` + contact + `"]}`)); err != nil {
			t.Fatalf("valid contact %q: %v", contact, err)
		}
	}
	for name, contacts := range map[string]string{
		"scheme":       `"https://example.test"`,
		"address":      `"mailto:broken"`,
		"length":       `"mailto:` + strings.Repeat("a", 255) + `@example.test"`,
		"count":        strings.Repeat(`"mailto:one@example.test",`, 10) + `"mailto:last@example.test"`,
		"encoded line": `"mailto:owner%0A@example.test"`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseAccountUpdateRequest([]byte(`{"contact":[` + contacts + `]}`)); err == nil {
				t.Fatal("account parser accepted an invalid contact list")
			}
		})
	}
}

func TestAccountMutationBudgetBoundsStateWrites(t *testing.T) {
	s := New(nil, AcceptAll{}).WithQuota(QuotaConfig{MaxAccountMutationsPerAccount: 2, MaxAccountMutationsPerSource: 2,
		SourceWindow: time.Hour})
	log := &acmeAuthModeLog{}
	s.stateLog, s.stateTenantID = log, "account-tenant"
	acct := &account{url: "http://ca.test/acme/acct/1", status: statusValid}
	for i, value := range []string{"one", "two", "three"} {
		w := httptest.NewRecorder()
		s.updateAccount(w, httptest.NewRequest(http.MethodPost, acct.url, nil),
			&jose.ACMEMessage{Payload: []byte(`{"contact":["mailto:` + value + `@example.test"]}`)}, acct)
		if i < 2 && w.Code != http.StatusOK {
			t.Fatalf("admitted update %d status = %d: %s", i, w.Code, w.Body.String())
		}
		if i == 2 && w.Code != http.StatusTooManyRequests {
			t.Fatalf("bounded update status = %d, want 429", w.Code)
		}
	}
	if len(log.events) != 2 || acct.contact[0] != "mailto:two@example.test" {
		t.Fatalf("state writes=%d contact=%v, want two admitted updates", len(log.events), acct.contact)
	}
	w := httptest.NewRecorder()
	s.updateAccount(w, httptest.NewRequest(http.MethodPost, acct.url, nil), &jose.ACMEMessage{}, acct)
	if w.Code != http.StatusOK {
		t.Fatalf("read-only account lookup status=%d, want 200", w.Code)
	}
}

func TestAccountMutationSourceBudgetSharesAccounts(t *testing.T) {
	s := New(nil, AcceptAll{}).WithQuota(QuotaConfig{MaxAccountMutationsPerAccount: 10,
		MaxAccountMutationsPerSource: 2, SourceWindow: time.Hour})
	log := &acmeAuthModeLog{}
	s.stateLog, s.stateTenantID = log, "account-tenant"
	for i := range 3 {
		acct := &account{url: "http://ca.test/acme/acct/" + string(rune('1'+i)), status: statusValid}
		w := httptest.NewRecorder()
		s.updateAccount(w, httptest.NewRequest(http.MethodPost, acct.url, nil),
			&jose.ACMEMessage{Payload: []byte(`{"contact":["mailto:owner@example.test"]}`)}, acct)
		if i < 2 && w.Code != http.StatusOK || i == 2 && w.Code != http.StatusTooManyRequests {
			t.Fatalf("account %d status=%d", i, w.Code)
		}
	}
	if len(log.events) != 2 {
		t.Fatalf("state writes=%d, want source-bounded two", len(log.events))
	}
}

func TestAccountMutationTenantBudgetSharesAccounts(t *testing.T) {
	s := New(nil, AcceptAll{}).WithQuota(QuotaConfig{MaxAccountMutationsPerAccount: 10,
		MaxAccountMutationsPerTenant: 2, MaxAccountMutationsPerSource: 10, SourceWindow: time.Hour})
	log := &acmeAuthModeLog{}
	s.stateLog, s.stateTenantID = log, "account-tenant"
	for i := range 3 {
		acct := &account{url: "http://ca.test/acme/acct/" + string(rune('1'+i)), status: statusValid}
		w := httptest.NewRecorder()
		s.updateAccount(w, httptest.NewRequest(http.MethodPost, acct.url, nil),
			&jose.ACMEMessage{Payload: []byte(`{"contact":["mailto:owner@example.test"]}`)}, acct)
		if i < 2 && w.Code != http.StatusOK || i == 2 && w.Code != http.StatusTooManyRequests {
			t.Fatalf("account %d status=%d", i, w.Code)
		}
	}
	if len(log.events) != 2 {
		t.Fatalf("state writes=%d, want tenant-bounded two", len(log.events))
	}
}

func TestAccountRouteBodyLimit(t *testing.T) {
	s := New(nil, AcceptAll{})
	for _, route := range []string{"/acme/new-account", "/acme/acct/1", "/acme/key-change"} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "http://ca.test"+route,
			strings.NewReader(strings.Repeat("x", 20<<10))))
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("%s body status=%d, want 413", route, w.Code)
		}
	}
}

func FuzzAccountContactAdmission(f *testing.F) {
	for _, seed := range []string{
		`{"contact":["mailto:owner@example.test"]}`,
		`{"contact":[]}`,
		`{"status":"deactivated"}`,
		`{"contact":[null]}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		request, err := ParseAccountUpdateRequest(payload)
		if err == nil && request.Contact != nil {
			if err := validateAccountContacts(*request.Contact); err != nil {
				t.Fatalf("admitted contact list is invalid: %v", err)
			}
		}
	})
}
