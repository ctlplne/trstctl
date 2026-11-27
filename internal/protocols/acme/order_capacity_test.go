// SPDX-License-Identifier: BUSL-1.1

package acme

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/jose"
)

func TestACMEPendingAccountSharePreservesOtherAccounts(t *testing.T) {
	for _, test := range []struct {
		name                     string
		maxAuthzs, maxChallenges int
	}{
		{name: "authorizations", maxAuthzs: 2, maxChallenges: 30},
		{name: "challenges", maxAuthzs: 10, maxChallenges: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := New(nil, AcceptAll{}).WithQuota(QuotaConfig{
				MaxPendingOrders: 20, MaxPendingOrdersPerAccount: 10,
				MaxPendingAuthorizations: 20, MaxPendingChallenges: 60,
				MaxPendingAuthorizationsPerAccount: test.maxAuthzs,
				MaxPendingChallengesPerAccount:     test.maxChallenges,
				MaxNewOrdersPerAccount:             20, MaxNewOrdersPerSource: 20,
			})
			a := &account{url: "http://ca.test/acme/acct/a", status: statusValid}
			b := &account{url: "http://ca.test/acme/acct/b", status: statusValid}
			first := createQuotaOrder(t, s, a, "first.example.test")
			if first.Code != http.StatusCreated {
				t.Fatalf("first account order = %d: %s", first.Code, first.Body.String())
			}
			if test.name == "authorizations" {
				second := createQuotaOrder(t, s, a, "second.example.test")
				if second.Code != http.StatusCreated {
					t.Fatalf("second account order = %d: %s", second.Code, second.Body.String())
				}
			}
			assertRateLimited(t, createQuotaOrder(t, s, a, "next.example.test"))
			if other := createQuotaOrder(t, s, b, "other.example.test"); other.Code != http.StatusCreated {
				t.Fatalf("other account order = %d: %s", other.Code, other.Body.String())
			}
		})
	}
}

func TestACMEPendingCredentialSharePreservesOtherCredentials(t *testing.T) {
	for _, test := range []struct {
		name                     string
		maxAuthzs, maxChallenges int
	}{
		{name: "authorizations", maxAuthzs: 2, maxChallenges: 30},
		{name: "challenges", maxAuthzs: 10, maxChallenges: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := New(nil, AcceptAll{}).WithQuota(QuotaConfig{
				MaxPendingOrders: 20, MaxPendingOrdersPerAccount: 10,
				MaxPendingAuthorizations: 20, MaxPendingChallenges: 60,
				MaxPendingAuthorizationsPerAccount: 10, MaxPendingChallengesPerAccount: 30,
				MaxPendingAuthorizationsPerEAB: test.maxAuthzs,
				MaxPendingChallengesPerEAB:     test.maxChallenges,
				MaxNewOrdersPerAccount:         20, MaxNewOrdersPerSource: 20,
			})
			s.eabCredentials = map[string]*eabCredential{
				"shared": {keyID: "shared"}, "other": {keyID: "other"},
			}
			a := &account{url: "http://ca.test/acme/acct/a", status: statusValid, eabKeyID: "shared"}
			b := &account{url: "http://ca.test/acme/acct/b", status: statusValid, eabKeyID: "shared"}
			c := &account{url: "http://ca.test/acme/acct/c", status: statusValid, eabKeyID: "other"}
			for _, acct := range []*account{a, b, c} {
				s.accounts[acct.url] = acct
			}
			if first := createQuotaOrder(t, s, a, "first.example.test"); first.Code != http.StatusCreated {
				t.Fatalf("first order = %d: %s", first.Code, first.Body.String())
			}
			if test.name == "authorizations" {
				if second := createQuotaOrder(t, s, b, "second.example.test"); second.Code != http.StatusCreated {
					t.Fatalf("second order = %d: %s", second.Code, second.Body.String())
				}
			}
			assertRateLimited(t, createQuotaOrder(t, s, b, "next.example.test"))
			if other := createQuotaOrder(t, s, c, "other.example.test"); other.Code != http.StatusCreated {
				t.Fatalf("other credential order = %d: %s", other.Code, other.Body.String())
			}
		})
	}
}

func TestACMECompletedAccountClosureReleasesPendingCapacity(t *testing.T) {
	s := New(nil, AcceptAll{}).WithQuota(QuotaConfig{
		MaxPendingOrders: 1, MaxPendingOrdersPerAccount: 1,
		MaxPendingAuthorizations: 1, MaxPendingChallenges: 3,
		MaxNewOrdersPerAccount: 10, MaxNewOrdersPerSource: 10,
	})
	a := &account{url: "http://ca.test/acme/acct/a", status: statusValid}
	b := &account{url: "http://ca.test/acme/acct/b", status: statusValid}
	if first := createQuotaOrder(t, s, a, "first.example.test"); first.Code != http.StatusCreated {
		t.Fatalf("first order = %d: %s", first.Code, first.Body.String())
	}
	w := httptest.NewRecorder()
	s.updateAccount(w, httptest.NewRequest(http.MethodPost, a.url, nil),
		&jose.ACMEMessage{Payload: []byte(`{"status":"deactivated"}`)}, a)
	if w.Code != http.StatusOK {
		t.Fatalf("account closure = %d: %s", w.Code, w.Body.String())
	}
	if other := createQuotaOrder(t, s, b, "other.example.test"); other.Code != http.StatusCreated {
		t.Fatalf("other account order = %d: %s", other.Code, other.Body.String())
	}
}

type countingOrderPolicy struct{ calls int }

func (p *countingOrderPolicy) AllowedMethods(context.Context, string, string) ([]string, bool, error) {
	p.calls++
	return []string{ChallengeHTTP01}, true, nil
}

func TestACMESourceBudgetPrecedesPolicyLookup(t *testing.T) {
	policy := &countingOrderPolicy{}
	s := New(nil, AcceptAll{}).WithQuota(QuotaConfig{
		MaxNewOrdersPerSource: 1, MaxNewOrdersPerAccount: 10, SourceWindow: time.Hour,
	}).WithDomainValidationPolicy(policy)
	a := &account{url: "http://ca.test/acme/acct/a", status: statusValid}
	if first := createQuotaOrder(t, s, a, "first.example.test"); first.Code != http.StatusCreated {
		t.Fatalf("first order = %d: %s", first.Code, first.Body.String())
	}
	assertRateLimited(t, createQuotaOrder(t, s, a, "second.example.test"))
	if policy.calls != 1 {
		t.Fatalf("policy lookups=%d, want one admitted lookup", policy.calls)
	}
}
