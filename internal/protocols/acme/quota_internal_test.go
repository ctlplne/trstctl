package acme

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/jose"
)

func TestACMEQuotaRejectsFlood(t *testing.T) {
	nonceSrv := New(nil, AcceptAll{}).WithQuota(QuotaConfig{
		MaxNonces:                  1,
		MaxPendingOrders:           1,
		MaxPendingAuthorizations:   1,
		MaxPendingChallenges:       3,
		MaxPendingOrdersPerAccount: 1,
		MaxNewOrdersPerSource:      10,
		MaxNewAccountsPerSource:    10,
		MaxNewNoncesPerSource:      10,
		SourceWindow:               time.Minute,
		StateTTL:                   time.Hour,
	})

	rec := httptest.NewRecorder()
	nonceSrv.newNonce(rec, httptest.NewRequest(http.MethodGet, "http://ca.test/acme/new-nonce", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("first nonce status = %d, want 204", rec.Code)
	}
	rec = httptest.NewRecorder()
	nonceSrv.newNonce(rec, httptest.NewRequest(http.MethodGet, "http://ca.test/acme/new-nonce", nil))
	assertRateLimited(t, rec)
	if got := len(nonceSrv.nonces); got != 1 {
		t.Fatalf("nonce flood retained %d nonces, want quota-bound 1", got)
	}

	orderSrv := New(nil, AcceptAll{}).WithQuota(QuotaConfig{
		MaxNonces:                  10,
		MaxPendingOrders:           1,
		MaxPendingAuthorizations:   1,
		MaxPendingChallenges:       3,
		MaxPendingOrdersPerAccount: 1,
		MaxNewOrdersPerSource:      10,
		MaxNewAccountsPerSource:    10,
		MaxNewNoncesPerSource:      10,
		SourceWindow:               time.Minute,
		StateTTL:                   time.Hour,
	})
	acct := &account{url: "http://ca.test/acme/acct/1", status: statusValid}
	msg := &jose.ACMEMessage{Payload: []byte(`{"identifiers":[{"type":"dns","value":"one.quota.test"}]}`)}
	rec = httptest.NewRecorder()
	orderSrv.newOrder(rec, httptest.NewRequest(http.MethodPost, "http://ca.test/acme/new-order", nil), msg, acct)
	if rec.Code != http.StatusCreated {
		t.Fatalf("first order status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	msg = &jose.ACMEMessage{Payload: []byte(`{"identifiers":[{"type":"dns","value":"two.quota.test"}]}`)}
	rec = httptest.NewRecorder()
	orderSrv.newOrder(rec, httptest.NewRequest(http.MethodPost, "http://ca.test/acme/new-order", nil), msg, acct)
	assertRateLimited(t, rec)
	if got := len(orderSrv.orders); got != 1 {
		t.Fatalf("order flood retained %d orders, want quota-bound 1", got)
	}
	if got := len(orderSrv.authzs); got != 1 {
		t.Fatalf("order flood retained %d authzs, want quota-bound 1", got)
	}
	if got := len(orderSrv.challenges); got != 3 {
		t.Fatalf("order flood retained %d challenges, want quota-bound 3", got)
	}
}

func TestACMEQuotaJanitorExpiresPendingState(t *testing.T) {
	srv := New(nil, AcceptAll{}).WithQuota(QuotaConfig{
		MaxNonces:                  10,
		MaxPendingOrders:           1,
		MaxPendingAuthorizations:   1,
		MaxPendingChallenges:       3,
		MaxPendingOrdersPerAccount: 1,
		MaxNewOrdersPerSource:      10,
		MaxNewAccountsPerSource:    10,
		MaxNewNoncesPerSource:      10,
		SourceWindow:               time.Minute,
		NonceTTL:                   time.Minute,
		StateTTL:                   time.Nanosecond,
	})
	acct := &account{url: "http://ca.test/acme/acct/1", status: statusValid}
	msg := &jose.ACMEMessage{Payload: []byte(`{"identifiers":[{"type":"dns","value":"old.quota.test"}]}`)}
	rec := httptest.NewRecorder()
	srv.newOrder(rec, httptest.NewRequest(http.MethodPost, "http://ca.test/acme/new-order", nil), msg, acct)
	if rec.Code != http.StatusCreated {
		t.Fatalf("first order status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	time.Sleep(5 * time.Millisecond)

	msg = &jose.ACMEMessage{Payload: []byte(`{"identifiers":[{"type":"dns","value":"fresh.quota.test"}]}`)}
	rec = httptest.NewRecorder()
	srv.newOrder(rec, httptest.NewRequest(http.MethodPost, "http://ca.test/acme/new-order", nil), msg, acct)
	if rec.Code != http.StatusCreated {
		t.Fatalf("second order after janitor expiry status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
}

func TestACMEAccountOrderRateLimitIsAccountKeyed(t *testing.T) {
	srv := New(nil, AcceptAll{}).WithQuota(QuotaConfig{
		MaxNonces:                  10,
		MaxAccounts:                10,
		MaxPendingOrders:           10,
		MaxPendingAuthorizations:   10,
		MaxPendingChallenges:       30,
		MaxPendingOrdersPerAccount: 10,
		MaxNewOrdersPerAccount:     1,
		MaxNewOrdersPerSource:      10,
		MaxNewAccountsPerSource:    10,
		MaxNewNoncesPerSource:      10,
		SourceWindow:               time.Minute,
		StateTTL:                   time.Hour,
	})
	acctA := &account{url: "http://ca.test/acme/acct/a", status: statusValid}
	acctB := &account{url: "http://ca.test/acme/acct/b", status: statusValid}

	rec := createQuotaOrder(t, srv, acctA, "first.account-limit.test")
	if rec.Code != http.StatusCreated {
		t.Fatalf("first account A order status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	rec = createQuotaOrder(t, srv, acctA, "second.account-limit.test")
	assertRateLimited(t, rec)
	rec = createQuotaOrder(t, srv, acctB, "other-account.account-limit.test")
	if rec.Code != http.StatusCreated {
		t.Fatalf("account B order status = %d, want unaffected 201: %s", rec.Code, rec.Body.String())
	}
}

func TestACMEConcurrentOrderCapIsAccountKeyed(t *testing.T) {
	srv := New(nil, AcceptAll{}).WithQuota(QuotaConfig{
		MaxNonces:                  10,
		MaxAccounts:                10,
		MaxPendingOrders:           10,
		MaxPendingAuthorizations:   10,
		MaxPendingChallenges:       30,
		MaxPendingOrdersPerAccount: 1,
		MaxNewOrdersPerAccount:     10,
		MaxNewOrdersPerSource:      10,
		MaxNewAccountsPerSource:    10,
		MaxNewNoncesPerSource:      10,
		SourceWindow:               time.Minute,
		StateTTL:                   time.Hour,
	})
	acctA := &account{url: "http://ca.test/acme/acct/a", status: statusValid}
	acctB := &account{url: "http://ca.test/acme/acct/b", status: statusValid}

	rec := createQuotaOrder(t, srv, acctA, "first.concurrent-limit.test")
	if rec.Code != http.StatusCreated {
		t.Fatalf("first account A order status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	rec = createQuotaOrder(t, srv, acctA, "second.concurrent-limit.test")
	assertRateLimited(t, rec)
	rec = createQuotaOrder(t, srv, acctB, "other-account.concurrent-limit.test")
	if rec.Code != http.StatusCreated {
		t.Fatalf("account B order status = %d, want unaffected 201: %s", rec.Code, rec.Body.String())
	}
}

func createQuotaOrder(t *testing.T, srv *Server, acct *account, domain string) *httptest.ResponseRecorder {
	t.Helper()
	msg := &jose.ACMEMessage{Payload: []byte(`{"identifiers":[{"type":"dns","value":"` + domain + `"}]}`)}
	rec := httptest.NewRecorder()
	srv.newOrder(rec, httptest.NewRequest(http.MethodPost, "http://ca.test/acme/new-order", nil), msg, acct)
	return rec
}

func assertRateLimited(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("quota status = %d, want 429: %s", rec.Code, rec.Body.String())
	}
	if retry := rec.Header().Get("Retry-After"); retry == "" {
		t.Fatal("quota response did not set Retry-After")
	}
	var problem struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode problem response: %v", err)
	}
	if !strings.Contains(problem.Type, "rateLimited") {
		t.Fatalf("problem type = %q, want rateLimited", problem.Type)
	}
}
