// SPDX-License-Identifier: BUSL-1.1

package acme_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

type accountStatusCapture struct{ limited *atomic.Bool }

func (c accountStatusCapture) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := http.DefaultTransport.RoundTrip(r)
	if err == nil && response.StatusCode == http.StatusTooManyRequests {
		c.limited.Store(true)
	}
	return response, err
}

func requireInactiveACMEAccount(t *testing.T, err error) {
	t.Helper()
	var problem *xacme.Error
	if !errors.As(err, &problem) || problem.StatusCode != http.StatusUnauthorized || problem.ProblemType != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("inactive account: got %v, want ACME 401 unauthorized", err)
	}
}

func TestACMENewAccountAdmitsOnlyBoundedMailContacts(t *testing.T) {
	ctx := context.Background()
	log := openACMEStateLog(t)
	srv, err := acmesrv.New(nil, acmesrv.AcceptAll{}).WithStateLog(ctx, "account-contact", log)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	client, err := acmekey.NewClient(ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Register(ctx, &xacme.Account{Contact: []string{"https://example.test/contact"}}, xacme.AcceptTOS); err == nil {
		t.Fatal("invalid account contact was admitted")
	}
	if seq, err := log.LastSequence(ctx); err != nil || seq != 0 {
		t.Fatalf("rejected registration advanced the event log: sequence=%d err=%v", seq, err)
	}
}

func TestACMEAccountWriteBudgetPreservesEventLog(t *testing.T) {
	ctx := context.Background()
	log := openACMEStateLog(t)
	srv, err := acmesrv.New(nil, acmesrv.AcceptAll{}).WithQuota(acmesrv.QuotaConfig{
		MaxAccountMutationsPerAccount: 2, MaxAccountMutationsPerSource: 2,
	}).WithStateLog(ctx, "account-budget", log)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	client, err := acmekey.NewClient(ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatal(err)
	}
	for _, contact := range []string{"mailto:one@example.test", "mailto:two@example.test"} {
		if _, err := client.UpdateReg(ctx, &xacme.Account{Contact: []string{contact}}); err != nil {
			t.Fatalf("admitted account write: %v", err)
		}
	}
	before, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var limited atomic.Bool
	client.HTTPClient = &http.Client{Transport: accountStatusCapture{limited: &limited}}
	updateCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, _ = client.UpdateReg(updateCtx, &xacme.Account{Contact: []string{"mailto:three@example.test"}})
	if !limited.Load() {
		t.Fatal("account write did not receive a 429 response")
	}
	if after, err := log.LastSequence(ctx); err != nil || after != before {
		t.Fatalf("bounded account write advanced event log: %d -> %d, err=%v", before, after, err)
	}
}

// The independent x/crypto client uses the account URL advertised at registration.
// Registration lookup must not mutate contact; updates and retirement must survive
// event replay without revoking an already-issued certificate.
func TestACMEAccountLifecycleSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	log := openACMEStateLog(t)
	const tenant = "account-lifecycle"
	srv, err := acmesrv.New(mustBuiltin(t), acmesrv.AcceptAll{}).WithStateLog(ctx, tenant, log)
	if err != nil {
		t.Fatal(err)
	}
	var handler atomic.Pointer[acmesrv.Server]
	handler.Store(srv)
	current := srv
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.Load().ServeHTTP(w, r) }))
	t.Cleanup(ts.Close)
	client, err := acmekey.NewClient(ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	account, err := client.Register(ctx, &xacme.Account{Contact: []string{"mailto:owner@example.test"}}, xacme.AcceptTOS)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Register(ctx, &xacme.Account{Contact: []string{"mailto:ignored@example.test"}}, xacme.AcceptTOS)
	if err != nil && !errors.Is(err, xacme.ErrAccountAlreadyExists) {
		t.Fatal(err)
	}
	lookup, err := client.GetReg(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(lookup.Contact, account.Contact) {
		t.Errorf("registration lookup changed contact: %v", lookup.Contact)
	}
	updated, err := client.UpdateReg(ctx, &xacme.Account{Contact: []string{"mailto:new-owner@example.test"}})
	if err != nil {
		t.Fatalf("update advertised account endpoint: %v", err)
	}
	if updated.Status != "valid" || !slices.Equal(updated.Contact, []string{"mailto:new-owner@example.test"}) {
		t.Fatalf("updated account: %+v", updated)
	}

	other, err := acmekey.NewClient(ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = other.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatal(err)
	}
	if _, err = other.GetOrder(ctx, account.URI); err == nil {
		t.Fatal("another account read the account resource")
	}
	if _, err = other.Accept(ctx, &xacme.Challenge{URI: account.URI}); err == nil {
		t.Fatal("another account updated the account resource")
	}

	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("account-lifecycle.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	ready := validateOrder(t, ctx, client, order)
	chain, _, err := client.CreateOrderCert(ctx, ready.FinalizeURL, buildCSR(t, "account-lifecycle.example.test", []string{"account-lifecycle.example.test"}), true)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := certinfo.Inspect(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.AuthorizeOrder(ctx, xacme.DomainIDs("pending-account.example.test")); err != nil {
		t.Fatal(err)
	}
	if err = client.DeactivateReg(ctx); err != nil {
		t.Fatalf("deactivate advertised account endpoint: %v", err)
	}
	for _, restart := range []bool{false, true} {
		if restart {
			current, err = acmesrv.New(mustBuiltin(t), acmesrv.AcceptAll{}).WithStateLog(ctx, tenant, log)
			if err != nil {
				t.Fatal(err)
			}
			handler.Store(current)
		}
		_, err = client.AuthorizeOrder(ctx, xacme.DomainIDs("denied-account.example.test"))
		requireInactiveACMEAccount(t, err)
		_, err = client.GetOrder(ctx, order.URI)
		requireInactiveACMEAccount(t, err)
		_, err = client.GetReg(ctx, "") // JWK lookup cannot resurrect the account.
		requireInactiveACMEAccount(t, err)
		requireInactiveACMEAccount(t, client.DeactivateReg(ctx))
		if _, revoked := current.IsRevoked(leaf.SHA256Fingerprint); revoked {
			t.Fatal("account retirement revoked an existing certificate")
		}
		activities := current.DomainValidationActivities(10)
		foundPending := false
		for _, activity := range activities {
			if activity.Domain == "pending-account.example.test" {
				foundPending = true
				if activity.OrderStatus != "invalid" || activity.AuthorizationStatus != "deactivated" {
					t.Fatalf("pending operation survived retirement: %+v", activity)
				}
			}
		}
		if !foundPending {
			t.Fatal("retirement lost pending-operation evidence")
		}
		if _, err = other.AuthorizeOrder(ctx, xacme.DomainIDs("other-account.example.test")); err != nil {
			t.Fatalf("retirement affected another account: %v", err)
		}
	}
}
