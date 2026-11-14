// SPDX-License-Identifier: BUSL-1.1

package acme_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/events"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// sharedState is the state two replicas share, as the served store keeps it.
type sharedState struct {
	mu     sync.Mutex
	nonces map[string]time.Time
	claims map[string]time.Time
}

func (s *sharedState) MintNonce(_ context.Context, nonce string, expires time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonces[nonce] = expires
	return nil
}

func (s *sharedState) RedeemNonce(_ context.Context, nonce string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	expires, ok := s.nonces[nonce]
	delete(s.nonces, nonce)
	return ok && time.Now().Before(expires), nil
}

func (s *sharedState) ClaimFinalize(_ context.Context, orderID string, until time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if held, ok := s.claims[orderID]; ok && time.Now().Before(held) {
		return false, nil
	}
	s.claims[orderID] = until
	return true, nil
}

func (s *sharedState) ReleaseFinalize(_ context.Context, orderID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.claims, orderID)
	return nil
}

// badNonces counts the badNonce problems a client was answered.
type badNonces struct {
	next  http.RoundTripper
	count atomic.Int64
}

func (b *badNonces) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := b.next.RoundTrip(r)
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		return resp, err
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if strings.Contains(string(body), "badNonce") {
		b.count.Add(1)
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

// P15-L7: with shared state, two replicas behind a balancer that alternates
// on every request serve a whole order with no affinity — a nonce one mints
// the other redeems, so the client never meets badNonce — and the order's
// finalize is one: while another replica holds its claim, finalize is refused
// as in progress, and once the claim is released it issues.
func TestSharedStateNeedsNoReplicaAffinityP15L7(t *testing.T) {
	ctx := context.Background()
	log := openACMEStateLog(t)
	const tenantID = "tenant-acme-shared"
	registration, err := log.Append(ctx, events.Event{Type: "tenant.registered", TenantID: tenantID, Data: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	scope := func(context.Context) (acmesrv.StateScope, error) {
		return acmesrv.StateScope{Identity: "registration-p15l7", FirstSequence: registration.Sequence}, nil
	}
	shared := &sharedState{nonces: map[string]time.Time{}, claims: map[string]time.Time{}}
	replicas := make([]*acmesrv.Server, 2)
	for i := range replicas {
		srv, err := acmesrv.New(mustBuiltin(t), acmesrv.AcceptAll{}).WithStateScope(scope).WithStateLog(ctx, tenantID, log)
		if err != nil {
			t.Fatal(err)
		}
		replicas[i] = srv.WithSharedState(shared)
	}
	var turn atomic.Int64
	balancer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		replicas[turn.Add(1)%2].ServeHTTP(w, r)
	}))
	t.Cleanup(balancer.Close)
	client, err := acmekey.NewRSAClient(balancer.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	counter := &badNonces{next: http.DefaultTransport}
	client.HTTPClient = &http.Client{Transport: counter}
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatal(err)
	}
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("shared.acme.test"))
	if err != nil {
		t.Fatal(err)
	}
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			t.Fatal(err)
		}
		for _, chal := range authz.Challenges {
			if chal.Type == "http-01" {
				if _, err := client.Accept(ctx, chal); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if order, err = client.WaitOrder(ctx, order.URI); err != nil || order.Status != xacme.StatusReady {
		t.Fatalf("order = %+v %v", order, err)
	}
	orderID := order.URI[strings.LastIndex(order.URI, "/")+1:]
	shared.mu.Lock()
	shared.claims[orderID] = time.Now().Add(time.Minute)
	shared.mu.Unlock()
	csr := buildCSR(t, "shared.acme.test", []string{"shared.acme.test"})
	if _, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true); err == nil || !strings.Contains(err.Error(), "in progress") {
		t.Fatalf("a finalize while another replica holds the claim = %v", err)
	}
	if err := shared.ReleaseFinalize(ctx, orderID); err != nil {
		t.Fatal(err)
	}
	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil || len(der) == 0 {
		t.Fatalf("finalize after the claim was released: %v", err)
	}
	if n := counter.count.Load(); n != 0 {
		t.Fatalf("the client met badNonce %d times", n)
	}
}
