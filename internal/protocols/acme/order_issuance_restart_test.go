// SPDX-License-Identifier: MPL-2.0

package acme_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/events"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// The CA commits a certificate, then loses its response until the caller
// restarts. It models the gap before ACME can append certificate.issued.
type interruptedOrderCA struct {
	ca.CA
	mu     sync.Mutex
	fail   bool
	keys   []string
	issued map[string]ca.Certificate
}

func (c *interruptedOrderCA) Issue(ctx context.Context, req ca.IssueRequest) (ca.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys = append(c.keys, req.ProviderIdempotencyKey)
	cert, ok := c.issued[req.ProviderIdempotencyKey]
	if !ok {
		var err error
		cert, err = c.CA.Issue(ctx, req)
		if err != nil {
			return ca.Certificate{}, err
		}
		c.issued[req.ProviderIdempotencyKey] = cert
	}
	if c.fail {
		return ca.Certificate{}, errors.New("injected lost issuance response")
	}
	return cert, nil
}

func TestACMEOrderIssuanceIdentitySurvivesInterruptedFinalizeAndRestart(t *testing.T) {
	ctx := context.Background()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	const tenant = "acme-order-retry"
	issuer := &interruptedOrderCA{CA: mustBuiltin(t), fail: true, issued: make(map[string]ca.Certificate)}
	srv, err := acmesrv.New(issuer, acmesrv.AcceptAll{}).WithStateLog(ctx, tenant, log)
	if err != nil {
		t.Fatal(err)
	}
	first := httptest.NewServer(srv)
	t.Cleanup(first.Close)
	client, err := acmekey.NewRSAClient(first.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	client.RetryBackoff = func(int, *http.Request, *http.Response) time.Duration { return -1 }
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatal(err)
	}
	const domain = "retry.acme.test"
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatal(err)
	}
	order = validateOrder(t, ctx, client, order)
	csr := buildCSR(t, domain, []string{domain})
	if _, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true); err == nil {
		t.Fatal("injected lost response unexpectedly completed the order")
	}
	first.Close()
	issuer.mu.Lock()
	if len(issuer.keys) != 1 || issuer.keys[0] == "" {
		issuer.mu.Unlock()
		t.Fatal("new order did not give its CA one nonempty issuance identity")
	}
	firstKey := issuer.keys[0]
	original := issuer.issued[firstKey]
	issuer.fail = false
	issuer.mu.Unlock()

	replayed, err := acmesrv.New(issuer, acmesrv.AcceptAll{}).WithStateLog(ctx, tenant, log)
	if err != nil {
		t.Fatal(err)
	}
	second := httptest.NewServer(replayed)
	t.Cleanup(second.Close)
	restarted := &xacme.Client{Key: client.Key, KID: client.KID, DirectoryURL: second.URL + "/directory"}
	finalizeURL := rewriteBaseURL(t, order.FinalizeURL, second.URL)
	chain, _, err := restarted.CreateOrderCert(ctx, finalizeURL, csr, true)
	if err != nil || len(chain) == 0 {
		t.Fatalf("retry after restart: %v", err)
	}
	issuer.mu.Lock()
	if len(issuer.keys) != 2 || issuer.keys[1] != firstKey || len(issuer.issued) != 1 {
		issuer.mu.Unlock()
		t.Fatal("restart reminted instead of recovering the original issuance")
	}
	issuer.mu.Unlock()
	// A completed-order replay must not reach the CA at all.
	duplicate, _, err := restarted.CreateOrderCert(ctx, finalizeURL, csr, true)
	if err != nil || len(duplicate) == 0 || !bytes.Equal(duplicate[0], chain[0]) {
		t.Fatalf("completed-order replay: %v", err)
	}
	for i := 0; i < 2; i++ {
		if i == 1 {
			// A different account requesting the same name/key also owns a new mint.
			restarted, err = acmekey.NewRSAClient(second.URL + "/directory")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := restarted.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
				t.Fatal(err)
			}
		}
		renewal, err := restarted.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
		if err != nil {
			t.Fatal(err)
		}
		renewal = validateOrder(t, ctx, restarted, renewal)
		if _, _, err := restarted.CreateOrderCert(ctx, renewal.FinalizeURL, csr, true); err != nil {
			t.Fatal(err)
		}
	}
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	if len(issuer.keys) != 4 || len(issuer.issued) != 3 || issuer.keys[2] == "" || issuer.keys[3] == "" {
		t.Fatalf("expected three independent issuances and one interrupted retry; calls=%d mints=%d", len(issuer.keys), len(issuer.issued))
	}
	if !bytes.Equal(issuer.issued[firstKey].CertificatePEM, original.CertificatePEM) {
		t.Fatal("original issuance changed after renewal")
	}
}
