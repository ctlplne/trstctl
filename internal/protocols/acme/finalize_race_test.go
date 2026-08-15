// SPDX-License-Identifier: MPL-2.0

package acme_test

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// TestConcurrentFinalizeIssuesAtMostOneCertificate is the regression guard for
// the double-issuance race. finalize read the order under s.mu, RELEASED the
// lock, and only then checked whether the order was ready — so two concurrent
// finalize requests for the same order both observed "ready" and both went on to
// mint. One authorization, two certificates.
//
// The order is now CLAIMED while the lock is still held, so the loser sees
// "processing" and is refused.
func TestConcurrentFinalizeIssuesAtMostOneCertificate(t *testing.T) {
	builtin, err := ca.NewBuiltin("trstctl ACME finalize-race CA")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(acmesrv.New(builtin, acmesrv.AcceptAll{}))
	t.Cleanup(ts.Close)

	client, err := acmekey.NewRSAClient(ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("register: %v", err)
	}
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("race.acme.test"))
	if err != nil {
		t.Fatalf("authorize order: %v", err)
	}
	finalizeURL := order.FinalizeURL
	order = validateOrder(t, ctx, client, order)
	if order.FinalizeURL != "" {
		finalizeURL = order.FinalizeURL
	}

	// Count DISTINCT certificates, not successful calls: RFC 8555 replay
	// legitimately returns the SAME certificate to a repeated finalize, and that
	// is correct. The defect is one authorization yielding more than one
	// certificate.
	const attempts = 8
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		certs = map[string]int{}
	)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			csr := buildCSR(t, "race.acme.test", []string{"race.acme.test"})
			der, _, err := client.CreateOrderCert(ctx, finalizeURL, csr, true)
			if err != nil || len(der) == 0 {
				return
			}
			var key []byte
			for _, block := range der {
				key = append(key, block...)
			}
			mu.Lock()
			certs[string(key)]++
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(certs) > 1 {
		t.Fatalf("one authorization produced %d DISTINCT certificates across %d concurrent finalize requests; "+
			"the order was claimed by more than one request", len(certs), attempts)
	}
	if len(certs) == 0 {
		t.Fatal("no concurrent finalize succeeded; the claim refuses the winner too")
	}
}
