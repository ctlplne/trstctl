// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"testing"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/events"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// Different orders must renew even when a stock client's reused key produces
// identical CSR bytes. A retry of one order must still return that order's leaf.
func TestServedACMERenewalWithIdenticalCSR(t *testing.T) {
	dns := newServedDNSWebhookFixture(t, "renewal-client-dns")
	validators := acmesrv.Validators{DNS01: acmesrv.DNS01Validator{Resolver: dns}}
	h := newServedHarnessWithEventOptions(t,
		config.Protocols{ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		[]events.OpenOption{events.WithRequiredPrivacyEventPolicies()},
		func(d *Deps) { d.ACMEValidators = &validators },
	)
	ctx := context.Background()
	client, err := acmekey.NewRSAClient(h.ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatal(err)
	}
	const domain = "reuse.acme.test"
	csr := buildServedCSR(t, domain)
	issue := func() (*xacme.Order, []byte) {
		t.Helper()
		order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
		if err != nil {
			t.Fatal(err)
		}
		authz, err := client.GetAuthorization(ctx, order.AuthzURLs[0])
		if err != nil {
			t.Fatal(err)
		}
		for _, challenge := range authz.Challenges {
			if challenge.Type != acmesrv.ChallengeDNS01 {
				continue
			}
			value, err := client.DNS01ChallengeRecord(challenge.Token)
			if err != nil {
				t.Fatal(err)
			}
			dns.mu.Lock()
			dns.records[acmesrv.DNS01RecordName(domain)] = map[string]bool{value: true}
			dns.mu.Unlock()
			if _, err := client.Accept(ctx, challenge); err != nil {
				t.Fatal(err)
			}
		}
		order, err = client.WaitOrder(ctx, order.URI)
		if err != nil {
			t.Fatal(err)
		}
		chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
		if err != nil || len(chain) != 2 {
			t.Fatalf("finalize: %v, chain length %d", err, len(chain))
		}
		if err := crypto.VerifyLeafSignedByCA(chain[0], caCertDER(t, h.caPEM)); err != nil {
			t.Fatal(err)
		}
		assertServedRequesterCustody(t, h, chain[0])
		return order, chain[0]
	}
	firstOrder, first := issue()
	_, renewed := issue()
	if bytes.Equal(first, renewed) {
		t.Fatal("different ACME orders with identical CSR returned the same certificate")
	}
	firstKey, err := crypto.PublicKeyDERFromCert(first)
	if err != nil {
		t.Fatal(err)
	}
	renewedKey, err := crypto.PublicKeyDERFromCert(renewed)
	if err != nil || !bytes.Equal(firstKey, renewedKey) {
		t.Fatalf("renewal changed the requested public key: %v", err)
	}
	replayed, _, err := client.CreateOrderCert(ctx, firstOrder.FinalizeURL, csr, true)
	if err != nil || len(replayed) != 2 || !bytes.Equal(replayed[0], first) {
		t.Fatalf("same-order retry did not return the original leaf: %v", err)
	}
	if err := client.RevokeCert(ctx, nil, first, xacme.CRLReasonCessationOfOperation); err != nil {
		t.Fatal(err)
	}
	_, third := issue()
	if bytes.Equal(third, first) || bytes.Equal(third, renewed) {
		t.Fatal("new order returned a previous certificate after revocation")
	}
}
