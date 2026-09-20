// SPDX-License-Identifier: BUSL-1.1

package acme_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// validateOrder drives an order through http-01 to the ready state.
func validateOrder(t *testing.T, ctx context.Context, client *xacme.Client, order *xacme.Order) *xacme.Order {
	t.Helper()
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			t.Fatalf("get authorization: %v", err)
		}
		var chal *xacme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "http-01" {
				chal = c
			}
		}
		if chal == nil {
			t.Fatal("server offered no http-01 challenge")
		}
		if _, err := client.Accept(ctx, chal); err != nil {
			t.Fatalf("accept challenge: %v", err)
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			t.Fatalf("wait authorization: %v", err)
		}
	}
	ready, err := client.WaitOrder(ctx, order.URI)
	if err != nil {
		t.Fatalf("wait order: %v", err)
	}
	return ready
}

// TestACMEFinalizeRejectsIdentifiersTheOrderDidNotAuthorize is the regression
// guard for the unauthorized-issuance defect. finalize handed the client's CSR
// straight to the CA without comparing its names to the order's validated
// identifiers, and every in-process CA takes its names from the CSR (see the
// contract on ca.IssueRequest.DNSNames), so an account that legitimately
// validated a domain it controls could finalize with a CSR for ANY other name
// and receive a CA-signed certificate for it.
//
// RFC 8555 §7.4: the CSR must indicate the exact same set of identifiers as the
// order.
func TestACMEFinalizeRejectsIdentifiersTheOrderDidNotAuthorize(t *testing.T) {
	builtin, err := ca.NewBuiltin("trstctl ACME identifier-binding CA")
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

	// The attacker really does control this name and validates it honestly.
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("attacker-owned.test"))
	if err != nil {
		t.Fatalf("authorize order: %v", err)
	}
	order = validateOrder(t, ctx, client, order)

	for _, tc := range []struct {
		name string
		cn   string
		sans []string
	}{
		{"unauthorized name", "victim-bank.test", []string{"victim-bank.test"}},
		{"authorized plus smuggled name", "attacker-owned.test", []string{"attacker-owned.test", "victim-bank.test"}},
		{"smuggled via subject CN only", "victim-bank.test", []string{"attacker-owned.test"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			csr := buildCSR(t, tc.cn, tc.sans)
			der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
			if err == nil {
				t.Fatalf("finalize MINTED a certificate for an unauthorized identifier (%d bytes); "+
					"the order authorized only attacker-owned.test", len(der))
			}
			if !strings.Contains(strings.ToLower(err.Error()), "csr") {
				t.Logf("refused with: %v", err)
			}
		})
	}
}

// TestACMEFinalizeAcceptsExactlyTheAuthorizedIdentifiers keeps the guard honest:
// the legitimate case must still issue, so the fix cannot be a blanket refusal.
// It also covers the two forms that denote the same DNS name — differing case
// and a fully-qualified trailing dot.
func TestACMEFinalizeAcceptsExactlyTheAuthorizedIdentifiers(t *testing.T) {
	for _, tc := range []struct {
		name string
		cn   string
		sans []string
	}{
		{"exact match", "exact.acme.test", []string{"exact.acme.test"}},
		{"case-insensitive", "EXACT.acme.test", []string{"Exact.ACME.test"}},
		{"trailing dot", "exact.acme.test.", []string{"exact.acme.test."}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			builtin, err := ca.NewBuiltin("trstctl ACME identifier-binding CA")
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
			order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("exact.acme.test"))
			if err != nil {
				t.Fatalf("authorize order: %v", err)
			}
			order = validateOrder(t, ctx, client, order)

			der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, buildCSR(t, tc.cn, tc.sans), true)
			if err != nil {
				t.Fatalf("finalize refused the exact authorized identifier set: %v", err)
			}
			if len(der) == 0 {
				t.Fatal("no certificate chain returned")
			}
		})
	}
}
