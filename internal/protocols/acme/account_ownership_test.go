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

// TestACMEObjectsAreScopedToTheirAccount is the regression guard for the
// cross-account defect: finalize, getOrder, getAuthz and getCert looked their
// object up by path ID and never compared it to the authenticated account. Order
// IDs are sequential integers, so a second account could enumerate a victim's
// order, finalize the work the victim had already validated, and download the
// resulting certificate.
//
// Victim validates an order it legitimately controls; attacker — a separate,
// fully-registered ACME account — then tries to use every object of it.
func TestACMEObjectsAreScopedToTheirAccount(t *testing.T) {
	builtin, err := ca.NewBuiltin("trstctl ACME ownership CA")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(acmesrv.New(builtin, acmesrv.AcceptAll{}))
	t.Cleanup(ts.Close)

	ctx := context.Background()
	newAccount := func(t *testing.T) *xacme.Client {
		t.Helper()
		c, err := acmekey.NewRSAClient(ts.URL + "/directory")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
			t.Fatalf("register: %v", err)
		}
		return c
	}

	victim := newAccount(t)
	attacker := newAccount(t)

	order, err := victim.AuthorizeOrder(ctx, xacme.DomainIDs("victim-owned.test"))
	if err != nil {
		t.Fatalf("authorize order: %v", err)
	}
	authzURL := order.AuthzURLs[0]
	// WaitOrder's result does not carry the order URI, so keep the original.
	orderURI, finalizeURL := order.URI, order.FinalizeURL
	order = validateOrder(t, ctx, victim, order)
	if order.FinalizeURL != "" {
		finalizeURL = order.FinalizeURL
	}

	t.Run("attacker cannot read the order", func(t *testing.T) {
		if got, err := attacker.GetOrder(ctx, orderURI); err == nil {
			t.Fatalf("attacker read another account's order: status=%q identifiers=%v", got.Status, got.Identifiers)
		}
	})

	t.Run("attacker cannot read the authorization", func(t *testing.T) {
		if got, err := attacker.GetAuthorization(ctx, authzURL); err == nil {
			t.Fatalf("attacker read another account's authorization for %v", got.Identifier)
		}
	})

	// Responding to a challenge is scoped to the owning account too (RFC 8555
	// §7.5.1). This route was missed when the four above were fixed: it looked the
	// challenge up by ID and acted on it with no ownership comparison, so any
	// registered account could drive validation state on a victim's authorization
	// — and for device-attest-01, bind its own key attestation to it.
	t.Run("attacker cannot accept a challenge", func(t *testing.T) {
		az, err := victim.GetAuthorization(ctx, authzURL)
		if err != nil {
			t.Fatalf("victim cannot read its own authorization: %v", err)
		}
		if len(az.Challenges) == 0 {
			t.Skip("no challenges on this authorization")
		}
		for _, ch := range az.Challenges {
			if _, err := attacker.Accept(ctx, ch); err == nil {
				t.Fatalf("attacker accepted another account's %s challenge at %s", ch.Type, ch.URI)
			}
		}
	})

	t.Run("attacker cannot finalize the order", func(t *testing.T) {
		csr := buildCSR(t, "victim-owned.test", []string{"victim-owned.test"})
		if der, _, err := attacker.CreateOrderCert(ctx, finalizeURL, csr, true); err == nil {
			t.Fatalf("attacker finalized another account's validated order and got %d bytes of certificate", len(der))
		}
	})

	// The victim's own use of every object must still work, so the guard cannot
	// be a blanket denial.
	t.Run("victim can still finalize and fetch", func(t *testing.T) {
		if _, err := victim.GetOrder(ctx, orderURI); err != nil {
			t.Fatalf("victim cannot read its own order: %v", err)
		}
		if _, err := victim.GetAuthorization(ctx, authzURL); err != nil {
			t.Fatalf("victim cannot read its own authorization: %v", err)
		}
		csr := buildCSR(t, "victim-owned.test", []string{"victim-owned.test"})
		der, certURL, err := victim.CreateOrderCert(ctx, finalizeURL, csr, true)
		if err != nil {
			t.Fatalf("victim cannot finalize its own order: %v", err)
		}
		if len(der) == 0 {
			t.Fatal("victim got no certificate")
		}

		// And the issued certificate is not readable by the attacker either.
		if certURL != "" {
			if _, err := attacker.FetchCert(ctx, certURL, true); err == nil {
				t.Fatal("attacker downloaded another account's issued certificate")
			} else if !strings.Contains(strings.ToLower(err.Error()), "certificate") {
				t.Logf("attacker refused with: %v", err)
			}
		}
	})
}
