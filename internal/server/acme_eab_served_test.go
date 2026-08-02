// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/acmekey"
)

// External Account Binding as authorization, proven on the assembled binary
// (epic B4).
//
// The server verified the EAB MAC and discarded the kid, so every account it
// admitted was identical: nothing recorded which credential let it in, and
// therefore nothing could scope what it asked for next, count what it had taken,
// or stop one credential without stopping all of them.
//
// These drive a stock x/crypto/acme client against the served mount and assert
// the four things that were missing: the kid is remembered, an out-of-scope
// identifier is refused fail-closed, the quota is enforced per credential, and an
// operator can switch one credential off through the served API while another
// keeps working.

func acmeEABScopedHarness(t *testing.T, keys []config.ACMEExternalAccountBindingKey) *servedHarness {
	t.Helper()
	return newServedHarness(t, config.Protocols{
		ACME:    config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		ACMEEAB: config.ACMEExternalAccountBinding{Required: true, Keys: keys},
	})
}

func registerWithEAB(t *testing.T, h *servedHarness, kid string, hmacKey []byte) *xacme.Client {
	t.Helper()
	client, err := acmekey.NewClient(h.ts.URL + "/directory")
	if err != nil {
		t.Fatalf("acme client: %v", err)
	}
	if _, err := client.Register(context.Background(), &xacme.Account{
		ExternalAccountBinding: &xacme.ExternalAccountBinding{KID: kid, Key: hmacKey},
	}, xacme.AcceptTOS); err != nil {
		t.Fatalf("register with EAB %q: %v", kid, err)
	}
	return client
}

func TestServedACMEEABScopesOrdersToItsAllowedIdentifiers(t *testing.T) {
	hmacKey := bytes.Repeat([]byte{0x42}, 32)
	h := acmeEABScopedHarness(t, []config.ACMEExternalAccountBindingKey{{
		KeyID: "payments-team", HMACKey: hmacKey,
		AllowedIdentifiers: []string{"*.payments.example.test"},
	}})
	client := registerWithEAB(t, h, "payments-team", hmacKey)
	ctx := context.Background()

	// Inside the credential's scope: accepted.
	if _, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("api.payments.example.test")); err != nil {
		t.Fatalf("in-scope order rejected: %v", err)
	}
	// The wildcard covers the apex too, which is what an operator granting
	// "*.payments.example.test" means.
	if _, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("payments.example.test")); err != nil {
		t.Fatalf("apex of the granted suffix rejected: %v", err)
	}

	// Outside it: refused fail-closed, naming the identifier and the credential.
	_, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("api.billing.example.test"))
	if err == nil {
		t.Fatal("served ACME accepted an order for an identifier outside the credential's scope; the kid is not being enforced")
	}
	if !strings.Contains(err.Error(), "billing.example.test") || !strings.Contains(err.Error(), "payments-team") {
		t.Fatalf("denial must name the identifier and the credential, got %v", err)
	}

	// A single out-of-scope identifier poisons the whole order — an order is
	// granted or it is not; there is no partial issuance.
	if _, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("api.payments.example.test", "api.billing.example.test")); err == nil {
		t.Fatal("served ACME accepted a mixed order containing an out-of-scope identifier")
	}
}

func TestServedACMEEABEnforcesItsOrderQuota(t *testing.T) {
	hmacKey := bytes.Repeat([]byte{0x43}, 32)
	h := acmeEABScopedHarness(t, []config.ACMEExternalAccountBindingKey{{
		KeyID: "capped", HMACKey: hmacKey, MaxOrders: 2,
	}})
	client := registerWithEAB(t, h, "capped", hmacKey)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if _, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("a.example.test")); err != nil {
			t.Fatalf("order %d inside the quota was rejected: %v", i+1, err)
		}
	}
	if _, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("a.example.test")); err == nil {
		t.Fatal("served ACME accepted an order past the credential's quota")
	}
}

func TestServedACMEEABRefusesAnExpiredCredential(t *testing.T) {
	hmacKey := bytes.Repeat([]byte{0x44}, 32)
	h := acmeEABScopedHarness(t, []config.ACMEExternalAccountBindingKey{{
		KeyID: "closed-window", HMACKey: hmacKey,
		NotAfter: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	}})

	client, err := acmekey.NewClient(h.ts.URL + "/directory")
	if err != nil {
		t.Fatalf("acme client: %v", err)
	}
	_, err = client.Register(context.Background(), &xacme.Account{
		ExternalAccountBinding: &xacme.ExternalAccountBinding{KID: "closed-window", Key: hmacKey},
	}, xacme.AcceptTOS)
	if err == nil {
		t.Fatal("served ACME admitted an account under a credential whose validity window has closed")
	}
	if !strings.Contains(err.Error(), "validity window") {
		t.Fatalf("refusal must name the cause, got %v", err)
	}
}

func TestServedACMEEABOperatorSurfaceListsScopeAndDisablesOneCredential(t *testing.T) {
	payments := bytes.Repeat([]byte{0x45}, 32)
	billing := bytes.Repeat([]byte{0x46}, 32)
	h := acmeEABScopedHarness(t, []config.ACMEExternalAccountBindingKey{
		{KeyID: "payments-team", HMACKey: payments, AllowedIdentifiers: []string{"*.payments.example.test"}, MaxOrders: 10},
		{KeyID: "billing-team", HMACKey: billing, AllowedIdentifiers: []string{"*.billing.example.test"}},
	})
	tok := seedScopedToken(t, h.store, h.tenant, "issuers:read", "issuers:write")
	ctx := context.Background()

	paymentsClient := registerWithEAB(t, h, "payments-team", payments)
	if _, err := paymentsClient.AuthorizeOrder(ctx, xacme.DomainIDs("api.payments.example.test")); err != nil {
		t.Fatalf("in-scope order rejected: %v", err)
	}

	// The read surface carries scope and live usage, and no secret in any form.
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/acme/eab-credentials", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list EAB credentials = %d, want 200; body=%s", status, body)
	}
	var posture struct {
		Served   bool `json:"served"`
		Required bool `json:"required"`
		Items    []struct {
			KeyID              string   `json:"key_id"`
			State              string   `json:"state"`
			AllowedIdentifiers []string `json:"allowed_identifiers"`
			MaxOrders          int      `json:"max_orders"`
			AccountsBound      int      `json:"accounts_bound"`
			OrdersCreated      int      `json:"orders_created"`
			OrdersDenied       int      `json:"orders_denied"`
			DisabledByOperator bool     `json:"disabled_by_operator"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &posture); err != nil {
		t.Fatalf("decode EAB posture: %v body=%s", err, body)
	}
	if !posture.Served || !posture.Required {
		t.Fatalf("posture = served %v required %v, want both true", posture.Served, posture.Required)
	}
	if len(posture.Items) != 2 {
		t.Fatalf("listed %d credentials, want 2; body=%s", len(posture.Items), body)
	}
	if posture.Items[0].KeyID != "billing-team" || posture.Items[1].KeyID != "payments-team" {
		t.Fatalf("credentials are not sorted by key id: %+v", posture.Items)
	}
	pay := posture.Items[1]
	if pay.State != "active" || pay.AccountsBound != 1 || pay.OrdersCreated != 1 {
		t.Fatalf("payments credential usage = %+v, want active with one account and one order", pay)
	}
	if len(pay.AllowedIdentifiers) != 1 || pay.AllowedIdentifiers[0] != "*.payments.example.test" || pay.MaxOrders != 10 {
		t.Fatalf("payments credential scope = %+v", pay)
	}
	// The HMAC key must not appear anywhere in the served response, in any
	// encoding an operator or a log shipper could pick up.
	for _, forbidden := range []string{"hmac", "0x45", "RUVFRQ", strings.Repeat("E", 8)} {
		if bytes.Contains(bytes.ToLower(body), bytes.ToLower([]byte(forbidden))) {
			t.Fatalf("served EAB posture leaks credential material (%q): %s", forbidden, body)
		}
	}

	// Disabling one credential stops new work under it.
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/acme/eab-credentials/payments-team/disable", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("disable = %d, want 200; body=%s", status, body)
	}
	if !bytes.Contains(body, []byte(`"disabled_by_operator":true`)) || !bytes.Contains(body, []byte(`"state":"disabled"`)) {
		t.Fatalf("disable response does not reflect the new state: %s", body)
	}

	// A new account under the disabled credential is refused...
	disabledClient, err := acmekey.NewClient(h.ts.URL + "/directory")
	if err != nil {
		t.Fatalf("acme client: %v", err)
	}
	_, err = disabledClient.Register(ctx, &xacme.Account{
		ExternalAccountBinding: &xacme.ExternalAccountBinding{KID: "payments-team", Key: payments},
	}, xacme.AcceptTOS)
	if err == nil {
		t.Fatal("served ACME admitted an account under a credential an operator disabled")
	}
	// ...and so is a new order on the account that already existed, without
	// touching anything already issued under it.
	if _, err := paymentsClient.AuthorizeOrder(ctx, xacme.DomainIDs("api.payments.example.test")); err == nil {
		t.Fatal("served ACME accepted an order under a credential an operator disabled")
	}

	// The other credential is untouched: disabling is per-credential, which is
	// the whole reason for binding accounts to a kid.
	billingClient := registerWithEAB(t, h, "billing-team", billing)
	if _, err := billingClient.AuthorizeOrder(ctx, xacme.DomainIDs("api.billing.example.test")); err != nil {
		t.Fatalf("an unrelated credential stopped working when another was disabled: %v", err)
	}

	// Re-enabling restores it.
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/acme/eab-credentials/payments-team/enable", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("enable = %d, want 200; body=%s", status, body)
	}
	if _, err := paymentsClient.AuthorizeOrder(ctx, xacme.DomainIDs("api.payments.example.test")); err != nil {
		t.Fatalf("order rejected after the credential was re-enabled: %v", err)
	}

	// The denial that happened while it was disabled is counted, so an operator
	// can see a credential being used for work it is not allowed to do.
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/acme/eab-credentials", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("re-list = %d, want 200", status)
	}
	if err := json.Unmarshal(body, &posture); err != nil {
		t.Fatalf("decode EAB posture: %v", err)
	}
	if posture.Items[1].OrdersDenied == 0 {
		t.Fatalf("denials are not counted against the credential: %+v", posture.Items[1])
	}

	// An unknown kid is a 404, not a silent success.
	status, _ = secretsReq(t, h, http.MethodPost, "/api/v1/acme/eab-credentials/no-such-kid/disable", tok, nil)
	if status != http.StatusNotFound {
		t.Fatalf("disable of an unknown credential = %d, want 404", status)
	}
}
