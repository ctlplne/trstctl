// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// P1-L3: a tenant's domain-validation policy (its DNS-01 provider config's
// allowed_methods) may require dns-persist-01. Saved through the API, it
// makes the served ACME server offer exactly that challenge for the zone's
// names, a wildcard included (its standing record carries policy=wildcard),
// and an order validates against the standing record.
func TestServedACMEDVPolicyMayRequireDNSPersistP1L3(t *testing.T) {
	zone := &persistTXT{txt: map[string][]string{}}
	validators := acmesrv.Validators{
		HTTP01: acmesrv.HTTP01Validator{}, DNS01: acmesrv.DNS01Validator{},
		DNSPersist01: acmesrv.DNSPersistValidator{Resolver: zone},
	}
	h := newOperatingServedHarness(t,
		config.Protocols{
			ACME:           config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
			ACMEDNSPersist: config.ACMEDNSPersist{IssuerDomainNames: []string{"ca.served.test"}},
		},
		func(d *Deps) { d.ACMEValidators = &validators },
	)
	tok := seedScopedToken(t, h.store, h.tenant, "issuers:read", "issuers:write")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/provider-configs", tok, map[string]any{
		"name": "persist-policy", "provider": "cloudflare", "zone": "policy.served.test",
		"credential_refs": map[string]any{ // #nosec G101 -- fabricated fixture reference, no value is real (CWE-798)
			"api_token_ref": "secret://dns/cloudflare/persist-policy",
		},
		"config":          map[string]any{"zone_id": "zone-persist"},
		"allowed_methods": []string{"dns-persist-01"},
		"allow_wildcards": true,
	})
	if status != http.StatusCreated {
		t.Fatalf("a DV policy requiring dns-persist-01 = %d %s, want 201", status, body)
	}
	var saved struct {
		AllowedMethods []string `json:"allowed_methods"`
	}
	if err := json.Unmarshal(body, &saved); err != nil || !slices.Equal(saved.AllowedMethods, []string{"dns-persist-01"}) {
		t.Fatalf("saved allowed_methods = %v (%v)", saved.AllowedMethods, err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	client, err := acmekey.NewClient(h.ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	client.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"www.policy.served.test", "*.policy.served.test"} {
		order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
		if err != nil {
			t.Fatalf("order %s under the dns-persist-01 policy: %v", domain, err)
		}
		for _, authzURL := range order.AuthzURLs {
			authz, err := client.GetAuthorization(ctx, authzURL)
			if err != nil {
				t.Fatal(err)
			}
			var offered []string
			var chal *xacme.Challenge
			for _, c := range authz.Challenges {
				offered = append(offered, c.Type)
				if c.Type == acmesrv.ChallengeDNSPersist01 {
					chal = c
				}
			}
			if !slices.Equal(offered, []string{acmesrv.ChallengeDNSPersist01}) {
				t.Fatalf("%s was offered %v, want only dns-persist-01 under the policy", domain, offered)
			}
			wildcard := acmesrv.IsWildcard(domain)
			zone.mu.Lock()
			zone.txt[acmesrv.DNSPersistRecordName(domain)] = []string{acmesrv.DNSPersistRecordValue("ca.served.test", string(client.KID), wildcard)}
			zone.mu.Unlock()
			if _, err := client.Accept(ctx, chal); err != nil {
				t.Fatalf("accept dns-persist-01 for %s: %v", domain, err)
			}
			if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
				t.Fatalf("%s did not validate against its standing record: %v", domain, err)
			}
		}
		if domain != "www.policy.served.test" {
			continue
		}
		if order, err = client.WaitOrder(ctx, order.URI); err != nil {
			t.Fatal(err)
		}
		if der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, buildServedCSR(t, domain), true); err != nil || len(der) == 0 {
			t.Fatalf("finalize %s: %v", domain, err)
		}
	}
}
