// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"net/http"
	"strings"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// CR-051: the managed zone alone cannot authorize publication. An account
// without current publication authority must supply its own DNS proof.
func TestServedACMEDNS01RequiresActiveIdentifierScopeForPublication(t *testing.T) {
	const (
		zone   = "managed-dns.example.test"
		issuer = "trstctl.example.test"
	)
	dns := newServedDNSWebhookFixture(t, "managed-dns-fixture")
	validators := acmesrv.Validators{DNS01: acmesrv.DNS01Validator{Resolver: dns}}
	cases := []struct {
		name      string
		scope     []string
		quota     int
		wildcard  bool
		publishes bool
	}{
		{name: "no-binding"},
		{name: "unscoped"},
		{name: "disabled", scope: []string{"disabled." + zone}},
		{name: "expired", scope: []string{"expired." + zone}},
		{name: "quota-exhausted", scope: []string{"quota-exhausted." + zone}, quota: 1},
		{name: "narrowed-wildcard", scope: []string{"*.narrowed-wildcard." + zone}, wildcard: true},
		{name: "scoped-wildcard", scope: []string{"*.scoped-wildcard." + zone}, wildcard: true, publishes: true},
		{name: "missing-key", scope: []string{"missing-key." + zone}},
	}
	keys := make([]config.ACMEExternalAccountBindingKey, 0, len(cases)-1)
	for i, tc := range cases[1:] {
		keys = append(keys, config.ACMEExternalAccountBindingKey{
			KeyID: tc.name, HMACKey: bytes.Repeat([]byte{byte(i + 1)}, 32),
			AllowedIdentifiers: tc.scope, MaxOrders: tc.quota,
		})
	}
	h := newServedHarness(t, config.Protocols{
		ACME:    config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		ACMEEAB: config.ACMEExternalAccountBinding{Keys: keys},
	}, withSecretsEnabled(t, nil), func(d *Deps) { d.ACMEValidators = &validators })
	registerServedTenant(t, h, "ACME managed DNS tenant")
	h.srv.acmeDNS01.caaResolver = dns
	dns.setCAA(zone, []acmesrv.CAARecord{{Tag: "issue", Value: issuer}})
	startServedDirectOutboxPump(t, h.srv)
	tok := seedScopedToken(t, h.store, h.tenant, "issuers:read", "issuers:write", "secrets:read", "secrets:write")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok, map[string]any{
		"name": "dns/managed/fixture", "value": "managed-dns-fixture",
	})
	if status != http.StatusCreated {
		t.Fatalf("store DNS webhook fixture: %d %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/provider-configs", tok, map[string]any{
		"name": "managed-dns", "provider": "webhook", "zone": zone,
		"credential_refs": map[string]any{"bearer_token_ref": "secret://dns/managed/fixture"}, // #nosec G101 -- logical fixture reference (CWE-798)
		"config":          map[string]any{"endpoint": dns.URL()},
		"allowed_methods": []string{"dns-01"}, "allow_wildcards": true, "caa_issuer_domain": issuer,
	})
	if status != http.StatusCreated {
		t.Fatalf("configure DNS webhook fixture: %d %s", status, body)
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			var client *xacme.Client
			if tc.name == "no-binding" {
				var err error
				client, err = acmekey.NewClient(h.ts.URL + "/directory")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
					t.Fatal(err)
				}
			} else {
				client = registerWithEAB(t, h, tc.name, keys[i-1].HMACKey)
			}
			domain := tc.name + "." + zone
			identifier := domain
			if tc.wildcard {
				identifier = "*." + domain
			}
			order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(identifier))
			if err != nil {
				t.Fatalf("create pending order: %v", err)
			}
			authz, err := client.GetAuthorization(ctx, order.AuthzURLs[0])
			if err != nil {
				t.Fatal(err)
			}
			if len(authz.Challenges) != 1 || authz.Challenges[0].Type != acmesrv.ChallengeDNS01 {
				t.Fatalf("expected only the requested DNS-01 challenge: %#v", authz.Challenges)
			}
			challenge := authz.Challenges[0]
			switch tc.name {
			case "disabled":
				if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/acme/eab-credentials/disabled/disable", tok, nil); status != http.StatusOK {
					t.Fatalf("disable credential: %d %s", status, body)
				}
			case "expired", "narrowed-wildcard":
				update := map[string]any{"allowed_identifiers": []string{domain}}
				if tc.name == "expired" {
					update["not_after"] = time.Now().Add(-time.Hour).Format(time.RFC3339)
				}
				path := "/api/v1/acme/eab-credentials/" + tc.name + "/policy"
				if status, body := secretsReq(t, h, http.MethodPut, path, tok, update); status != http.StatusOK {
					t.Fatalf("change credential policy: %d %s", status, body)
				}
			case "missing-key":
				if _, err := h.srv.protocols.acme.WithExternalAccountBindings(false, nil); err != nil {
					t.Fatalf("remove configured credential: %v", err)
				}
			}

			record := acmesrv.DNS01RecordName(identifier)
			value, err := client.DNS01ChallengeRecord(challenge.Token)
			if err != nil {
				t.Fatal(err)
			}
			baseline := servedOutboxRowsByDestination(t, h, "acme.dns01.")
			if tc.publishes {
				if _, err := client.Accept(ctx, challenge); err != nil {
					t.Fatalf("managed publication for scoped wildcard: %v", err)
				}
				if _, err := client.WaitAuthorization(ctx, authz.URI); err != nil {
					t.Fatalf("wait for managed validation: %v", err)
				}
				dns.assertPresentedAndCleaned(t, record, value)
				baseline["acme.dns01.present:delivered"]++
				baseline["acme.dns01.cleanup:delivered"]++
				if rows := servedOutboxRowsByDestination(t, h, "acme.dns01."); !maps.Equal(rows, baseline) {
					t.Fatalf("scoped wildcard DNS outbox = %v, want %v", rows, baseline)
				}
				return
			}
			_, err = client.Accept(ctx, challenge)
			var problem *xacme.Error
			if !errors.As(err, &problem) || problem.StatusCode != http.StatusBadRequest ||
				!strings.Contains(problem.Detail, "dns-01 TXT") {
				t.Errorf("challenge without client proof = %v, want DNS-01 validator refusal", err)
			}
			if rows := servedOutboxRowsByDestination(t, h, "acme.dns01."); !maps.Equal(rows, baseline) {
				t.Fatalf("challenge without publication authority changed the DNS outbox: before %v, after %v", baseline, rows)
			}
			dns.setTXT(record, value)
			if tc.name == "no-binding" {
				dns.setCAA(domain, []acmesrv.CAARecord{{Tag: "issue", Value: "different-issuer.example.test"}})
				_, err = client.Accept(ctx, challenge)
				if !errors.As(err, &problem) || problem.StatusCode != http.StatusBadRequest ||
					!strings.Contains(problem.Detail, "CAA") {
					t.Fatalf("client-managed TXT with denying CAA = %v, want CAA refusal", err)
				}
				dns.setCAA(domain, []acmesrv.CAARecord{{Tag: "issue", Value: issuer}})
			}
			if _, err := client.Accept(ctx, challenge); err != nil {
				t.Fatalf("correct client-published TXT refused: %v", err)
			}
			if _, err := client.WaitAuthorization(ctx, authz.URI); err != nil {
				t.Fatalf("wait for client-managed validation: %v", err)
			}
			dns.assertNeverRequested(t, record)
			if rows := servedOutboxRowsByDestination(t, h, "acme.dns01."); !maps.Equal(rows, baseline) {
				t.Fatalf("client-managed validation changed the DNS outbox: before %v, after %v", baseline, rows)
			}
		})
	}
}
