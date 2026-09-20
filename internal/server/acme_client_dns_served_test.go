// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// A stock client owns its DNS credentials. With no matching managed DNS zone,
// its proof must reach the normal validator. PostgreSQL, NATS,
// and signing transport are real; only DNS lookup uses a controlled fixture.
func TestServedACMEClientPublishedDNSProof(t *testing.T) {
	for _, proof := range []string{"correct", "missing", "wrong"} {
		t.Run(proof, func(t *testing.T) {
			dns := newServedDNSWebhookFixture(t, "unused-client-dns-fixture")
			validators := acmesrv.Validators{DNS01: acmesrv.DNS01Validator{Resolver: dns}}
			h := newServedHarness(t,
				config.Protocols{ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
				func(d *Deps) { d.ACMEValidators = &validators },
			)
			ctx := context.Background()
			client, err := acmekey.NewClient(h.ts.URL + "/directory")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
				t.Fatal(err)
			}
			const domain = "client-dns.example.test"
			order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
			if err != nil {
				t.Fatal(err)
			}
			authz, err := client.GetAuthorization(ctx, order.AuthzURLs[0])
			if err != nil {
				t.Fatal(err)
			}
			var challenge *xacme.Challenge
			for _, ch := range authz.Challenges {
				if ch.Type == acmesrv.ChallengeDNS01 {
					challenge = ch
				}
			}
			if challenge == nil {
				t.Fatal("server did not offer DNS-01")
			}
			value, err := client.DNS01ChallengeRecord(challenge.Token)
			if err != nil {
				t.Fatal(err)
			}
			if proof == "wrong" {
				value = "incorrect-client-proof"
			}
			if proof != "missing" {
				dns.mu.Lock()
				dns.records[acmesrv.DNS01RecordName(domain)] = map[string]bool{value: true}
				dns.mu.Unlock()
			}
			_, err = client.Accept(ctx, challenge)
			if proof != "correct" {
				if err == nil {
					t.Fatal("server accepted missing or incorrect client DNS proof")
				}
				if !strings.Contains(err.Error(), "dns-01 TXT") {
					t.Fatalf("refusal did not come from the DNS proof validator: %v", err)
				}
				if h.hasEvent(t, "certificate.recorded") || h.hasEvent(t, "acme.challenge.validated") {
					t.Fatal("refused DNS proof produced validation or certificate evidence")
				}
			} else {
				if err != nil {
					t.Fatalf("correct client-published TXT was refused: %v", err)
				}
				order, err = client.WaitOrder(ctx, order.URI)
				if err != nil {
					t.Fatal(err)
				}
				chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, buildServedCSR(t, domain), true)
				if err != nil {
					t.Fatal(err)
				}
				if len(chain) != 2 {
					t.Fatalf("certificate chain has %d entries, want leaf and issuer", len(chain))
				}
				if err := crypto.VerifyLeafSignedByCA(chain[0], caCertDER(t, h.caPEM)); err != nil {
					t.Fatal(err)
				}
				if _, err := client.UpdateReg(ctx, &xacme.Account{Contact: []string{"mailto:client-dns@example.test"}}); err != nil {
					t.Fatal(err)
				}
				if err := client.DeactivateReg(ctx); err != nil {
					t.Fatalf("served account deactivation: %v", err)
				}
				_, err = client.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
				var problem *xacme.Error
				if !errors.As(err, &problem) || problem.StatusCode != http.StatusUnauthorized {
					t.Fatalf("served inactive account admitted: %v", err)
				}
				if h.hasEvent(t, "certificate.revoked") {
					t.Fatal("account deactivation revoked the leaf")
				}
			}
			dns.assertNeverRequested(t, acmesrv.DNS01RecordName(domain))
			if rows := servedOutboxRowsByDestination(t, h, "acme.dns01."); len(rows) != 0 {
				t.Fatalf("client-managed DNS unexpectedly queued server-side writes: %v", rows)
			}
		})
	}
}
