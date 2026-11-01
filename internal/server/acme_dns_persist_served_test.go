// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// challengeNames reads issuer-domain-names from the served authorization
// responses, as a draft client does.
type challengeNames struct {
	mu    sync.Mutex
	names map[string][]string
}

func (c *challengeNames) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil || resp.Body == nil {
		return resp, err
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	var doc struct {
		Challenges []struct {
			Type    string   `json:"type"`
			URL     string   `json:"url"`
			Issuers []string `json:"issuer-domain-names"`
		} `json:"challenges"`
	}
	if json.Unmarshal(body, &doc) == nil {
		c.mu.Lock()
		for _, ch := range doc.Challenges {
			if ch.Type == acmesrv.ChallengeDNSPersist01 {
				c.names[ch.URL] = ch.Issuers
			}
		}
		c.mu.Unlock()
	}
	return resp, nil
}

// P1: protocols.acme_dns_persist makes the served ACME server offer
// dns-persist-01 naming this CA; a draft client publishes one standing record
// and two orders validate against it, the second with no DNS change.
func TestServedACMEDNSPersistP1(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	client, err := acmekey.NewClient(h.ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	seen := &challengeNames{names: map[string][]string{}}
	client.HTTPClient = &http.Client{Transport: seen, Timeout: 30 * time.Second}
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatal(err)
	}
	const domain = "persist.served.test"
	writes := 0
	issue := func() {
		t.Helper()
		order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
		if err != nil {
			t.Fatal(err)
		}
		for _, authzURL := range order.AuthzURLs {
			authz, err := client.GetAuthorization(ctx, authzURL)
			if err != nil {
				t.Fatal(err)
			}
			var chal *xacme.Challenge
			for _, c := range authz.Challenges {
				if c.Type == acmesrv.ChallengeDNSPersist01 {
					chal = c
				}
			}
			if chal == nil {
				t.Fatalf("the served ACME server offered no dns-persist-01: %+v", authz.Challenges)
			}
			seen.mu.Lock()
			issuers := seen.names[chal.URI]
			seen.mu.Unlock()
			if strings.Join(issuers, ",") != "ca.served.test" {
				t.Fatalf("issuer-domain-names = %v", issuers)
			}
			name := acmesrv.DNSPersistRecordName(domain)
			if want := acmesrv.DNSPersistRecordValue(issuers[0], string(client.KID), false); len(zone.txt[name]) != 1 || zone.txt[name][0] != want {
				zone.txt[name] = []string{want}
				writes++
			}
			if _, err := client.Accept(ctx, chal); err != nil {
				t.Fatalf("accept dns-persist-01: %v", err)
			}
			if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
				t.Fatalf("wait authorization: %v", err)
			}
		}
		if order, err = client.WaitOrder(ctx, order.URI); err != nil {
			t.Fatal(err)
		}
		der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, buildServedCSR(t, domain), true)
		if err != nil || len(der) == 0 {
			t.Fatalf("finalize: %v", err)
		}
	}
	issue()
	issue()
	if writes != 1 {
		t.Fatalf("%d DNS writes across two orders, want 1", writes)
	}
}
