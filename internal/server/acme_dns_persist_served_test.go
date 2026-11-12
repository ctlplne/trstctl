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
	"trstctl.com/trstctl/internal/crypto/certinfo"
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

// askedTXT records every name the served validator reads.
type askedTXT struct {
	persistTXT
	asked []string
}

func (r *askedTXT) LookupTXT(ctx context.Context, name string) ([]string, error) {
	r.mu.Lock()
	r.asked = append(r.asked, name)
	r.mu.Unlock()
	return r.persistTXT.LookupTXT(ctx, name)
}

// P1-L2: one standing record with policy=wildcard at a domain authorizes its
// subdomains through the served ACME server; without policy=wildcard it
// authorizes its own name only, and nothing above the registrable domain is
// read.
func TestServedACMEDNSPersistPolicyWildcardCoversSubdomainsP1L2(t *testing.T) {
	zone := &askedTXT{persistTXT: persistTXT{txt: map[string][]string{}}}
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
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	client, err := acmekey.NewClient(h.ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	client.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatal(err)
	}
	account := string(client.KID)
	zone.mu.Lock()
	zone.txt["_validation-persist.wild.p1l2.test"] = []string{acmesrv.DNSPersistRecordValue("ca.served.test", account, true)}
	zone.txt["_validation-persist.plain.p1l2.test"] = []string{acmesrv.DNSPersistRecordValue("ca.served.test", account, false)}
	zone.txt["_validation-persist.test"] = []string{acmesrv.DNSPersistRecordValue("ca.served.test", account, true)}
	zone.mu.Unlock()

	order := func(domain string) error {
		t.Helper()
		o, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
		if err != nil {
			return err
		}
		for _, authzURL := range o.AuthzURLs {
			authz, err := client.GetAuthorization(ctx, authzURL)
			if err != nil {
				return err
			}
			var chal *xacme.Challenge
			for _, c := range authz.Challenges {
				if c.Type == acmesrv.ChallengeDNSPersist01 {
					chal = c
				}
			}
			if chal == nil {
				t.Fatalf("no dns-persist-01 offered for %s", domain)
			}
			if _, err := client.Accept(ctx, chal); err != nil {
				return err
			}
			if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
				return err
			}
		}
		if o, err = client.WaitOrder(ctx, o.URI); err != nil {
			return err
		}
		der, _, err := client.CreateOrderCert(ctx, o.FinalizeURL, buildServedCSR(t, domain), true)
		if err != nil {
			return err
		}
		leaf, err := certinfo.Inspect(der[0])
		if err != nil {
			return err
		}
		if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != domain {
			t.Fatalf("issued for %v, want %s", leaf.DNSNames, domain)
		}
		return nil
	}

	// Two subdomains, one two labels down, validate against the one record
	// at wild.p1l2.test; neither has a record of its own.
	for _, domain := range []string{"www.wild.p1l2.test", "a.b.wild.p1l2.test"} {
		if err := order(domain); err != nil {
			t.Fatalf("%s under a policy=wildcard record at its parent: %v", domain, err)
		}
	}
	zone.mu.Lock()
	asked := strings.Join(zone.asked, ",")
	zone.asked = nil
	zone.mu.Unlock()
	if !strings.Contains(asked, "_validation-persist.a.b.wild.p1l2.test,_validation-persist.b.wild.p1l2.test,_validation-persist.wild.p1l2.test") {
		t.Fatalf("read %s, want the name's own record, then its parents nearest first", asked)
	}

	// Without policy=wildcard the record authorizes its own name only.
	if err := order("www.plain.p1l2.test"); err == nil || !strings.Contains(err.Error(), "does not allow subdomains (policy=wildcard)") {
		t.Fatalf("a subdomain under a record without policy=wildcard: %v", err)
	}
	if err := order("plain.p1l2.test"); err != nil {
		t.Fatalf("the record's own name: %v", err)
	}
	// A record above the registrable domain (p1l2.test) is never read.
	if err := order("www.none.p1l2.test"); err == nil || !strings.Contains(err.Error(), "no TXT record at _validation-persist.www.none.p1l2.test names this CA, nor at a parent domain up to _validation-persist.p1l2.test") {
		t.Fatalf("a name with no record up to its registrable domain: %v", err)
	}
	zone.mu.Lock()
	defer zone.mu.Unlock()
	for _, name := range zone.asked {
		if name == "_validation-persist.test" {
			t.Fatal("the served validator read a record above the registrable domain")
		}
	}
}
