// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/ca/digicert/digicertfake"
	"trstctl.com/trstctl/internal/config"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// A165 Done-when: unattended domain validation works for more than the ACME
// issuer kind. A DigiCert authority that opts into upstream DNS validation
// completes CertCentral's DNS TXT validation with no human step: trstctl
// publishes the order's value at _dnsauth.<name> through the tenant's DNS-01
// provider config, CertCentral sees it and issues, and the record is retracted.
// Without a provider config that consented to upstream validation, nothing is
// published and the issue is refused.
func TestServedDigiCertDomainValidationCompletesUnattended(t *testing.T) {
	dns := newServedDNSWebhookFixture(t, "dcv-webhook-token")
	dc, err := digicertfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dc.Close)
	dc.RequireDCV(func(name string) []string {
		values, _ := dns.LookupTXT(context.Background(), name)
		return values
	})
	keyFile := filepath.Join(t.TempDir(), "digicert-api-key")
	if err := os.WriteFile(keyFile, []byte(dc.APIKey()), 0o600); err != nil {
		t.Fatal(err)
	}
	endpoint, err := url.Parse(dc.URL())
	if err != nil {
		t.Fatal(err)
	}
	address := netip.MustParseAddr(endpoint.Hostname())
	// The running server fills this seam with its DNS-01 automation, as run.go
	// does for the configured authorities.
	holder := &upstreamDVHolder{}
	upstreams, err := externalCAsFromConfig(context.Background(), []config.ExternalCAConfig{{
		ID: "corp-digicert", Type: "digicert", Name: "Corp DigiCert", Endpoint: dc.URL(), APIKeyRef: "file:" + keyFile,
		UpstreamDNS01: true, CAAIssuerDomain: "digicert.com", PollInterval: "10ms",
		Network: config.ExternalCANetworkConfig{AllowInsecureHTTP: true, AllowPrivateEndpoint: true,
			PrivateEgressCIDRs: []string{netip.PrefixFrom(address, 32).String()}, Timeout: "10s"},
	}}, nil, nil, nil, holder)
	if err != nil {
		t.Fatalf("configure the DigiCert authority with upstream DNS validation: %v", err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.APIOptions = append(d.APIOptions, api.WithInsecureHeaderResolver())
		d.ExternalCAs = upstreams
		d.UpstreamDV = holder
	})
	h.srv.acmeDNS01.caaResolver = dns
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "issuers:read", "issuers:write", "secrets:read", "secrets:write")
	issue := func(name, key string) (int, []byte) {
		t.Helper()
		csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: externalCACSR(t, name)})
		return doExternalCARequest(t, h, http.MethodPost, "/api/v1/external-cas/corp-digicert/issue", key, map[string]any{
			"csr_pem": string(csrPEM), "dns_names": []string{name}, "ttl_seconds": int64((24 * time.Hour).Seconds()),
		})
	}

	// No provider config has consented to upstream validation yet.
	if code, body := issue("first.dcv.test", "a165-no-consent"); code == http.StatusCreated {
		t.Fatalf("an issue with no consenting DNS-01 provider config = %d %s; want refused", code, body)
	}
	dns.assertNeverRequested(t, "_dnsauth.first.dcv.test")

	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok, map[string]any{
		"name": "dns/dcv/bearer-token", "value": "dcv-webhook-token",
	}); status != http.StatusCreated {
		t.Fatalf("store the DNS webhook token: %d %s", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/provider-configs", tok, map[string]any{
		"name": "a165-dcv-webhook", "provider": "webhook", "zone": "dcv.test",
		"credential_refs": map[string]any{"bearer_token_ref": "secret://dns/dcv/bearer-token"}, // #nosec G101 -- secret reference, no credential value (CWE-798)
		"config":          map[string]any{"endpoint": dns.URL()},
		"allowed_methods": []string{"dns-01"}, "allow_upstream_dv": true,
	}); status != http.StatusCreated {
		t.Fatalf("create the consenting DNS-01 provider config: %d %s", status, body)
	}
	dns.setCAA("dcv.test", []acmesrv.CAARecord{{Tag: "issue", Value: "digicert.com"}})

	code, body := issue("app.dcv.test", "a165-dcv")
	var issued externalCAIssueResponse
	if code != http.StatusCreated || json.Unmarshal(body, &issued) != nil || !strings.Contains(issued.CertificatePEM, "BEGIN CERTIFICATE") {
		t.Fatalf("issue through DigiCert with unattended DCV = %d %s", code, body)
	}
	if values, _ := dns.LookupTXT(context.Background(), "_dnsauth.app.dcv.test"); len(values) != 0 {
		t.Fatalf("the DCV record is still published after issuance: %v", values)
	}
	// A165-L2: the validation is recorded like an upstream ACME authorization,
	// as one this install earned by publishing the record (not a reuse) ...
	auditor := seedScopedTokenSubject(t, h.store, h.tenant, "a165-dv-auditor", "audit:read")
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/audit/events?type=acme.dns01.upstream.authorization.observed&limit=10", auditor, nil)
	var observedEvents struct {
		Events []struct {
			Data struct {
				Identifier    string `json:"identifier"`
				ChallengeType string `json:"challenge_type"`
				Reused        bool   `json:"reused"`
			} `json:"data"`
		} `json:"events"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &observedEvents) != nil || len(observedEvents.Events) != 1 ||
		observedEvents.Events[0].Data.Identifier != "app.dcv.test" || observedEvents.Events[0].Data.ChallengeType != "dns-txt" ||
		observedEvents.Events[0].Data.Reused {
		t.Fatalf("DigiCert's validation of app.dcv.test as an upstream authorization event = %d %s", status, raw)
	}
	// ... and the projection that keeps "last validated" apart from "last
	// reused" takes it like an ACME authorization.
	tailCtx, stopTail := context.WithTimeout(context.Background(), 20*time.Second)
	defer stopTail()
	go func() { _ = h.srv.tailWorker.Run(tailCtx) }()
	var validated bool
	for !validated && tailCtx.Err() == nil {
		observed, err := h.store.ListACMEUpstreamAuthorizations(tailCtx, h.tenant)
		if err != nil && tailCtx.Err() == nil {
			t.Fatal(err)
		}
		for _, a := range observed {
			if a.Identifier == "app.dcv.test" && a.ChallengeType == "dns-txt" && a.ValidateCount == 1 && a.ReuseCount == 0 && !a.LastValidatedAt.IsZero() {
				validated = true
			}
		}
		if !validated {
			time.Sleep(50 * time.Millisecond)
		}
	}
	stopTail()
	if !validated {
		t.Fatal("DigiCert's validation of app.dcv.test never reached the upstream authorization view")
	}

	// CAA that does not authorize DigiCert stops the publish.
	dns.setCAA("caa.dcv.test", []acmesrv.CAARecord{{Tag: "issue", Value: "other-ca.example"}})
	if code, body := issue("caa.dcv.test", "a165-caa"); code == http.StatusCreated {
		t.Fatalf("an issue whose CAA names another CA = %d %s; want refused", code, body)
	}
	dns.assertNeverRequested(t, "_dnsauth.caa.dcv.test")
}

// A165-L3 Done-when (served, DigiCert stand-in): a wildcard order validates
// its base name the way CertCentral asks (the record at _dnsauth.<base>), and
// the wildcard is held to the same rules an upstream ACME wildcard is — a
// DNS-01 provider config that does not allow wildcards refuses it, and so does
// CAA whose issuewild does not name the authority — with nothing published
// for a refused order.
func TestServedDigiCertWildcardValidatesTheBaseNameUnderWildcardRulesA165L3(t *testing.T) {
	dns := newServedDNSWebhookFixture(t, "dcv-webhook-token")
	dc, err := digicertfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dc.Close)
	dc.RequireDCV(func(name string) []string {
		values, _ := dns.LookupTXT(context.Background(), name)
		return values
	})
	keyFile := filepath.Join(t.TempDir(), "digicert-api-key")
	if err := os.WriteFile(keyFile, []byte(dc.APIKey()), 0o600); err != nil {
		t.Fatal(err)
	}
	endpoint, err := url.Parse(dc.URL())
	if err != nil {
		t.Fatal(err)
	}
	address := netip.MustParseAddr(endpoint.Hostname())
	holder := &upstreamDVHolder{}
	upstreams, err := externalCAsFromConfig(context.Background(), []config.ExternalCAConfig{{
		ID: "corp-digicert", Type: "digicert", Name: "Corp DigiCert", Endpoint: dc.URL(), APIKeyRef: "file:" + keyFile,
		UpstreamDNS01: true, CAAIssuerDomain: "digicert.com", PollInterval: "10ms",
		Network: config.ExternalCANetworkConfig{AllowInsecureHTTP: true, AllowPrivateEndpoint: true,
			PrivateEgressCIDRs: []string{netip.PrefixFrom(address, 32).String()}, Timeout: "10s"},
	}}, nil, nil, nil, holder)
	if err != nil {
		t.Fatalf("configure the DigiCert authority with upstream DNS validation: %v", err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.APIOptions = append(d.APIOptions, api.WithInsecureHeaderResolver())
		d.ExternalCAs = upstreams
		d.UpstreamDV = holder
	})
	h.srv.acmeDNS01.caaResolver = dns
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "issuers:read", "issuers:write", "secrets:read", "secrets:write")
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok, map[string]any{
		"name": "dns/dcv/bearer-token", "value": "dcv-webhook-token",
	}); status != http.StatusCreated {
		t.Fatalf("store the DNS webhook token: %d %s", status, body)
	}
	for _, zone := range []struct {
		name      string
		wildcards bool
	}{{"nowild.dcv.test", false}, {"wild.dcv.test", true}} {
		if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/provider-configs", tok, map[string]any{
			"name": "a165l3-" + strings.Split(zone.name, ".")[0], "provider": "webhook", "zone": zone.name,
			"credential_refs": map[string]any{"bearer_token_ref": "secret://dns/dcv/bearer-token"}, // #nosec G101 -- secret reference, no credential value (CWE-798)
			"config":          map[string]any{"endpoint": dns.URL()},
			"allowed_methods": []string{"dns-01"}, "allow_upstream_dv": true, "allow_wildcards": zone.wildcards,
		}); status != http.StatusCreated {
			t.Fatalf("create the provider config for %s: %d %s", zone.name, status, body)
		}
		dns.setCAA(zone.name, []acmesrv.CAARecord{{Tag: "issue", Value: "digicert.com"}, {Tag: "issuewild", Value: ";"}})
	}
	issue := func(names []string, key string) (int, []byte) {
		t.Helper()
		csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: externalCACSR(t, names[0])})
		return doExternalCARequest(t, h, http.MethodPost, "/api/v1/external-cas/corp-digicert/issue", key, map[string]any{
			"csr_pem": string(csrPEM), "dns_names": names, "ttl_seconds": int64((24 * time.Hour).Seconds()),
		})
	}

	// A provider config that does not allow wildcards refuses one.
	if code, body := issue([]string{"*.a.nowild.dcv.test"}, "a165l3-policy"); code == http.StatusCreated {
		t.Fatalf("a wildcard under a config without wildcards = %d %s; want refused", code, body)
	}
	dns.assertNeverRequested(t, "_dnsauth.a.nowild.dcv.test")

	// CAA whose issuewild names no authority refuses it, even with issue
	// naming DigiCert.
	if code, body := issue([]string{"*.b.wild.dcv.test"}, "a165l3-caa"); code == http.StatusCreated {
		t.Fatalf("a wildcard CAA's issuewild denies = %d %s; want refused", code, body)
	}
	dns.assertNeverRequested(t, "_dnsauth.b.wild.dcv.test")

	// Allowed by both: the base name is validated and the certificate issued.
	dns.setCAA("wild.dcv.test", []acmesrv.CAARecord{{Tag: "issue", Value: "digicert.com"}, {Tag: "issuewild", Value: "digicert.com"}})
	code, body := issue([]string{"*.c.wild.dcv.test", "c.wild.dcv.test"}, "a165l3-ok")
	var issued externalCAIssueResponse
	if code != http.StatusCreated || json.Unmarshal(body, &issued) != nil || !strings.Contains(issued.CertificatePEM, "BEGIN CERTIFICATE") {
		t.Fatalf("a wildcard allowed by policy and issuewild = %d %s", code, body)
	}
	if values, _ := dns.LookupTXT(context.Background(), "_dnsauth.c.wild.dcv.test"); len(values) != 0 {
		t.Fatalf("the DCV record is still published after issuance: %v", values)
	}
}
