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
	"trstctl.com/trstctl/internal/ca/sectigo/sectigofake"
	"trstctl.com/trstctl/internal/config"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// TestServedSectigoDomainValidationCompletesUnattendedA165L1 is A165-L1's
// Done-when (served, the Sectigo SCM stand-in): Sectigo's DNS TXT domain
// validation runs through the assembled server as DigiCert's does. With no
// DNS-01 provider config that consented to upstream validation nothing is
// published and the issue is refused; with one, an issue through the Sectigo
// authority publishes the record SCM names, SCM validates it and issues with
// no human step, the record is retracted, and the validation is recorded as an
// upstream authorization this install earned (not a reuse), reaching the
// authorization view; CAA that does not name Sectigo stops the publish.
func TestServedSectigoDomainValidationCompletesUnattendedA165L1(t *testing.T) {
	dns := newServedDNSWebhookFixture(t, "dcv-webhook-token")
	sc, err := sectigofake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.Close)
	sc.RequireDCV(func(name string) []string {
		values, _ := dns.LookupTXT(context.Background(), name)
		return values
	})
	passwordFile := filepath.Join(t.TempDir(), "sectigo-password")
	if err := os.WriteFile(passwordFile, []byte(sc.Password()), 0o600); err != nil {
		t.Fatal(err)
	}
	endpoint, err := url.Parse(sc.URL())
	if err != nil {
		t.Fatal(err)
	}
	address := netip.MustParseAddr(endpoint.Hostname())
	holder := &upstreamDVHolder{}
	upstreams, err := externalCAsFromConfig(context.Background(), []config.ExternalCAConfig{{
		ID: "corp-sectigo", Type: "sectigo", Name: "Corp Sectigo", Endpoint: sc.URL(), Login: sc.Login(),
		PasswordRef: "file:" + passwordFile, CustomerURI: sc.CustomerURI(), OrgID: 1, CertType: 2,
		UpstreamDNS01: true, CAAIssuerDomain: "sectigo.com", PollInterval: "10ms",
		Network: config.ExternalCANetworkConfig{AllowInsecureHTTP: true, AllowPrivateEndpoint: true,
			PrivateEgressCIDRs: []string{netip.PrefixFrom(address, 32).String()}, Timeout: "10s"},
	}}, nil, nil, nil, holder)
	if err != nil {
		t.Fatalf("configure the Sectigo authority with upstream DNS validation: %v", err)
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
		return doExternalCARequest(t, h, http.MethodPost, "/api/v1/external-cas/corp-sectigo/issue", key, map[string]any{
			"csr_pem": string(csrPEM), "dns_names": []string{name}, "ttl_seconds": int64((24 * time.Hour).Seconds()),
		})
	}
	requests := func() int {
		dns.mu.Lock()
		defer dns.mu.Unlock()
		return len(dns.requests)
	}

	// No provider config has consented to upstream validation yet.
	if code, body := issue("first.dcv.test", "a165l1-no-consent"); code == http.StatusCreated {
		t.Fatalf("an issue with no consenting DNS-01 provider config = %d %s; want refused", code, body)
	}
	if n := requests(); n != 0 {
		t.Fatalf("the DNS provider was asked %d times with no consenting config; want never", n)
	}

	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok, map[string]any{
		"name": "dns/dcv/bearer-token", "value": "dcv-webhook-token",
	}); status != http.StatusCreated {
		t.Fatalf("store the DNS webhook token: %d %s", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/provider-configs", tok, map[string]any{
		"name": "a165l1-dcv-webhook", "provider": "webhook", "zone": "dcv.test",
		"credential_refs": map[string]any{"bearer_token_ref": "secret://dns/dcv/bearer-token"}, // #nosec G101 -- secret reference, no credential value (CWE-798)
		"config":          map[string]any{"endpoint": dns.URL()},
		"allowed_methods": []string{"dns-01"}, "allow_upstream_dv": true,
	}); status != http.StatusCreated {
		t.Fatalf("create the consenting DNS-01 provider config: %d %s", status, body)
	}
	dns.setCAA("dcv.test", []acmesrv.CAARecord{{Tag: "issue", Value: "sectigo.com"}})

	code, body := issue("app.dcv.test", "a165l1-dcv")
	var issued externalCAIssueResponse
	if code != http.StatusCreated || json.Unmarshal(body, &issued) != nil || !strings.Contains(issued.CertificatePEM, "BEGIN CERTIFICATE") {
		t.Fatalf("issue through Sectigo with unattended DCV = %d %s", code, body)
	}
	host, point := sc.DCVRecord("app.dcv.test")
	if host == "" || point == "" {
		t.Fatal("SCM never started the validation of app.dcv.test")
	}
	// The record SCM named was published and retracted.
	dns.assertPresentedAndCleaned(t, host, point)

	// The validation is recorded like an upstream ACME authorization, as one
	// this install earned by publishing the record (not a reuse) ...
	auditor := seedScopedTokenSubject(t, h.store, h.tenant, "a165l1-dv-auditor", "audit:read")
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
		t.Fatalf("Sectigo's validation of app.dcv.test as an upstream authorization event = %d %s", status, raw)
	}
	// ... and the authorization view takes it like an ACME authorization.
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
		t.Fatal("Sectigo's validation of app.dcv.test never reached the upstream authorization view")
	}

	// CAA that does not authorize Sectigo stops the publish.
	before := requests()
	dns.setCAA("caa.dcv.test", []acmesrv.CAARecord{{Tag: "issue", Value: "other-ca.example"}})
	if code, body := issue("caa.dcv.test", "a165l1-caa"); code == http.StatusCreated {
		t.Fatalf("an issue whose CAA names another CA = %d %s; want refused", code, body)
	}
	if n := requests() - before; n != 0 {
		t.Fatalf("the DNS provider was asked %d times for a name whose CAA names another CA; want never", n)
	}
	t.Logf("A165L1_OK record=%s", host)
}
