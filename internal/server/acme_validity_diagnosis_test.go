// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/profile"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// Exercise the real mounted finalization, issuer, event log, PostgreSQL
// projection and authenticated diagnostic read. No certificate may be recorded
// for a validity profile that leaves no forward lifetime after backdating.
func TestServedACMEValidityRefusalPersistsExactDiagnosis(t *testing.T) {
	var challengeAddr string
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, challengeAddr)
		},
	}
	validators := acmesrv.Validators{
		HTTP01: acmesrv.HTTP01Validator{Client: &http.Client{Transport: transport, Timeout: 5 * time.Second}},
		DNS01:  acmesrv.DNS01Validator{},
	}

	h := newServedHarness(t,
		config.Protocols{ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		func(d *Deps) { d.ACMEValidators = &validators; d.DefaultProfile = "diagnostic-validity" },
	)

	if !protoContains(h.srv.ServedProtocols(), "acme") {
		t.Fatal("ACME is not reported as served — wire-in failed")
	}

	storeServerTestProfile(t, h.store, h.tenant, "diagnostic-validity", profile.CertificateProfile{
		Name: "diagnostic-validity", AllowedEKUs: []string{"serverAuth"},
		MaxValidity: profile.Duration(2 * time.Minute), AllowedProtocols: []string{"acme"},
		AllowedDNSSuffixes: []string{"served.test"},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stock ECDSA-account-key ACME client pointed at the SERVED directory (proves
	// INTEROP-003 over the served path: a default ECDSA client registers).
	client, err := acmekey.NewClient(h.ts.URL + "/directory")
	if err != nil {
		t.Fatalf("acme client: %v", err)
	}

	client.RetryBackoff = func(int, *http.Request, *http.Response) time.Duration { return -1 }

	// Sanity: the served directory advertises the mandatory resources (INTEROP-002).
	dir, err := client.Discover(ctx)
	if err != nil {
		t.Fatalf("discover served directory: %v", err)
	}
	if dir.RevokeURL == "" {
		t.Error("served ACME directory omits revokeCert (INTEROP-002)")
	}

	acct, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS)
	if err != nil {
		t.Fatalf("register (ECDSA account): %v", err)
	}
	_ = acct

	const domain = "svc.served.test"
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatalf("authorize order: %v", err)
	}

	// Stand up the http-01 challenge responder that the served validator will reach
	// (the validator's dials are rewritten to this server's address).
	mux := http.NewServeMux()
	chalSrv := httptest.NewServer(mux)
	t.Cleanup(chalSrv.Close)
	challengeAddr = strings.TrimPrefix(chalSrv.URL, "http://")

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
			t.Fatal("served ACME offered no http-01 challenge")
		}
		resp, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			t.Fatalf("challenge response: %v", err)
		}
		mux.HandleFunc(client.HTTP01ChallengePath(chal.Token), func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, resp)
		})
		if _, err := client.Accept(ctx, chal); err != nil {
			t.Fatalf("accept challenge: %v", err)
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			t.Fatalf("wait authorization: %v", err)
		}
	}
	orderURI := order.URI
	if order, err = client.WaitOrder(ctx, orderURI); err != nil {
		t.Fatalf("wait order: %v", err)
	}

	// Finalize with a fresh CSR built through the crypto boundary (AN-3 forbids
	// stdlib crypto even in tests) — the SERVED ACME path signs it through the signer.
	csr := buildServedCSR(t, domain)

	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	var problem *xacme.Error
	if !errors.As(err, &problem) || problem.StatusCode != http.StatusInternalServerError ||
		problem.ProblemType != "urn:ietf:params:acme:error:serverInternal" ||
		!strings.Contains(problem.Detail, "leaves no usable lifetime") || len(der) != 0 {
		t.Fatalf("finalize refusal = %v, returned certificates = %d", err, len(der))
	}
	token := seedScopedToken(t, h.store, h.tenant, "certs:read")
	got := assertServedDiagnosticTenant(t, h, token, "validity_not_permitted", 1)
	d := got.Items[0]
	finalize, err := url.Parse(order.FinalizeURL)
	if err != nil {
		t.Fatal(err)
	}
	orderURL, err := url.Parse(orderURI)
	if err != nil {
		t.Fatal(err)
	}
	orderID := orderURL.Path[strings.LastIndex(orderURL.Path, "/")+1:]
	if d.Step != "issue" || d.OperationRef != "POST "+finalize.Path || d.IdentityRef != "order:"+orderID ||
		d.Remediation == "" || !strings.Contains(d.Remediation, "backdate") || d.VerificationAddress != "" {
		t.Fatalf("retained refusal lost cause, action, or exact route evidence: %+v", d)
	}
	if h.hasEvent(t, "certificate.recorded") || h.hasEvent(t, "protocol.issued") {
		t.Fatal("unusable validity refusal nevertheless recorded an issued certificate")
	}
}
