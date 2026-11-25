// SPDX-License-Identifier: BUSL-1.1

package server

// This harness exposes the deployment's issuing CA, EST, bulk revoke, OCSP,
// and the KMIP standing reader to the external KMIP end-to-end test. That test
// lives in server_test because internal/kmip imports this package.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

type CR648Product struct {
	t         *testing.T
	h         *servedHarness
	main      *httptest.Server
	token     string
	owner     string
	Tenant    string
	CACertDER []byte
}

func TestServerWiresKMIPClientStandingReader(t *testing.T) {
	var standing func(context.Context, string, []byte) error
	newServedHarness(t, config.Protocols{KMIP: config.KMIPProtocol{
		Enabled: true, TenantID: servedTestTenant,
		CertFile: "kmip-server.crt", KeyFile: "kmip-server.key", ClientCAFile: "client-ca.pem",
	}}, func(d *Deps) {
		d.KMIPFactory = func(deps KMIPFactoryDeps) (KMIPRuntime, error) {
			standing = deps.ClientCertificateStanding
			return &fakeKMIPRuntime{addr: "127.0.0.1:0"}, nil
		}
	})
	if standing == nil {
		t.Fatal("core server omitted the product issuing-CA standing reader from the KMIP factory")
	}
}

func NewCR648Product(t *testing.T) *CR648Product {
	t.Helper()
	h := newOperatingServedHarness(t, config.Protocols{
		EST: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
	})
	token := seedAPIToken(t, h.store, servedTestTenant)
	owner := seedScopedToken(t, h.store, servedTestTenant, "certs:issue", "certs:read", "identities:write")
	main := httptest.NewTLSServer(h.srv.Handler())
	t.Cleanup(main.Close)
	return &CR648Product{t: t, h: h, main: main, token: token, owner: owner, Tenant: servedTestTenant, CACertDER: h.srv.caCertDER}
}

func (p *CR648Product) ClientCertificateStanding() func(context.Context, string, []byte) error {
	return p.h.srv.kmipClientCertificateStanding(Deps{Store: p.h.store})
}

// IssueClientCertificate enrolls cn on the served EST endpoint (the
// deployment's issuing CA) and returns the leaf DER and its PKCS#8 key.
func (p *CR648Product) IssueClientCertificate(cn string) (leafDER, keyPKCS8 []byte) {
	t := p.t
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: cn, DNSNames: []string{cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	leafDER = estEnroll(t, p.main.Client(), p.main.URL+"/.well-known/est/simpleenroll", p.token, csrDER, http.StatusOK)
	keyPKCS8, err = key.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	return leafDER, keyPKCS8
}

// RevokeThroughAPI revokes every inventory certificate for cn with POST
// /api/v1/certificates/bulk-revoke, then polls the served OCSP responder.
func (p *CR648Product) RevokeThroughAPI(cn string, leafDER []byte) (reason, ocspStatus string) {
	t := p.t
	t.Helper()
	h := p.h
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/certificates?q="+url.QueryEscape(cn), p.owner, nil)
	if status != http.StatusOK {
		t.Fatalf("list certificates: %d %s", status, raw)
	}
	var list struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, item := range list.Items {
		ids = append(ids, item.ID)
	}
	if len(ids) == 0 {
		t.Fatalf("issued certificate not in the inventory: %s", raw)
	}
	for _, r := range []string{"keyCompromise", "cessationOfOperation"} {
		status, raw = secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", p.owner, "cr648-revoke-"+r,
			map[string]any{"certificate_ids": ids, "reason": r})
		if status == http.StatusOK {
			reason = r
			break
		}
		t.Logf("bulk-revoke reason %s: %d %s", r, status, raw)
	}
	if reason == "" {
		t.Fatal("bulk-revoke refused every reason")
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	ocspReq, err := crypto.BuildOCSPRequest(leafDER, h.srv.caCertDER)
	if err != nil {
		t.Fatal(err)
	}
	for range 50 {
		resp, err := p.main.Client().Post(p.main.URL+"/ocsp/"+servedTestTenant, "application/ocsp-request", bytes.NewReader(ocspReq))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if info, err := crypto.ParseOCSPResponse(body, h.srv.caCertDER); err == nil {
			ocspStatus = info.Status
			if ocspStatus == crypto.OCSPRevoked {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return reason, ocspStatus
}
