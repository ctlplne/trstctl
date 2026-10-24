// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/ca/digicert"
	"trstctl.com/trstctl/internal/ca/digicert/digicertfake"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/crypto/weakkey/weakkeytest"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/graph"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
	"trstctl.com/trstctl/internal/protocols/spiffe"
	"trstctl.com/trstctl/internal/store"
)

// Owner decision (batch 11): a CSR whose key fails a structural weak-key check
// is refused wherever its key is about to be certified, naming the check. The
// key here is 3·G on P-256: ec_small_scalar flags it, and a P-256 key passes
// every size and algorithm floor, so only the weak-key check can refuse it.
const weakSubjectCheck = "ec_small_scalar"

func weakSubjectSigner(t *testing.T) *crypto.LockedSigner {
	t.Helper()
	der, err := weakkeytest.SmallScalarPKCS8("P-256", 3)
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.NewLockedSignerFromPKCS8(crypto.ECDSAP256, der)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	return key
}

func weakSubjectCSR(t *testing.T, tmpl crypto.CertificateRequestTemplate) []byte {
	t.Helper()
	der, err := crypto.CreateCertificateRequest(tmpl, weakSubjectSigner(t))
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func assertNamesWeakSubjectCheck(t *testing.T, where string, text []byte) {
	t.Helper()
	if !bytes.Contains(text, []byte(weakSubjectCheck)) {
		t.Fatalf("%s refusal does not name the weak-key check %s: %s", where, weakSubjectCheck, text)
	}
}

// servedEventMentions reports whether a tenant event of eventType carries text.
func servedEventMentions(t *testing.T, h *servedHarness, eventType, text string) bool {
	t.Helper()
	found := false
	if err := h.log.Replay(t.Context(), 0, func(e events.Event) error {
		if e.Type == eventType && bytes.Contains(e.Data, []byte(text)) {
			found = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return found
}

func assertNoCertificateFor(t *testing.T, h *servedHarness, where string) {
	t.Helper()
	if h.hasEvent(t, "certificate.recorded") {
		t.Fatalf("%s minted a certificate for a weak subject key", where)
	}
}

func TestServedRESTTransitionRefusesAWeakSubjectKey(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write", "identities:read", "identities:write", "certs:read", "certs:issue")
	owner, err := h.store.CreateOwner(t.Context(), store.Owner{TenantID: h.tenant, Kind: store.OwnerWorkload, Name: "weak-csr"})
	if err != nil {
		t.Fatal(err)
	}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"owner_id": owner.ID, "kind": "x509", "name": "weak.example.test",
	})
	var ident struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &ident) != nil {
		t.Fatalf("create identity = %d: %s", status, body)
	}
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: weakSubjectCSR(t,
		crypto.CertificateRequestTemplate{CommonName: "weak.example.test", DNSNames: []string{"weak.example.test"}})})
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{
		"to": "issued", "reason": "weak key", "subject_csr_pem": string(csr),
	})
	if status != http.StatusBadRequest {
		t.Fatalf("weak subject key transition = %d, want 400: %s", status, body)
	}
	assertNamesWeakSubjectCheck(t, "REST transition", body)
	if got, err := h.store.GetIdentity(t.Context(), h.tenant, ident.ID); err != nil || got.Status != "requested" {
		t.Fatalf("refused transition moved the identity: %s %v", got.Status, err)
	}
}

func TestServedESTRefusesAWeakSubjectKey(t *testing.T) {
	h := newServedHarness(t, config.Protocols{EST: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}})
	registerServedTenant(t, h, "EST weak-key tenant")
	token := seedAPIToken(t, h.store, servedTestTenant)
	body := base64.StdEncoding.EncodeToString(weakSubjectCSR(t, crypto.CertificateRequestTemplate{CommonName: "device-est-weak"}))
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/.well-known/est/simpleenroll", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/pkcs10")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	text, _ := readAllClose(resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("EST weak subject key = %d, want 400: %s", resp.StatusCode, text)
	}
	assertNamesWeakSubjectCheck(t, "EST", text)
	assertNoCertificateFor(t, h, "EST")
}

func TestServedSCEPRefusesAWeakSubjectKey(t *testing.T) {
	intuneCfg, challenge := servedSCEPIntuneChallenge(t, "device-scep-weak")
	h := newOperatingServedHarness(t, config.Protocols{
		SCEP:                config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		SCEPIntuneChallenge: intuneCfg,
	})
	caResp, err := h.ts.Client().Get(h.ts.URL + "/scep?operation=GetCACert")
	if err != nil {
		t.Fatal(err)
	}
	caBody, _ := readAllClose(caResp)
	raCertDER := scepRARecipient(t, caBody)
	clientCertDER, clientKeyPKCS8, _ := newSCEPClientWithChallenge(t, "device-scep-weak", challenge)
	csr := weakSubjectCSR(t, crypto.CertificateRequestTemplate{CommonName: "device-scep-weak", ChallengePassword: []byte(challenge)})
	reqDER, err := crypto.BuildSCEPRequest(csr, clientCertDER, clientKeyPKCS8, raCertDER, "served-scep-weak")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := h.ts.Client().Post(h.ts.URL+"/scep?operation=PKIOperation", "application/x-pki-message", bytes.NewReader(reqDER))
	if err != nil {
		t.Fatal(err)
	}
	reply, _ := readAllClose(resp)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("SCEP issued for a weak subject key: %d", resp.StatusCode)
	}
	assertNoCertificateFor(t, h, "SCEP")
	// SCEP carries no text to the client; the issuance evidence names the check.
	if !servedEventMentions(t, h, "protocol.scep.issuance.observed", weakSubjectCheck) {
		t.Fatalf("no SCEP evidence names %s (HTTP %d %s)", weakSubjectCheck, resp.StatusCode, reply)
	}
}

func TestServedCMPRefusesAWeakSubjectKey(t *testing.T) {
	clientCertDER, clientKeyPKCS8, _ := newSCEPClient(t, "device-cmp-weak")
	anchorFile := writeCMPAnchorPEM(t, clientCertDER)
	h := newServedHarness(t, config.Protocols{
		CMP:                      config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		CMPClientTrustAnchorFile: anchorFile,
	})
	registerServedTenant(t, h, "CMP weak-key tenant")
	csr := weakSubjectCSR(t, crypto.CertificateRequestTemplate{CommonName: "device-cmp-weak"})
	reqDER, err := crypto.BuildCMPRequest(csr, clientCertDER, clientKeyPKCS8, []byte("served-cmp-weak"), []byte("nonce-weak-12345"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := h.ts.Client().Post(h.ts.URL+"/cmp", "application/pkixcmp", bytes.NewReader(reqDER))
	if err != nil {
		t.Fatal(err)
	}
	text, _ := readAllClose(resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("CMP weak subject key = %d, want 400: %s", resp.StatusCode, text)
	}
	assertNamesWeakSubjectCheck(t, "CMP", text)
	assertNoCertificateFor(t, h, "CMP")
}

func TestServedACMERefusesAWeakSubjectKey(t *testing.T) {
	var challengeAddr string
	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, challengeAddr)
	}}
	validators := acmesrv.Validators{
		HTTP01: acmesrv.HTTP01Validator{Client: &http.Client{Transport: transport, Timeout: 5 * time.Second}},
		DNS01:  acmesrv.DNS01Validator{},
	}
	h := newOperatingServedHarness(t, config.Protocols{ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		func(d *Deps) { d.ACMEValidators = &validators })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	client, err := acmekey.NewClient(h.ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatal(err)
	}
	const domain = "weak.served.test"
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	chalSrv := httptest.NewServer(mux)
	t.Cleanup(chalSrv.Close)
	challengeAddr = strings.TrimPrefix(chalSrv.URL, "http://")
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range authz.Challenges {
			if c.Type != "http-01" {
				continue
			}
			resp, err := client.HTTP01ChallengeResponse(c.Token)
			if err != nil {
				t.Fatal(err)
			}
			mux.HandleFunc(client.HTTP01ChallengePath(c.Token), func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, resp) })
			if _, err := client.Accept(ctx, c); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			t.Fatal(err)
		}
	}
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		t.Fatal(err)
	}
	csr := weakSubjectCSR(t, crypto.CertificateRequestTemplate{CommonName: domain, DNSNames: []string{domain}})
	_, _, err = client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	var problem *xacme.Error
	if !errors.As(err, &problem) || problem.StatusCode != http.StatusBadRequest || !strings.HasSuffix(problem.ProblemType, ":badCSR") {
		t.Fatalf("ACME finalize with a weak subject key = %v; want a 400 badCSR", err)
	}
	assertNamesWeakSubjectCheck(t, "ACME", []byte(problem.Detail))
	assertNoCertificateFor(t, h, "ACME")
}

func TestServedVaultPKIRefusesAWeakSubjectKey(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "audit:read", "policy:read", "policy:write")
	vaultServedRequest(t, h, token, http.MethodPut, "/v1/sys/policies/acl/api-token", map[string]any{
		"policy": `path "*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }`,
	}, http.StatusNoContent)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: weakSubjectCSR(t,
		crypto.CertificateRequestTemplate{CommonName: "vault-weak.example.test"})})
	body := vaultServedRequestKey(t, h, token, http.MethodPost, "/v1/pki/sign/default", "vault-pki-sign-weak",
		map[string]any{"csr": string(csrPEM), "ttl": "15m"}, http.StatusUnprocessableEntity)
	assertNamesWeakSubjectCheck(t, "Vault PKI sign", body)
	if bytes.Contains(body, []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("Vault PKI signed a weak subject key: %s", body)
	}
}

func TestTenantSPIFFERefusesAWeakWorkloadKey(t *testing.T) {
	st := newServerTestStore(t)
	log := openServerFederationSeamTestLog(t)
	const tenant = "5d3f2a71-7a0c-4c8e-9f0e-2b7f1d6a9c44"
	const id = "spiffe://weak.test/workload"
	if err := st.UpsertTenant(t.Context(), store.Tenant{TenantID: tenant, Name: "SPIFFE weak key"}); err != nil {
		t.Fatal(err)
	}
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	caDER, err := crypto.SelfSignedCACert(key, "weak svid test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &spiffe.CAIssuer{CACertDER: caDER, CASigner: key, JWTSigner: key, JWTKeyID: "qa"}
	wl, err := spiffe.New(spiffe.Config{
		TenantID: tenant, TenantServiceWork: st.BeginTenantService,
		Issuer: tenantSPIFFEIssuer{Issuer: issuer, tenantID: tenant, work: st.BeginTenantService},
		Audit:  audit.NewAuditor(log), Graph: graph.New(),
		Entries: []spiffe.RegistrationEntry{{SPIFFEID: id, Selectors: []string{"unix"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	if _, err := wl.FetchX509SVIDs(ctx, weakSubjectSigner(t).Public().DER, []string{"unix"}); err == nil || !strings.Contains(err.Error(), weakSubjectCheck) {
		t.Fatalf("X.509-SVID for a weak workload key = %v; want a refusal naming %s", err, weakSubjectCheck)
	}
}

func TestServedAgentEnrollmentRefusesAWeakSubjectKey(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withAgentChannel)
	bearer := seedScopedToken(t, h.store, h.tenant, "agents:write")
	token := mintServedEnrollmentToken(t, h, bearer, "weak-agent-enroll", "node-weak")
	status, body := postServedBootstrap(t, h, token, weakSubjectCSR(t, crypto.CertificateRequestTemplate{CommonName: "node-weak"}))
	if status == http.StatusOK || status >= 500 {
		t.Fatalf("agent bootstrap with a weak key = %d %s; want a client refusal", status, body)
	}
	assertNamesWeakSubjectCheck(t, "agent enrollment", body)
}

func TestServedExternalCARefusesAWeakSubjectKey(t *testing.T) {
	dc, err := digicertfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dc.Close)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.APIOptions = append(d.APIOptions, api.WithInsecureHeaderResolver())
		d.ExternalCAs = []ExternalCA{{ID: "digicert", Type: "digicert",
			CA: digicert.New("digicert", dc.URL(), []byte(dc.APIKey()), digicert.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))}}
	})
	startServedExternalCADispatcher(t, h)
	const name = "weak.digicert.served.test"
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: weakSubjectCSR(t,
		crypto.CertificateRequestTemplate{CommonName: name, DNSNames: []string{name}})})
	code, body := doExternalCARequest(t, h, http.MethodPost, "/api/v1/external-cas/digicert/issue", "weak-external-ca", map[string]any{
		"csr_pem": string(csrPEM), "dns_names": []string{name}, "ttl_seconds": int64((24 * time.Hour).Seconds()),
	})
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("external CA issue with a weak key = %d, want 422: %s", code, body)
	}
	assertNamesWeakSubjectCheck(t, "external CA", body)
	if got := externalCAOutboxCount(t, h, "weak-external-ca:external-ca:digicert"); got != 0 {
		t.Fatalf("a weak subject key queued %d external CA requests", got)
	}
}
