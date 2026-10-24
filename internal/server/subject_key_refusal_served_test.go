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

	"github.com/jackc/pgx/v5"
	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/ca/digicert"
	"trstctl.com/trstctl/internal/ca/digicert/digicertfake"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/weakkey/weakkeytest"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/graph"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
	"trstctl.com/trstctl/internal/protocols/spiffe"
	"trstctl.com/trstctl/internal/store"
)

// Owner decision (batch 11): a requester's key is refused wherever it is about
// to be certified when it fails a structural weak-key check, naming the check,
// or when the tenant has recorded it as compromised (CA/B BR 6.1.1.3,
// condition 4). The weak key is 3·G on P-256: ec_small_scalar flags it, and a
// P-256 key passes every size and algorithm floor, so only the weak-key check
// can refuse it. The compromised key is a sound P-256 key that a certificate
// of the tenant, revoked with reason keyCompromise, carried.
const weakSubjectCheck = "ec_small_scalar"

type badSubjectKey struct {
	name   string
	marker string // what the refusal must name
	signer func(t *testing.T, st *store.Store, tenantID string) *crypto.LockedSigner
}

var badSubjectKeys = []badSubjectKey{
	{name: "weak", marker: weakSubjectCheck, signer: func(t *testing.T, _ *store.Store, _ string) *crypto.LockedSigner {
		return weakSubjectSigner(t)
	}},
	{name: "compromised", marker: "recorded as compromised", signer: compromisedSubjectSigner},
}

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

// compromisedSubjectSigner returns a sound key the tenant has recorded as
// compromised: a certificate carrying it is revoked with reason keyCompromise.
func compromisedSubjectSigner(t *testing.T, st *store.Store, tenantID string) *crypto.LockedSigner {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	der, err := crypto.SelfSignedCACert(key, "compromised key", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertCertificate(t.Context(), store.Certificate{TenantID: tenantID, Subject: info.Subject,
		Fingerprint: info.SHA256Fingerprint, CertificateDER: der, Source: "import"}); err != nil {
		t.Fatalf("record the compromised key's certificate: %v", err)
	}
	// Revoke through the projection writer a certificate.revoked event drives,
	// which records the subject key as compromised.
	if err := st.WithTenant(t.Context(), tenantID, func(tx pgx.Tx) error {
		return st.SetCertificateRevokedTx(t.Context(), tx, tenantID, info.SHA256Fingerprint, "keyCompromise", time.Now().UTC())
	}); err != nil {
		t.Fatalf("revoke the compromised key's certificate: %v", err)
	}
	return key
}

func badSubjectCSR(t *testing.T, key *crypto.LockedSigner, tmpl crypto.CertificateRequestTemplate) []byte {
	t.Helper()
	der, err := crypto.CreateCertificateRequest(tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func assertRefusalNames(t *testing.T, where string, bad badSubjectKey, text []byte) {
	t.Helper()
	if !bytes.Contains(text, []byte(bad.marker)) {
		t.Fatalf("%s refusal of the %s key does not name %q: %s", where, bad.name, bad.marker, text)
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

func TestServedRESTTransitionRefusesBadSubjectKeys(t *testing.T) {
	for _, bad := range badSubjectKeys {
		t.Run(bad.name, func(t *testing.T) {
			h := newOperatingServedHarness(t, config.Protocols{})
			tok := seedScopedToken(t, h.store, h.tenant,
				"owners:read", "owners:write", "identities:read", "identities:write", "certs:read", "certs:issue")
			owner, err := h.store.CreateOwner(t.Context(), store.Owner{TenantID: h.tenant, Kind: store.OwnerWorkload, Name: "bad-csr"})
			if err != nil {
				t.Fatal(err)
			}
			status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
				"owner_id": owner.ID, "kind": "x509", "name": "bad.example.test",
			})
			var ident struct {
				ID string `json:"id"`
			}
			if status != http.StatusCreated || json.Unmarshal(body, &ident) != nil {
				t.Fatalf("create identity = %d: %s", status, body)
			}
			csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: badSubjectCSR(t, bad.signer(t, h.store, h.tenant),
				crypto.CertificateRequestTemplate{CommonName: "bad.example.test", DNSNames: []string{"bad.example.test"}})})
			status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{
				"to": "issued", "reason": "bad key", "subject_csr_pem": string(csr),
			})
			if status != http.StatusBadRequest {
				t.Fatalf("%s subject key transition = %d, want 400: %s", bad.name, status, body)
			}
			assertRefusalNames(t, "REST transition", bad, body)
			if got, err := h.store.GetIdentity(t.Context(), h.tenant, ident.ID); err != nil || got.Status != "requested" {
				t.Fatalf("refused transition moved the identity: %s %v", got.Status, err)
			}
		})
	}
}

func TestServedESTRefusesBadSubjectKeys(t *testing.T) {
	for _, bad := range badSubjectKeys {
		t.Run(bad.name, func(t *testing.T) {
			h := newServedHarness(t, config.Protocols{EST: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}})
			registerServedTenant(t, h, "EST bad-key tenant")
			token := seedAPIToken(t, h.store, servedTestTenant)
			body := base64.StdEncoding.EncodeToString(badSubjectCSR(t, bad.signer(t, h.store, servedTestTenant),
				crypto.CertificateRequestTemplate{CommonName: "device-est-bad"}))
			req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/.well-known/est/simpleenroll", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/pkcs10")
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := h.ts.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			text, _ := readAllClose(resp)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("EST %s subject key = %d, want 400: %s", bad.name, resp.StatusCode, text)
			}
			assertRefusalNames(t, "EST", bad, text)
			assertNoCertificateFor(t, h, "EST")
		})
	}
}

func TestServedSCEPRefusesBadSubjectKeys(t *testing.T) {
	for _, bad := range badSubjectKeys {
		t.Run(bad.name, func(t *testing.T) {
			device := "device-scep-" + bad.name
			intuneCfg, challenge := servedSCEPIntuneChallenge(t, device)
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
			clientCertDER, clientKeyPKCS8, _ := newSCEPClientWithChallenge(t, device, challenge)
			csr := badSubjectCSR(t, bad.signer(t, h.store, servedTestTenant),
				crypto.CertificateRequestTemplate{CommonName: device, ChallengePassword: []byte(challenge)})
			reqDER, err := crypto.BuildSCEPRequest(csr, clientCertDER, clientKeyPKCS8, raCertDER, "served-scep-"+bad.name)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := h.ts.Client().Post(h.ts.URL+"/scep?operation=PKIOperation", "application/x-pki-message", bytes.NewReader(reqDER))
			if err != nil {
				t.Fatal(err)
			}
			reply, _ := readAllClose(resp)
			if resp.StatusCode == http.StatusOK {
				t.Fatalf("SCEP issued for a %s subject key", bad.name)
			}
			assertNoCertificateFor(t, h, "SCEP")
			// SCEP carries no text to the client; the issuance evidence names it.
			if !servedEventMentions(t, h, "protocol.scep.issuance.observed", bad.marker) {
				t.Fatalf("no SCEP evidence names %q (HTTP %d %s)", bad.marker, resp.StatusCode, reply)
			}
		})
	}
}

func TestServedCMPRefusesBadSubjectKeys(t *testing.T) {
	for _, bad := range badSubjectKeys {
		t.Run(bad.name, func(t *testing.T) {
			clientCertDER, clientKeyPKCS8, _ := newSCEPClient(t, "device-cmp-bad")
			anchorFile := writeCMPAnchorPEM(t, clientCertDER)
			h := newServedHarness(t, config.Protocols{
				CMP:                      config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
				CMPClientTrustAnchorFile: anchorFile,
			})
			registerServedTenant(t, h, "CMP bad-key tenant")
			csr := badSubjectCSR(t, bad.signer(t, h.store, servedTestTenant), crypto.CertificateRequestTemplate{CommonName: "device-cmp-bad"})
			reqDER, err := crypto.BuildCMPRequest(csr, clientCertDER, clientKeyPKCS8, []byte("served-cmp-bad"), []byte("nonce-bad-123456"))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := h.ts.Client().Post(h.ts.URL+"/cmp", "application/pkixcmp", bytes.NewReader(reqDER))
			if err != nil {
				t.Fatal(err)
			}
			text, _ := readAllClose(resp)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("CMP %s subject key = %d, want 400: %s", bad.name, resp.StatusCode, text)
			}
			assertRefusalNames(t, "CMP", bad, text)
			assertNoCertificateFor(t, h, "CMP")
		})
	}
}

func TestServedACMERefusesBadSubjectKeys(t *testing.T) {
	for _, bad := range badSubjectKeys {
		t.Run(bad.name, func(t *testing.T) {
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
			const domain = "bad.served.test"
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
			csr := badSubjectCSR(t, bad.signer(t, h.store, servedTestTenant), crypto.CertificateRequestTemplate{CommonName: domain, DNSNames: []string{domain}})
			_, _, err = client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
			var problem *xacme.Error
			if !errors.As(err, &problem) || problem.StatusCode != http.StatusBadRequest || !strings.HasSuffix(problem.ProblemType, ":badCSR") {
				t.Fatalf("ACME finalize with a %s subject key = %v; want a 400 badCSR", bad.name, err)
			}
			assertRefusalNames(t, "ACME", bad, []byte(problem.Detail))
			assertNoCertificateFor(t, h, "ACME")
		})
	}
}

func TestServedVaultPKIRefusesBadSubjectKeys(t *testing.T) {
	for _, bad := range badSubjectKeys {
		t.Run(bad.name, func(t *testing.T) {
			h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
			token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "audit:read", "policy:read", "policy:write")
			vaultServedRequest(t, h, token, http.MethodPut, "/v1/sys/policies/acl/api-token", map[string]any{
				"policy": `path "*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }`,
			}, http.StatusNoContent)
			csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: badSubjectCSR(t, bad.signer(t, h.store, h.tenant),
				crypto.CertificateRequestTemplate{CommonName: "vault-bad.example.test"})})
			body := vaultServedRequestKey(t, h, token, http.MethodPost, "/v1/pki/sign/default", "vault-pki-sign-bad",
				map[string]any{"csr": string(csrPEM), "ttl": "15m"}, http.StatusUnprocessableEntity)
			assertRefusalNames(t, "Vault PKI sign", bad, body)
			if bytes.Contains(body, []byte("BEGIN CERTIFICATE")) {
				t.Fatalf("Vault PKI signed a %s subject key: %s", bad.name, body)
			}
		})
	}
}

func TestTenantSPIFFERefusesBadWorkloadKeys(t *testing.T) {
	for _, bad := range badSubjectKeys {
		t.Run(bad.name, func(t *testing.T) {
			st := newServerTestStore(t)
			log := openServerFederationSeamTestLog(t)
			const tenant = "5d3f2a71-7a0c-4c8e-9f0e-2b7f1d6a9c44"
			const id = "spiffe://bad.test/workload"
			if err := st.UpsertTenant(t.Context(), store.Tenant{TenantID: tenant, Name: "SPIFFE bad key"}); err != nil {
				t.Fatal(err)
			}
			key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(key.Destroy)
			caDER, err := crypto.SelfSignedCACert(key, "bad svid test", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			issuer := &spiffe.CAIssuer{CACertDER: caDER, CASigner: key, JWTSigner: key, JWTKeyID: "qa"}
			wl, err := spiffe.New(spiffe.Config{
				TenantID: tenant, TenantServiceWork: st.BeginTenantService,
				Issuer: tenantSPIFFEIssuer{Issuer: issuer, tenantID: tenant, work: st.BeginTenantService, store: st},
				Audit:  audit.NewAuditor(log), Graph: graph.New(),
				Entries: []spiffe.RegistrationEntry{{SPIFFEID: id, Selectors: []string{"unix"}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			workload := bad.signer(t, st, tenant)
			if _, err := wl.FetchX509SVIDs(ctx, workload.Public().DER, []string{"unix"}); err == nil || !strings.Contains(err.Error(), bad.marker) {
				t.Fatalf("X.509-SVID for a %s workload key = %v; want a refusal naming %q", bad.name, err, bad.marker)
			}
		})
	}
}

func TestServedAgentEnrollmentRefusesBadSubjectKeys(t *testing.T) {
	for _, bad := range badSubjectKeys {
		t.Run(bad.name, func(t *testing.T) {
			h := newOperatingServedHarness(t, config.Protocols{}, withAgentChannel)
			bearer := seedScopedToken(t, h.store, h.tenant, "agents:write")
			token := mintServedEnrollmentToken(t, h, bearer, "bad-agent-enroll", "node-bad")
			status, body := postServedBootstrap(t, h, token, badSubjectCSR(t, bad.signer(t, h.store, h.tenant),
				crypto.CertificateRequestTemplate{CommonName: "node-bad"}))
			if status == http.StatusOK || status >= 500 {
				t.Fatalf("agent bootstrap with a %s key = %d %s; want a client refusal", bad.name, status, body)
			}
			assertRefusalNames(t, "agent enrollment", bad, body)
		})
	}
}

func TestServedExternalCARefusesBadSubjectKeys(t *testing.T) {
	for _, bad := range badSubjectKeys {
		t.Run(bad.name, func(t *testing.T) {
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
			const name = "bad.digicert.served.test"
			csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: badSubjectCSR(t, bad.signer(t, h.store, h.tenant),
				crypto.CertificateRequestTemplate{CommonName: name, DNSNames: []string{name}})})
			code, body := doExternalCARequest(t, h, http.MethodPost, "/api/v1/external-cas/digicert/issue", "bad-external-ca", map[string]any{
				"csr_pem": string(csrPEM), "dns_names": []string{name}, "ttl_seconds": int64((24 * time.Hour).Seconds()),
			})
			if code != http.StatusUnprocessableEntity {
				t.Fatalf("external CA issue with a %s key = %d, want 422: %s", bad.name, code, body)
			}
			assertRefusalNames(t, "external CA", bad, body)
			if got := externalCAOutboxCount(t, h, "bad-external-ca:external-ca:digicert"); got != 0 {
				t.Fatalf("a %s subject key queued %d external CA requests", bad.name, got)
			}
		})
	}
}
