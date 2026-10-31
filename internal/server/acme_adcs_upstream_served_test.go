// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/profile"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// adcsCertsrvStandIn answers the two Web Enrollment endpoints the adcs driver
// uses: certfnsh.asp signs the submitted CSR under the stand-in's own issuing
// CA for the named template, and certnew.cer returns leaf plus issuer. It
// records every template it was asked for.
type adcsCertsrvStandIn struct {
	mu        sync.Mutex
	caDER     []byte
	caKey     *crypto.LockedSigner
	issued    map[int][]byte
	templates []string
}

func newADCSCertsrvStandIn(t *testing.T) (*adcsCertsrvStandIn, *httptest.Server) {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	caDER, err := crypto.SelfSignedCACert(key, "Corp Issuing CA (AD CS stand-in)", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	standIn := &adcsCertsrvStandIn{caDER: caDER, caKey: key, issued: map[int][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(standIn.serve))
	t.Cleanup(srv.Close)
	return standIn, srv
}

func (a *adcsCertsrvStandIn) serve(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/certsrv/certfnsh.asp":
		if err := r.ParseForm(); err != nil || r.Form.Get("Mode") != "newreq" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		block, _ := pem.Decode([]byte(r.Form.Get("CertRequest")))
		if block == nil {
			http.Error(w, "no CSR", http.StatusBadRequest)
			return
		}
		leaf, err := crypto.SignLeafFromCSR(a.caDER, a.caKey, block.Bytes, 24*time.Hour)
		if err != nil {
			http.Error(w, "The request was denied", http.StatusOK)
			return
		}
		id := len(a.issued) + 1
		a.issued[id] = leaf
		a.templates = append(a.templates, strings.TrimPrefix(r.Form.Get("CertAttrib"), "CertificateTemplate:"))
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, `<a href="certnew.cer?ReqID=%d&Enc=b64">Download certificate</a>`, id)
	case r.Method == http.MethodGet && r.URL.Path == "/certsrv/certnew.cer":
		var id int
		_, _ = fmt.Sscanf(r.URL.Query().Get("ReqID"), "%d", &id)
		leaf := a.issued[id]
		if leaf == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}))
		_, _ = w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.caDER}))
	default:
		http.NotFound(w, r)
	}
}

// A159 Done-when: a stock ACME client gets a certificate from AD CS through
// trstctl. The ACME mount's profile names an adcs external CA (one template
// per entry); stock certbot completes DNS-01 against trstctl, trstctl's
// profile checks pass, the CSR goes to AD CS Web Enrollment, and certbot
// receives the AD CS leaf with the AD CS chain, recorded in inventory.
func TestServedACMEStockCertbotGetsAnADCSCertificateThroughTrstctl(t *testing.T) {
	certbot, err := exec.LookPath("certbot")
	if err != nil {
		if os.Getenv("TRSTCTL_REQUIRE_CERTBOT") == "1" {
			t.Fatalf("TRSTCTL_REQUIRE_CERTBOT is set but certbot is not on PATH: %v", err)
		}
		t.Skip("certbot not on PATH; set TRSTCTL_REQUIRE_CERTBOT=1 in CI to make the stock ACME client mandatory")
	}
	standIn, certsrv := newADCSCertsrvStandIn(t)
	upstreams := adcsUpstreamConfig(t, certsrv.URL)

	dir := t.TempDir()
	domain := "adcs.served.test"
	recordsPath := filepath.Join(dir, "certbot-dns-records.tsv")
	hookLogPath := filepath.Join(dir, "certbot-hooks.log")
	hooksDir := filepath.Join(dir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil { // #nosec G301 -- fixture tree in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}
	authHook, cleanupHook := filepath.Join(hooksDir, "auth.sh"), filepath.Join(hooksDir, "cleanup.sh")
	servedWriteExecutable(t, authHook, servedCertbotAuthHookScript())
	servedWriteExecutable(t, cleanupHook, servedCertbotCleanupHookScript())
	const dnsWebhookToken = "certbot-a159-webhook-token" // #nosec G101 -- fabricated test-only webhook credential (CWE-798)
	dns := newServedDNSWebhookFixture(t, dnsWebhookToken)
	validators := acmesrv.Validators{DNS01: acmesrv.DNS01Validator{Resolver: servedCertbotDNSResolver{recordsPath: recordsPath}}}
	h := newServedHarness(t,
		config.Protocols{ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.ACMEValidators = &validators
			d.ExternalCAs = upstreams
			d.DefaultProfile = "adcs-web"
		},
	)
	startServedOutboxPump(t, h.srv)
	seedServedCertbotDNSPolicyAUD73(t, h, dns, domain, dnsWebhookToken)
	storeServerTestProfile(t, h.store, h.tenant, "adcs-web", profile.CertificateProfile{
		Name: "adcs-web", AllowedProtocols: []string{"acme"}, AllowedDNSSuffixes: []string{"served.test"},
		MaxValidity: profile.Duration(7 * 24 * time.Hour), UpstreamExternalCA: "corp-adcs-web",
	})

	ts := httptest.NewTLSServer(h.srv.Handler())
	t.Cleanup(ts.Close)
	caFile := filepath.Join(dir, "served-acme-https-ca.pem")
	servedWriteTLSCertPEM(t, caFile, ts)
	configDir, workDir, logsDir := filepath.Join(dir, "config"), filepath.Join(dir, "work"), filepath.Join(dir, "logs")
	for _, p := range []string{configDir, workDir, logsDir} {
		if err := os.MkdirAll(p, 0o755); err != nil { // #nosec G301 -- fixture tree in a test tempdir; the mode is part of the fixture (CWE-276)
			t.Fatal(err)
		}
	}
	certName := "trstctl-adcs-through-acme"
	env := append(os.Environ(), "REQUESTS_CA_BUNDLE="+caFile, "SSL_CERT_FILE="+caFile,
		"TRSTCTL_CERTBOT_RECORDS="+recordsPath, "TRSTCTL_CERTBOT_HOOK_LOG="+hookLogPath)
	issueLogPath := filepath.Join(dir, "certbot-issue.log")
	servedRunExternalClient(t, certbot, []string{
		"certonly", "--manual", "--preferred-challenges", "dns",
		"--manual-auth-hook", authHook, "--manual-cleanup-hook", cleanupHook,
		"--agree-tos", "--email", "acme-adcs@example.com", "--no-eff-email",
		"--cert-name", certName, "-d", domain,
		"--server", ts.URL + "/directory", "--config-dir", configDir, "--work-dir", workDir, "--logs-dir", logsDir,
		"--non-interactive",
	}, env, issueLogPath)

	liveDir := filepath.Join(configDir, "live", certName)
	certPath := filepath.Join(liveDir, "cert.pem")
	servedAssertCertbotIssuedDomain(t, certPath, domain)
	leafDER := servedReadPEMCert(t, certPath)
	if err := crypto.VerifyLeafSignedByCA(leafDER, standIn.caDER); err != nil {
		t.Fatalf("certbot's certificate was not issued by AD CS: %v", err)
	}
	if err := crypto.VerifyLeafSignedByCA(leafDER, caCertDER(t, h.caPEM)); err == nil {
		t.Fatal("certbot's certificate was signed by trstctl's own CA; the profile's upstream was bypassed")
	}
	chain := servedReadPEMCert(t, filepath.Join(liveDir, "chain.pem"))
	if string(chain) != string(standIn.caDER) {
		t.Fatal("certbot's chain is not the AD CS issuing CA")
	}
	standIn.mu.Lock()
	templates := append([]string(nil), standIn.templates...)
	standIn.mu.Unlock()
	if len(templates) != 1 || templates[0] != "WebServer" {
		t.Fatalf("AD CS saw templates %v; want exactly one WebServer request", templates)
	}
	if !h.hasEvent(t, "certificate.recorded") {
		t.Fatal("the AD CS certificate was not recorded in inventory")
	}
	servedArchiveConformanceTranscripts(t, "served-acme-certbot-adcs", caFile, issueLogPath, certPath)
}

// adcsUpstreamConfig is the adcs external CA in front of the stand-in.
func adcsUpstreamConfig(t *testing.T, certsrvURL string) []ExternalCA {
	t.Helper()
	endpoint, err := url.Parse(certsrvURL)
	if err != nil {
		t.Fatal(err)
	}
	address := netip.MustParseAddr(endpoint.Hostname())
	upstreams, err := externalCAsFromConfig(context.Background(), []config.ExternalCAConfig{{
		ID: "corp-adcs-web", Type: "adcs", Name: "Corp AD CS (WebServer template)", Endpoint: certsrvURL + "/certsrv",
		CAConfig: `CORP-DC01\Corp Issuing CA`, Template: "WebServer", PollInterval: "10ms",
		Network: config.ExternalCANetworkConfig{AllowInsecureHTTP: true, AllowPrivateEndpoint: true,
			PrivateEgressCIDRs: []string{netip.PrefixFrom(address, 32).String()}, Timeout: "10s"},
	}}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("configure the AD CS external CA: %v", err)
	}
	return upstreams
}

// A159: EST in front of the same AD CS template. The served EST mount's profile
// routes simpleenroll to AD CS, and the returned PKCS#7 carries the AD CS leaf.
// A profile naming an external CA the tenant does not have is refused at save.
func TestServedESTThroughAnADCSTemplateAndProfileUpstreamChecks(t *testing.T) {
	standIn, certsrv := newADCSCertsrvStandIn(t)
	h := newServedHarness(t, config.Protocols{EST: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		func(d *Deps) {
			d.ExternalCAs = adcsUpstreamConfig(t, certsrv.URL)
			d.DefaultProfile = "adcs-est"
		})
	startServedOutboxPump(t, h.srv)
	registerServedTenant(t, h, "EST through AD CS tenant")
	storeServerTestProfile(t, h.store, h.tenant, "adcs-est", profile.CertificateProfile{
		Name: "adcs-est", AllowedProtocols: []string{"est"}, MaxValidity: profile.Duration(7 * 24 * time.Hour),
		UpstreamExternalCA: "corp-adcs-web",
	})
	token := seedAPIToken(t, h.store, servedTestTenant)
	body := base64.StdEncoding.EncodeToString(newDeviceCSR(t, "device-est-adcs"))
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/.well-known/est/simpleenroll", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/pkcs10")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("EST simpleenroll: %v", err)
	}
	p7b64, _ := readAllClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("EST simpleenroll through AD CS status %d: %s", resp.StatusCode, p7b64)
	}
	p7, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(p7b64)))
	if err != nil {
		t.Fatalf("EST response is not base64 PKCS#7: %v", err)
	}
	certs, err := crypto.CertsFromPKCS7(p7)
	if err != nil || len(certs) == 0 {
		t.Fatalf("EST response carries no certificate: %v", err)
	}
	if err := crypto.VerifyLeafSignedByCA(certs[0], standIn.caDER); err != nil {
		t.Fatalf("the EST certificate was not issued by AD CS: %v", err)
	}

	profiles := seedScopedToken(t, h.store, h.tenant, "profiles:read", "profiles:write")
	for name, want := range map[string]int{"corp-adcs-web": http.StatusCreated, "corp-adcs-typo": http.StatusUnprocessableEntity} {
		status, out := secretsReq(t, h, http.MethodPost, "/api/v1/profiles", profiles, map[string]any{
			"name": "upstream-" + name, "spec": map[string]any{"allowed_protocols": []string{"acme"}, "upstream_external_ca": name},
		})
		if status != want {
			t.Errorf("profile naming upstream %q = %d %s; want %d", name, status, out, want)
		}
	}
}
