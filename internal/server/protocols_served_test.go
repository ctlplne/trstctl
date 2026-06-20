package server

import (
	"bytes"
	"context"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/kek"
	"trstctl.com/trstctl/internal/events"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

// servedHarness is the assembled control plane (server.Build -> Handler) over the
// embedded stack (bundled PostgreSQL + in-process NATS) and a REAL out-of-process
// signer over a UDS — the SAME composition cmd/trstctl serves. It is the wire-in
// proof rig for EXC-WIRE-02: the protocol acceptance tests drive THIS handler, not a
// library function, so they fail on the pre-wiring tree (no protocol was mounted) and
// pass post-wiring.
type servedHarness struct {
	srv    *Server
	ts     *httptest.Server // the served handler over TLS-less httptest (the mux is identical)
	tenant string
	caPEM  []byte
	log    *events.Log
	store  *store.Store
	signer SignerProvider
	authz  *crypto.SignAuthorizer
	caFile string
}

const servedTestTenant = "11111111-1111-1111-1111-111111111111"

// newServedHarness boots the full server with the given protocol config and a real
// signer, returning an httptest.Server serving the assembled handler. PostgreSQL is
// a shared package fixture reset per test; NATS, signer state, and sockets stay
// per-test so process-boundary behavior remains isolated.
func newServedHarness(t *testing.T, protocols config.Protocols, opts ...func(*Deps)) *servedHarness {
	t.Helper()
	if testing.Short() {
		t.Skip("boots embedded PostgreSQL + a signer; skipped in -short")
	}
	ctx := context.Background()
	dir := t.TempDir()

	// Embedded PostgreSQL + in-process NATS — the make-test spine.
	st := newServerTestStore(t)
	if protocols.RAKeyFile == "" && (protocols.SCEP.Enabled || protocols.CMP.Enabled) {
		protocols.RAKeyFile = filepath.Join(dir, "protocol-ra.key")
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(dir, "nats")})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	// A REAL signer: a persistent signing server over a UDS, dialed by a client wired
	// as the SignerProvider. The issuing CA key is generated INSIDE this signer
	// (AN-4); the control plane never holds it.
	kekW, err := kek.LoadOrCreate(filepath.Join(dir, "kek.bin"))
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	t.Cleanup(kekW.Destroy)
	ks := signing.NewKeyStore(filepath.Join(dir, "keys"), kekW)
	authz, err := crypto.NewSignAuthorizer(bytes.Repeat([]byte{0x39}, 32))
	if err != nil {
		t.Fatalf("NewSignAuthorizer: %v", err)
	}
	t.Cleanup(authz.Destroy)
	signerSrv, err := signing.NewPersistentServer(ks, signing.WithAuthorizer(authz))
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	socketDir, err := os.MkdirTemp("", "trstctl-signer-")
	if err != nil {
		t.Fatalf("signer socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "s.sock")
	signerCtx, cancelSigner := context.WithCancel(ctx)
	signerDone := make(chan error, 1)
	signerEarlyErr := make(chan error, 1)
	go func() {
		serr := signing.ServeServer(signerCtx, socket, signerSrv)
		if serr != nil {
			signerEarlyErr <- serr
		}
		signerDone <- serr
	}()
	t.Cleanup(func() {
		cancelSigner()
		if serr := <-signerDone; serr != nil {
			t.Errorf("serve signer: %v", serr)
		}
	})
	client, err := signing.DialReady(ctx, socket, 10*time.Second)
	if err != nil {
		select {
		case serr := <-signerEarlyErr:
			t.Fatalf("serve signer: %v", serr)
		default:
		}
		t.Fatalf("dial signer: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	caFile := filepath.Join(dir, "issuing-ca.crt")
	signerProvider := signing.StaticProvider{C: client}
	deps := Deps{
		Store:          st,
		Log:            log,
		Signer:         signerProvider,
		SignAuthorizer: authz,
		CACertFile:     caFile,
		KEK:            kekW,
		Protocols:      protocols,
	}
	for _, o := range opts {
		o(&deps)
	}
	srv, err := Build(ctx, deps)
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	if !srv.OutOfProcessSigning() {
		t.Fatal("issuing CA is not signer-backed — AN-4 violated in the test rig")
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	return &servedHarness{
		srv: srv, ts: ts, tenant: servedTestTenant, caPEM: srv.CACertPEM(),
		log: log, store: st, signer: signerProvider, authz: authz, caFile: caFile,
	}
}

// hasEvent reports whether an event of the given type for the harness tenant exists
// in the log (AN-2 assertion: the protocol mint was event-sourced).
func (h *servedHarness) hasEvent(t *testing.T, eventType string) bool {
	t.Helper()
	found := false
	if err := h.log.Replay(context.Background(), 0, func(e events.Event) error {
		if e.Type == eventType && e.TenantID == h.tenant {
			found = true
		}
		return nil
	}); err != nil {
		t.Fatalf("replay events: %v", err)
	}
	return found
}

// TestServedACMEEndToEnd is the EXC-WIRE-02 / INTEROP-001/002/003 acceptance proof for
// ACME: a STOCK golang.org/x/crypto/acme client with an ECDSA account key drives the
// SERVED ACME handler (mounted by server.Build, the same cmd/trstctl serves) through
// new-account -> new-order -> http-01 -> finalize and downloads a REAL, signer-issued
// certificate; the cert verifies against the served issuing CA and a
// certificate.recorded event exists (AN-2). Then the client REVOKES via ACME and the
// SERVED OCSP responder returns revoked. It MUST fail on the pre-wiring tree (no ACME
// was mounted: /directory 404s) and PASS after, and is race-clean.
func TestServedACMEEndToEnd(t *testing.T) {
	// Mint the ACME server with the production composition but a loopback-capable
	// HTTP-01 validator that dials a test challenge server (production keeps the
	// SSRF-guarded default — see Deps.ACMEValidators). The challenge server is set up
	// after the harness so its address is known; we rewrite all validator dials to it.
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
		func(d *Deps) { d.ACMEValidators = &validators },
	)

	if !protoContains(h.srv.ServedProtocols(), "acme") {
		t.Fatal("ACME is not reported as served — wire-in failed")
	}

	ctx := context.Background()

	// Stock ECDSA-account-key ACME client pointed at the SERVED directory (proves
	// INTEROP-003 over the served path: a default ECDSA client registers).
	client, err := acmekey.NewClient(h.ts.URL + "/directory")
	if err != nil {
		t.Fatalf("acme client: %v", err)
	}

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
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		t.Fatalf("wait order: %v", err)
	}

	// Finalize with a fresh CSR built through the crypto boundary (AN-3 forbids
	// stdlib crypto even in tests) — the SERVED ACME path signs it through the signer.
	csr := buildServedCSR(t, domain)
	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		t.Fatalf("finalize/create cert: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("served ACME returned no certificate")
	}
	leafDER := der[0]

	// The issued cert must verify against the SERVED issuing CA (a real, signer-issued
	// chain, not a stub).
	if err := crypto.VerifyLeafSignedByCA(leafDER, caCertDER(t, h.caPEM)); err != nil {
		t.Fatalf("served-ACME cert does not verify against the served CA: %v", err)
	}
	info, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatalf("inspect issued cert: %v", err)
	}
	if !protoContains(info.DNSNames, domain) {
		t.Errorf("issued cert SANs = %v, want %s", info.DNSNames, domain)
	}

	// AN-2: the served mint recorded a certificate.recorded event for the tenant.
	if !h.hasEvent(t, "certificate.recorded") {
		t.Error("no certificate.recorded event — the served ACME mint was not event-sourced (AN-2)")
	}
	// The protocol-specific issuance audit event is also present.
	if !h.hasEvent(t, "protocol.issued") {
		t.Error("no protocol.issued event for the served ACME mint (AN-2)")
	}

	// Before revoke: OCSP says good (the serial was bridged into ca_issued_certs).
	if st := servedOCSPStatus(t, h.srv, h.tenant, leafDER, h.caPEM); st != "good" {
		t.Fatalf("pre-revoke OCSP status = %q, want good", st)
	}

	// Revoke via ACME (RFC 8555 §7.6) using the ACCOUNT key (nil signer → the client
	// kid-authenticates with the account that ordered the cert — the account-key
	// revoke path). This avoids exposing the leaf key as a stdlib crypto.Signer, which
	// the AN-3 boundary forbids even in tests.
	if err := client.RevokeCert(ctx, nil, leafDER, xacme.CRLReasonKeyCompromise); err != nil {
		t.Fatalf("ACME revoke: %v", err)
	}

	if st := servedOCSPStatus(t, h.srv, h.tenant, leafDER, h.caPEM); st != "revoked" {
		t.Fatalf("post-revoke OCSP status = %q, want revoked", st)
	}

	crlDER, err := h.srv.GenerateCRL(ctx, h.tenant)
	if err != nil {
		t.Fatalf("generate served CRL after ACME revoke: %v", err)
	}
	crlInfo, err := crypto.ParseCRL(crlDER, caCertDER(t, h.caPEM))
	if err != nil {
		t.Fatalf("parse served CRL after ACME revoke: %v", err)
	}
	if !protoContains(crlInfo.RevokedSerials, info.SerialNumber) {
		t.Fatalf("CRL revoked serials = %v, want %s from ACME revoke", crlInfo.RevokedSerials, info.SerialNumber)
	}
}

// TestServedACMEStateRebuildsAfterServerRestart proves CORRECT-003 on the mounted
// control-plane path: ACME account/order/cert/ARI state is replayed from the tenant
// event log into a fresh server.Build instance before /directory and /acme/* serve.
func TestServedACMEStateRebuildsAfterServerRestart(t *testing.T) {
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
	protocols := config.Protocols{ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}}
	h := newServedHarness(t, protocols, func(d *Deps) { d.ACMEValidators = &validators })

	ctx := context.Background()
	client, err := acmekey.NewClient(h.ts.URL + "/directory")
	if err != nil {
		t.Fatalf("acme client: %v", err)
	}
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("register: %v", err)
	}
	const domain = "restart.served.test"
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatalf("authorize order: %v", err)
	}

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
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		t.Fatalf("wait order: %v", err)
	}
	der, certURL, err := client.CreateOrderCert(ctx, order.FinalizeURL, buildServedCSR(t, domain), true)
	if err != nil {
		t.Fatalf("finalize/create cert: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("served ACME returned no certificate")
	}
	leafDER := der[0]
	info, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatalf("inspect issued cert: %v", err)
	}
	certID, err := certinfo.ARICertID(leafDER)
	if err != nil {
		t.Fatalf("ARI certID: %v", err)
	}
	h.ts.Close()

	restarted, err := Build(ctx, Deps{
		Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz,
		CACertFile: h.caFile, Protocols: protocols, ACMEValidators: &validators,
	})
	if err != nil {
		t.Fatalf("restart server build: %v", err)
	}
	ts2 := httptest.NewServer(restarted.Handler())
	t.Cleanup(ts2.Close)
	if !bytes.Equal(restarted.CACertPEM(), h.caPEM) {
		t.Fatal("served issuing CA changed across restart")
	}

	restartedClient := &xacme.Client{
		Key:          client.Key,
		DirectoryURL: ts2.URL + "/directory",
		KID:          client.KID,
	}
	fetched, err := restartedClient.FetchCert(ctx, rewriteServedBaseURL(t, certURL, ts2.URL), true)
	if err != nil {
		t.Fatalf("fetch cert after restart: %v", err)
	}
	if len(fetched) == 0 || !bytes.Equal(fetched[0], leafDER) {
		t.Fatal("restarted served ACME returned the wrong certificate")
	}
	renewal, err := http.Get(ts2.URL + "/acme/renewal-info/" + certID)
	if err != nil {
		t.Fatalf("fetch ARI after restart: %v", err)
	}
	defer func() { _ = renewal.Body.Close() }()
	if renewal.StatusCode != http.StatusOK {
		t.Fatalf("ARI after restart status = %d, want 200", renewal.StatusCode)
	}

	if err := restartedClient.RevokeCert(ctx, nil, leafDER, xacme.CRLReasonCessationOfOperation); err != nil {
		t.Fatalf("ACME revoke after restart: %v", err)
	}
	if st := servedOCSPStatus(t, restarted, h.tenant, leafDER, h.caPEM); st != "revoked" {
		t.Fatalf("post-restart ACME revoke OCSP status = %q, want revoked", st)
	}
	crlDER, err := restarted.GenerateCRL(ctx, h.tenant)
	if err != nil {
		t.Fatalf("generate served CRL after restart revoke: %v", err)
	}
	crlInfo, err := crypto.ParseCRL(crlDER, caCertDER(t, h.caPEM))
	if err != nil {
		t.Fatalf("parse served CRL after restart revoke: %v", err)
	}
	if !protoContains(crlInfo.RevokedSerials, info.SerialNumber) {
		t.Fatalf("post-restart CRL revoked serials = %v, want %s", crlInfo.RevokedSerials, info.SerialNumber)
	}
}

func TestACMEProtocolQuotaIsIndependentFromAPIRateLimit(t *testing.T) {
	h := newServedHarness(t,
		config.Protocols{
			ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
			ACMEQuota: config.ACMEQuota{
				MaxNonces:             1,
				MaxNewNoncesPerSource: 10,
			},
		},
	)

	resp, err := http.Get(h.ts.URL + "/acme/new-nonce")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("first served ACME nonce status = %d, want 204", resp.StatusCode)
	}
	resp, err = http.Get(h.ts.URL + "/acme/new-nonce")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("served ACME quota status = %d, want 429 from the protocol-local quota", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.Contains(got, "application/problem+json") {
		t.Fatalf("served ACME quota content-type = %q, want problem+json", got)
	}
}

// servedOCSPStatus drives the SERVED OCSP responder (Server.OCSPResponse — the exact
// served path) for a leaf and returns its status string.
func servedOCSPStatus(t *testing.T, srv *Server, tenant string, leafDER []byte, caPEM []byte) string {
	t.Helper()
	reqDER, err := crypto.BuildOCSPRequest(leafDER, caCertDER(t, caPEM))
	if err != nil {
		t.Fatalf("build OCSP request: %v", err)
	}
	respDER, err := srv.OCSPResponse(context.Background(), tenant, reqDER)
	if err != nil {
		t.Fatalf("served OCSP response: %v", err)
	}
	info, err := crypto.ParseOCSPResponse(respDER, caCertDER(t, caPEM))
	if err != nil {
		t.Fatalf("parse OCSP response: %v", err)
	}
	return info.Status
}

// buildServedCSR builds a PKCS#10 CSR for the domain through the crypto boundary
// (AN-3 forbids stdlib crypto even in tests). A fresh locked ECDSA key signs the CSR;
// the served ACME path then signs the leaf through the signer.
func buildServedCSR(t *testing.T, domain string) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	der, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: domain, DNSNames: []string{domain}}, key)
	if err != nil {
		t.Fatalf("build CSR: %v", err)
	}
	return der
}

// caCertDER decodes a PEM CA cert to DER.
func caCertDER(t *testing.T, caPEM []byte) []byte {
	t.Helper()
	blk, _ := pem.Decode(caPEM)
	if blk == nil {
		t.Fatal("CA PEM does not decode")
	}
	return blk.Bytes
}

func rewriteServedBaseURL(t *testing.T, rawURL, base string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	b, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse %q: %v", base, err)
	}
	u.Scheme = b.Scheme
	u.Host = b.Host
	return u.String()
}

// contains reports whether s contains v.
func protoContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
