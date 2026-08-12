// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/kek"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/pluginhost/wasmgen"
	"trstctl.com/trstctl/internal/projections"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
	"trstctl.com/trstctl/internal/protocols/ari"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

// dnsProviderWASMFor is a minimal signed DNS-provider plugin: run() satisfies the
// admission/conformance probe without performing any privileged call, and
// present_txt()/cleanup_txt() each perform one granted host operation so the
// served path proves the capability sandbox is active.
//
// It writes inside dir, which the test grants: the capability ABI carries a real
// path through guest memory, so the module has to name one and the grant has to
// cover it.
func dnsProviderWASMFor(dir string) []byte {
	target := filepath.Join(dir, "txt-record")
	args := wasmgen.WriteArgs(target, "v")
	return wasmgen.Module("cap_write", 4, []byte(target+"v"), []wasmgen.Export{
		{Name: "run", Const: 0},
		{Name: "present_txt", Args: args},
		{Name: "cleanup_txt", Args: args},
	})
}

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
	kek    sealKeyWrapper

	externalCADispatcherOnce sync.Once
}

func startServedExternalCADispatcher(t *testing.T, h *servedHarness) {
	t.Helper()
	h.externalCADispatcherOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			h.srv.RunDispatcher(ctx)
		}()
		t.Cleanup(func() {
			cancel()
			<-done
		})
	})
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
		serr := signing.ServeServerWithOptions(signerCtx, socket, signerSrv, signing.ServeOptions{AllowInsecureDevNonLinux: runtime.GOOS != "linux"})
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
		APIOptions: []api.Option{
			api.WithKubernetesCSRPosture(st),
			api.WithKubernetesTrustBundlePosture(st),
		},
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
		kek: deps.KEK,
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

// TestServedACMEDNS01ProviderCatalogCAPISS02 proves CAP-ISS-02 on the running
// control-plane surface: broad DNS-01 provider coverage is discoverable through the
// served API, not merely present as libraries or prose. The response deliberately
// exposes credential-reference fields only; provider tokens remain in the secret
// store/outbox path, never in browser/API catalog payloads.
func TestServedACMEDNS01ProviderCatalogCAPISS02(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "issuers:read")

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/acme/dns-01/providers", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("dns-01 provider catalog: status %d body %s", status, body)
	}

	var catalog struct {
		Items []struct {
			Name                      string   `json:"name"`
			Kind                      string   `json:"kind"`
			Served                    bool     `json:"served"`
			PropagationPreflight      bool     `json:"propagation_preflight"`
			Conformance               string   `json:"conformance"`
			CredentialReferenceFields []string `json:"credential_reference_fields"`
			SecretFields              []string `json:"secret_fields"`
			Capabilities              []string `json:"capabilities"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &catalog); err != nil {
		t.Fatalf("decode dns-01 provider catalog: %v body=%s", err, body)
	}

	required := map[string]bool{
		"route53":    false,
		"googledns":  false,
		"azuredns":   false,
		"cloudflare": false,
		"rfc2136":    false,
		"webhook":    false,
	}
	for _, item := range catalog.Items {
		if _, ok := required[item.Name]; !ok {
			continue
		}
		if !item.Served {
			t.Fatalf("%s catalog row is not marked served: %+v", item.Name, item)
		}
		if item.Kind == "" || item.Conformance != "present-validate-cleanup" {
			t.Fatalf("%s catalog row does not expose provider conformance: %+v", item.Name, item)
		}
		if !item.PropagationPreflight {
			t.Fatalf("%s catalog row omits propagation preflight support: %+v", item.Name, item)
		}
		if len(item.CredentialReferenceFields) == 0 {
			t.Fatalf("%s catalog row does not require secret references: %+v", item.Name, item)
		}
		if len(item.SecretFields) != 0 {
			t.Fatalf("%s catalog row exposes raw secret fields in the served API: %+v", item.Name, item)
		}
		if len(item.Capabilities) == 0 {
			t.Fatalf("%s catalog row omits provider capability grants: %+v", item.Name, item)
		}
		required[item.Name] = true
	}
	for name, seen := range required {
		if !seen {
			t.Fatalf("served DNS-01 provider catalog missing %s; body=%s", name, body)
		}
	}
}

// TestServedACMEDNS01ProviderConfigAndPreflightTRACE003 proves TRACE-003 on the
// running control-plane surface: DNS-01 provider configuration is served as a
// tenant-scoped, event-sourced API/CLI target that stores credential references
// only, and preflight evaluates delegation, TXT propagation, CAA, method, and
// wildcard policy before ACME issuance relies on a DNS-01 provider.
func TestServedACMEDNS01ProviderConfigAndPreflightTRACE003(t *testing.T) {
	caaDNS := newServedDNSWebhookFixture(t, "dns-preflight-token")
	caaDNS.setCAA("example.test", []acmesrv.CAARecord{{Tag: "issuewild", Value: "trstctl.example"}})
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.APIOptions = append(d.APIOptions, api.WithACMEDNS01CAAResolver(caaDNS))
	})
	tok := seedScopedToken(t, h.store, h.tenant, "issuers:read", "issuers:write")

	create := map[string]any{
		"name":              "prod-cloudflare",
		"provider":          "cloudflare",
		"zone":              "example.test",
		"delegation_target": "tenant-123.auth.acme-dns.example.net",
		"credential_refs": map[string]any{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
			"api_token_ref": "secret://dns/cloudflare/api-token",
		},
		"config": map[string]any{
			"zone_id": "zone-prod",
		},
		"caa_issuer_domain": "trstctl.example",
		"allowed_methods":   []string{"dns-01"},
		"allow_wildcards":   true,
	}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/provider-configs", tok, create)
	if status != http.StatusCreated {
		t.Fatalf("create dns-01 provider config: status %d body %s", status, body)
	}
	if bytes.Contains(body, []byte("raw-token")) {
		t.Fatalf("provider config response leaked raw secret material: %s", body)
	}
	var created struct {
		ID             string            `json:"id"`
		Provider       string            `json:"provider"`
		CredentialRefs map[string]string `json:"credential_refs"`
		SecretHandling string            `json:"secret_handling"`
		AllowedMethods []string          `json:"allowed_methods"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode created provider config: %v body=%s", err, body)
	}
	if created.ID == "" || created.Provider != "cloudflare" {
		t.Fatalf("created provider config lost identity/provider: %+v", created)
	}
	if created.SecretHandling != "credential_refs_only" || created.CredentialRefs["api_token_ref"] == "" {
		t.Fatalf("created provider config did not preserve credential-reference-only shape: %+v", created)
	}
	if len(created.AllowedMethods) != 1 || created.AllowedMethods[0] != "dns-01" {
		t.Fatalf("created provider config did not retain DNS-01 method policy: %+v", created.AllowedMethods)
	}

	rejectInlineSecret := map[string]any{
		"name":     "bad-cloudflare",
		"provider": "cloudflare",
		"credential_refs": map[string]any{
			"api_token": "raw-token",
		},
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/provider-configs", tok, rejectInlineSecret)
	if status != http.StatusBadRequest {
		t.Fatalf("inline DNS provider secret should be rejected: status %d body %s", status, body)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/acme/dns-01/provider-configs", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list dns-01 provider configs: status %d body %s", status, body)
	}
	if !bytes.Contains(body, []byte(created.ID)) {
		t.Fatalf("list dns-01 provider configs omitted created config %s: %s", created.ID, body)
	}

	preflight := map[string]any{
		"config_id":      created.ID,
		"domain":         "*.example.test",
		"expected_txt":   "txt-proof",
		"observed_txt":   []string{"txt-proof"},
		"observed_cname": "tenant-123.auth.acme-dns.example.net.",
		"caa_records": []map[string]any{
			{"name": "example.test", "tag": "issuewild", "issuer_domain": "trstctl.example"},
		},
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/preflight", tok, preflight)
	if status != http.StatusOK {
		t.Fatalf("dns-01 preflight: status %d body %s", status, body)
	}
	var result struct {
		Ready          bool     `json:"ready"`
		RecordName     string   `json:"record_name"`
		SelectedMethod string   `json:"selected_method"`
		Wildcard       bool     `json:"wildcard"`
		FailedChecks   []string `json:"failed_checks"`
		Checks         []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode dns-01 preflight: %v body=%s", err, body)
	}
	if !result.Ready || result.RecordName != "_acme-challenge.example.test" || result.SelectedMethod != "dns-01" || !result.Wildcard || len(result.FailedChecks) != 0 {
		t.Fatalf("dns-01 preflight did not pass expected checks: %+v body=%s", result, body)
	}
	passed := map[string]bool{}
	for _, check := range result.Checks {
		if check.Status == "pass" {
			passed[check.Name] = true
		}
	}
	for _, name := range []string{"provider_config", "method_policy", "wildcard_policy", "cname_delegation", "txt_propagation", "caa_policy"} {
		if !passed[name] {
			t.Fatalf("dns-01 preflight missing passing check %q: %+v", name, result.Checks)
		}
	}
	if !h.hasEvent(t, projections.EventACMEDNS01ProviderConfigUpserted) || !h.hasEvent(t, projections.EventACMEDNS01Preflighted) {
		t.Fatal("DNS-01 provider config/preflight did not append expected audit events")
	}
}

// TestServedACMEDNS01OrderPublishesAndCleansUpThroughOutboxTRACE012 proves the
// TRACE-012 closure on the running control-plane surface: a stock ACME client
// accepts dns-01 without pre-publishing the TXT itself, and the served ACME order
// path resolves the tenant provider config, publishes the TXT through the outbox,
// validates it, cleans it up through the outbox, and then finalizes a real signer-
// issued certificate.
func TestServedACMEDNS01OrderPublishesAndCleansUpThroughOutboxTRACE012(t *testing.T) {
	dns := newServedDNSWebhookFixture(t, "dns-webhook-token")
	validators := acmesrv.Validators{
		HTTP01: acmesrv.HTTP01Validator{},
		DNS01:  acmesrv.DNS01Validator{Resolver: dns},
	}
	h := newServedHarness(t,
		config.Protocols{ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		withSecretsEnabled(t, nil),
		func(d *Deps) { d.ACMEValidators = &validators },
	)
	startServedOutboxPump(t, h.srv)
	tok := seedScopedToken(t, h.store, h.tenant, "issuers:read", "issuers:write", "secrets:read", "secrets:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok, map[string]any{
		"name":  "dns/webhook/bearer-token",
		"value": "dns-webhook-token",
	})
	if status != http.StatusCreated {
		t.Fatalf("create DNS webhook bearer secret: status %d body %s", status, body)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/provider-configs", tok, map[string]any{
		"name":     "trace012-webhook",
		"provider": "webhook",
		"zone":     "trace012.test",
		"credential_refs": map[string]any{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
			"bearer_token_ref": "secret://dns/webhook/bearer-token",
		},
		"config": map[string]any{
			"endpoint": dns.URL(),
		},
		"allowed_methods": []string{"dns-01"},
		"allow_wildcards": true,
	})
	if status != http.StatusCreated {
		t.Fatalf("create DNS-01 provider config: status %d body %s", status, body)
	}

	ctx := context.Background()
	client, err := acmekey.NewClient(h.ts.URL + "/directory")
	if err != nil {
		t.Fatalf("acme client: %v", err)
	}
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("register: %v", err)
	}

	const domain = "dns01.trace012.test"
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatalf("authorize order: %v", err)
	}
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			t.Fatalf("get authorization: %v", err)
		}
		var chal *xacme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "dns-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			t.Fatal("served ACME offered no dns-01 challenge")
		}
		wantValue, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			t.Fatalf("compute dns-01 challenge record: %v", err)
		}
		if _, err := client.Accept(ctx, chal); err != nil {
			t.Fatalf("accept dns-01 challenge: %v", err)
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			t.Fatalf("wait authorization: %v", err)
		}
		dns.assertPresentedAndCleaned(t, acmesrv.DNS01RecordName(domain), wantValue)
	}
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		t.Fatalf("wait order: %v", err)
	}

	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, buildServedCSR(t, domain), true)
	if err != nil {
		t.Fatalf("finalize/create cert: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("served ACME DNS-01 order returned no certificate")
	}
	if err := crypto.VerifyLeafSignedByCA(der[0], caCertDER(t, h.caPEM)); err != nil {
		t.Fatalf("served ACME DNS-01 cert does not verify against the served CA: %v", err)
	}
	rows := servedOutboxRowsByDestination(t, h, "acme.dns01.")
	if rows["acme.dns01.present:delivered"] != 1 || rows["acme.dns01.cleanup:delivered"] != 1 {
		t.Fatalf("dns-01 outbox rows = %#v, want one delivered present and cleanup row", rows)
	}
	if !h.hasEvent(t, "acme.dns01.record.presented") || !h.hasEvent(t, "acme.dns01.record.cleaned") {
		t.Fatal("served DNS-01 publish/cleanup did not append audit events")
	}
}

// TestServedACMEDomainValidationPolicyLimitsOrderChallengesTRACE016 proves F73 on
// the assembled served ACME path: tenant-managed allowed_methods policy is not just
// a preflight helper. New orders for a managed domain advertise only the currently
// allowed DV challenge types, and policy updates take effect on later orders.
func TestServedACMEDomainValidationPolicyLimitsOrderChallengesTRACE016(t *testing.T) {
	h := newServedHarness(t,
		config.Protocols{ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
	)
	tok := seedScopedToken(t, h.store, h.tenant, "issuers:read", "issuers:write")

	create := map[string]any{
		"name":     "trace016-dv-policy",
		"provider": "webhook",
		"zone":     "trace016.test",
		"credential_refs": map[string]any{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
			"bearer_token_ref": "secret://dns/trace016/bearer-token",
		},
		"config": map[string]any{
			"endpoint": "https://dns.trace016.invalid",
		},
		"allowed_methods": []string{"dns-01"},
	}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/provider-configs", tok, create)
	if status != http.StatusCreated {
		t.Fatalf("create TRACE-016 DV policy provider config: status %d body %s", status, body)
	}
	var created struct {
		ID             string   `json:"id"`
		AllowedMethods []string `json:"allowed_methods"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode TRACE-016 provider config: %v body=%s", err, body)
	}
	if created.ID == "" || len(created.AllowedMethods) != 1 || created.AllowedMethods[0] != "dns-01" {
		t.Fatalf("created TRACE-016 policy config did not retain dns-01 policy: %+v body=%s", created, body)
	}

	ctx := context.Background()
	client, err := acmekey.NewClient(h.ts.URL + "/directory")
	if err != nil {
		t.Fatalf("acme client: %v", err)
	}
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("register: %v", err)
	}
	assertServedACMEChallengeTypes(t, ctx, client, "dns-only.trace016.test", []string{"dns-01"})

	update := map[string]any{
		"name":     "trace016-dv-policy",
		"provider": "webhook",
		"zone":     "trace016.test",
		"credential_refs": map[string]any{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
			"bearer_token_ref": "secret://dns/trace016/bearer-token",
		},
		"config": map[string]any{
			"endpoint": "https://dns.trace016.invalid",
		},
		"allowed_methods": []string{"tls-alpn-01"},
	}
	status, body = secretsReq(t, h, http.MethodPut, "/api/v1/acme/dns-01/provider-configs/"+created.ID, tok, update)
	if status != http.StatusOK {
		t.Fatalf("update TRACE-016 DV policy provider config: status %d body %s", status, body)
	}
	assertServedACMEChallengeTypes(t, ctx, client, "alpn-only.trace016.test", []string{"tls-alpn-01"})

	if !h.hasEvent(t, projections.EventACMEDNS01ProviderConfigUpserted) {
		t.Fatal("TRACE-016 DV policy management did not append provider-config audit events")
	}
}

func assertServedACMEChallengeTypes(t *testing.T, ctx context.Context, client *xacme.Client, domain string, want []string) {
	t.Helper()
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatalf("authorize order for %s: %v", domain, err)
	}
	if len(order.AuthzURLs) != 1 {
		t.Fatalf("order for %s returned %d authorizations, want 1", domain, len(order.AuthzURLs))
	}
	authz, err := client.GetAuthorization(ctx, order.AuthzURLs[0])
	if err != nil {
		t.Fatalf("get authorization for %s: %v", domain, err)
	}
	got := make([]string, 0, len(authz.Challenges))
	for _, chal := range authz.Challenges {
		got = append(got, chal.Type)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ACME challenges for %s = %v, want only %v", domain, got, want)
	}
}

// TestServedACMEDNS01OrderPublishesDelegatedCNAMEThroughOutboxTRACE014 proves F71
// on the served order-time path: when a tenant provider config declares a
// delegation target, ACME DNS-01 publish/cleanup writes only to that isolated
// validation target and fails closed when the production _acme-challenge name is
// not delegated.
func TestServedACMEDNS01OrderPublishesDelegatedCNAMEThroughOutboxTRACE014(t *testing.T) {
	dns := newServedDNSWebhookFixture(t, "dns-delegated-token")
	h := newServedHarness(t,
		config.Protocols{ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		withSecretsEnabled(t, nil),
	)
	h.srv.acmeDNS01.cnameResolver = dns
	startServedDirectOutboxPump(t, h.srv)
	tok := seedScopedToken(t, h.store, h.tenant, "issuers:read", "issuers:write", "secrets:read", "secrets:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok, map[string]any{
		"name":  "dns/delegated/bearer-token",
		"value": "dns-delegated-token",
	})
	if status != http.StatusCreated {
		t.Fatalf("create DNS delegated bearer secret: status %d body %s", status, body)
	}

	const delegatedTarget = "tenant-123.auth.acme-dns.example.net"
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/provider-configs", tok, map[string]any{
		"name":              "trace014-delegated-webhook",
		"provider":          "webhook",
		"zone":              "trace014.test",
		"delegation_target": delegatedTarget,
		"credential_refs": map[string]any{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
			"bearer_token_ref": "secret://dns/delegated/bearer-token",
		},
		"config": map[string]any{
			"endpoint": dns.URL(),
		},
		"allowed_methods": []string{"dns-01"},
		"allow_wildcards": true,
	})
	if status != http.StatusCreated {
		t.Fatalf("create delegated DNS-01 provider config: status %d body %s", status, body)
	}

	const domain = "delegated.trace014.test"
	const keyAuth = "trace014-key-authorization"
	recordName := acmesrv.DNS01RecordName(domain)
	wantValue := acmesrv.DNS01RecordValue(keyAuth)
	dns.setCNAME(recordName, delegatedTarget+".")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cleanup, err := h.srv.acmeDNS01.Present(ctx, h.tenant, domain, "", keyAuth)
	if err != nil {
		t.Fatalf("served ACME DNS-01 delegated present: %v", err)
	}
	observed, err := dns.LookupTXT(ctx, recordName)
	if err != nil {
		t.Fatalf("lookup delegated DNS-01 TXT: %v", err)
	}
	if !containsString(observed, wantValue) {
		t.Fatalf("delegated DNS-01 records = %v, want %s at %s via %s", observed, wantValue, recordName, delegatedTarget)
	}
	if err := cleanup(ctx); err != nil {
		t.Fatalf("served ACME DNS-01 delegated cleanup: %v", err)
	}
	dns.assertPresentedAndCleaned(t, delegatedTarget, wantValue)
	dns.assertNeverRequested(t, recordName)

	const missingDomain = "missing-delegation.trace014.test"
	missingRecord := acmesrv.DNS01RecordName(missingDomain)
	if _, err := h.srv.acmeDNS01.Present(ctx, h.tenant, missingDomain, "", "trace014-missing-key-authorization"); err == nil {
		t.Fatal("served ACME DNS-01 delegated present succeeded without a CNAME")
	}
	dns.assertNeverRequested(t, missingRecord)
}

// TestServedACMEDNS01LiveCAAEnforcementTRACE015 proves F72 on the assembled served
// path: CAA is read from the authoritative DNS resolver, not trusted from the
// preflight request body, and an order-time CAA denial stops before any DNS write or
// outbox row is committed.
func TestServedACMEDNS01LiveCAAEnforcementTRACE015(t *testing.T) {
	dns := newServedDNSWebhookFixture(t, "dns-caa-token")
	h := newServedHarness(t,
		config.Protocols{ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.APIOptions = append(d.APIOptions, api.WithACMEDNS01CAAResolver(dns))
		},
	)
	h.srv.acmeDNS01.caaResolver = dns
	startServedDirectOutboxPump(t, h.srv)
	tok := seedScopedToken(t, h.store, h.tenant, "issuers:read", "issuers:write", "secrets:read", "secrets:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok, map[string]any{
		"name":  "dns/caa/bearer-token",
		"value": "dns-caa-token",
	})
	if status != http.StatusCreated {
		t.Fatalf("create DNS CAA bearer secret: status %d body %s", status, body)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/provider-configs", tok, map[string]any{
		"name":              "trace015-caa-webhook",
		"provider":          "webhook",
		"zone":              "trace015.test",
		"caa_issuer_domain": "trstctl.example",
		"credential_refs": map[string]any{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
			"bearer_token_ref": "secret://dns/caa/bearer-token",
		},
		"config": map[string]any{
			"endpoint": dns.URL(),
		},
		"allowed_methods": []string{"dns-01"},
		"allow_wildcards": true,
	})
	if status != http.StatusCreated {
		t.Fatalf("create CAA DNS-01 provider config: status %d body %s", status, body)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode CAA provider config: %v body=%s", err, body)
	}
	if created.ID == "" {
		t.Fatal("created CAA provider config returned no id")
	}

	dns.setCAA("trace015.test", []acmesrv.CAARecord{{Tag: "issue", Value: "trstctl.example"}})
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/preflight", tok, map[string]any{
		"config_id":    created.ID,
		"domain":       "allowed.trace015.test",
		"expected_txt": "txt-proof",
		"observed_txt": []string{"txt-proof"},
		"caa_records": []map[string]any{
			{"name": "trace015.test", "tag": "issue", "issuer_domain": "other.ca"},
		},
	})
	if status != http.StatusOK {
		t.Fatalf("CAA live preflight: status %d body %s", status, body)
	}
	var preflight struct {
		Ready        bool     `json:"ready"`
		FailedChecks []string `json:"failed_checks"`
		Checks       []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(body, &preflight); err != nil {
		t.Fatalf("decode CAA preflight: %v body=%s", err, body)
	}
	if !preflight.Ready || containsString(preflight.FailedChecks, "caa_policy") {
		t.Fatalf("preflight trusted request-supplied CAA instead of live DNS: %+v body=%s", preflight, body)
	}
	if !checkStatus(preflight.Checks, "caa_policy", "pass") {
		t.Fatalf("preflight did not report passing live CAA policy: %+v", preflight.Checks)
	}

	dns.setCAA("trace015.test", []acmesrv.CAARecord{{Tag: "issue", Value: "other.ca"}})
	const deniedDomain = "denied.trace015.test"
	deniedRecord := acmesrv.DNS01RecordName(deniedDomain)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := h.srv.acmeDNS01.Present(ctx, h.tenant, deniedDomain, "", "trace015-denied-key-authorization"); err == nil {
		t.Fatal("served ACME DNS-01 present succeeded when live CAA denied the configured issuer")
	}
	dns.assertNeverRequested(t, deniedRecord)
	if rows := servedOutboxRowsByDestination(t, h, "acme.dns01."); len(rows) != 0 {
		t.Fatalf("CAA denial should stop before enqueueing DNS-01 outbox work, got rows %#v", rows)
	}

	dns.setCAAError(errors.New("servfail"))
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/preflight", tok, map[string]any{
		"config_id":    created.ID,
		"domain":       "lookup-error.trace015.test",
		"expected_txt": "txt-proof",
		"observed_txt": []string{"txt-proof"},
	})
	if status != http.StatusOK {
		t.Fatalf("CAA lookup-error preflight: status %d body %s", status, body)
	}
	if err := json.Unmarshal(body, &preflight); err != nil {
		t.Fatalf("decode CAA lookup-error preflight: %v body=%s", err, body)
	}
	if preflight.Ready || !containsString(preflight.FailedChecks, "caa_policy") {
		t.Fatalf("preflight did not fail closed on live CAA lookup error: %+v body=%s", preflight, body)
	}
}

func checkStatus(checks []struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}, name, status string) bool {
	for _, check := range checks {
		if check.Name == name && check.Status == status {
			return true
		}
	}
	return false
}

// TestServedACMEDNS01OrderActivatesSignedDNSProviderPluginTRACE013 proves F70 on
// the served path: a signed/conformant DNS provider plugin is admitted into the
// running provider catalog, a tenant provider config can select it, and the served
// ACME DNS-01 automation hook activates the plugin from the outbox worker before
// publish/cleanup complete. TRACE-012 covers the stock ACME client finalization
// over this same hook; this test isolates the plugin activation contract.
func TestServedACMEDNS01OrderActivatesSignedDNSProviderPluginTRACE013(t *testing.T) {
	dns := newServedDNSWebhookFixture(t, "dns-plugin-token")
	validators := acmesrv.Validators{
		HTTP01: acmesrv.HTTP01Validator{},
		DNS01:  acmesrv.DNS01Validator{Resolver: dns},
	}
	pubDER, sign, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate plugin signing key: %v", err)
	}
	keyPEM := crypto.MarshalPublicKeyPEM(pubDER)
	dnsWorkdir, dnsGrant := pluginGrantDir(t)
	dnsDir := writePluginDir(t, "reference-dns", dnsProviderWASMFor(dnsWorkdir), sign)

	h := newServedHarness(t,
		config.Protocols{ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.ACMEValidators = &validators
			d.Plugins = PluginConfig{
				DNSDir:         dnsDir,
				TrustedKeyPEMs: [][]byte{keyPEM},
				DNSGrant:       dnsGrant,
			}
		},
	)
	startServedDirectOutboxPump(t, h.srv)
	tok := seedScopedToken(t, h.store, h.tenant, "issuers:read", "issuers:write", "secrets:read", "secrets:write")

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/acme/dns-01/providers", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list DNS-01 provider catalog: status %d body %s", status, body)
	}
	var catalog struct {
		Items []struct {
			Name            string   `json:"name"`
			Kind            string   `json:"kind"`
			Conformance     string   `json:"conformance"`
			ProviderPackage string   `json:"provider_package"`
			Provenance      string   `json:"provenance"`
			Capabilities    []string `json:"capabilities"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &catalog); err != nil {
		t.Fatalf("decode DNS-01 provider catalog: %v body=%s", err, body)
	}
	var pluginCatalogOK bool
	for _, item := range catalog.Items {
		if item.Name == "reference-dns" {
			if item.Kind != "plugin" || item.Conformance == "" || item.Provenance == "" || item.ProviderPackage != "signed-wasm:reference-dns" || !containsString(item.Capabilities, "fs.write") {
				t.Fatalf("plugin catalog row lacks admission/conformance/provenance/grant evidence: %+v", item)
			}
			pluginCatalogOK = true
		}
	}
	if !pluginCatalogOK {
		t.Fatalf("signed DNS plugin was not exposed in provider catalog: %+v", catalog.Items)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok, map[string]any{
		"name":  "dns/plugin/bearer-token",
		"value": "dns-plugin-token",
	})
	if status != http.StatusCreated {
		t.Fatalf("create DNS plugin bearer secret: status %d body %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/provider-configs", tok, map[string]any{
		"name":     "trace013-plugin",
		"provider": "reference-dns",
		"zone":     "trace013.test",
		"credential_refs": map[string]any{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
			"bearer_token_ref": "secret://dns/plugin/bearer-token",
		},
		"config": map[string]any{
			"endpoint": dns.URL(),
		},
		"allowed_methods": []string{"dns-01"},
		"allow_wildcards": true,
	})
	if status != http.StatusCreated {
		t.Fatalf("create DNS plugin provider config: status %d body %s", status, body)
	}

	const domain = "plugin-dns01.trace013.test"
	const keyAuth = "trace013-key-authorization"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cleanup, err := h.srv.acmeDNS01.Present(ctx, h.tenant, domain, "", keyAuth)
	if err != nil {
		t.Fatalf("served ACME DNS-01 plugin present: %v", err)
	}
	recordName := acmesrv.DNS01RecordName(domain)
	wantValue := acmesrv.DNS01RecordValue(keyAuth)
	observed, err := dns.LookupTXT(ctx, recordName)
	if err != nil {
		t.Fatalf("lookup DNS plugin TXT: %v", err)
	}
	if !containsString(observed, wantValue) {
		t.Fatalf("DNS plugin publish records = %v, want %s", observed, wantValue)
	}
	if err := cleanup(ctx); err != nil {
		t.Fatalf("served ACME DNS-01 plugin cleanup: %v", err)
	}
	dns.assertPresentedAndCleaned(t, recordName, wantValue)
	if !h.hasEvent(t, "acme.dns01.plugin.presented") || !h.hasEvent(t, "acme.dns01.plugin.cleaned") {
		t.Fatal("served DNS plugin publish/cleanup did not append plugin audit events")
	}
	if h.hasEvent(t, "acme.dns01.plugin.denied") || h.hasEvent(t, "acme.dns01.plugin.failed") {
		t.Fatal("served DNS plugin recorded a denial/failure despite its configured grant")
	}
}

type servedDNSWebhookFixture struct {
	srv         *httptest.Server
	bearerToken string

	mu       sync.Mutex
	records  map[string]map[string]bool
	cnames   map[string]string
	caa      map[string][]acmesrv.CAARecord
	caaErr   error
	requests []servedDNSWebhookRequest
}

type servedDNSWebhookRequest struct {
	Action        string `json:"action"`
	Name          string `json:"name"`
	Value         string `json:"value"`
	Authorization string `json:"-"`
}

func newServedDNSWebhookFixture(t *testing.T, bearerToken string) *servedDNSWebhookFixture {
	t.Helper()
	f := &servedDNSWebhookFixture{
		bearerToken: bearerToken,
		records:     map[string]map[string]bool{},
		cnames:      map[string]string{},
		caa:         map[string][]acmesrv.CAARecord{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *servedDNSWebhookFixture) URL() string { return f.srv.URL }

func (f *servedDNSWebhookFixture) setCNAME(name, target string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cnames[strings.TrimSuffix(name, ".")] = strings.TrimSuffix(target, ".")
}

func (f *servedDNSWebhookFixture) setCAA(name string, records []acmesrv.CAARecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.caaErr = nil
	name = strings.TrimSuffix(name, ".")
	f.caa[name] = append([]acmesrv.CAARecord(nil), records...)
}

func (f *servedDNSWebhookFixture) setCAAError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.caaErr = err
}

func (f *servedDNSWebhookFixture) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	action := strings.TrimPrefix(r.URL.Path, "/")
	if action != "present" && action != "cleanup" {
		http.NotFound(w, r)
		return
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+f.bearerToken {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	defer func() { _ = r.Body.Close() }()
	var req servedDNSWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Authorization = r.Header.Get("Authorization")
	if req.Action != action || req.Name == "" || req.Value == "" {
		http.Error(w, "invalid webhook request", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, req)
	switch action {
	case "present":
		if f.records[req.Name] == nil {
			f.records[req.Name] = map[string]bool{}
		}
		f.records[req.Name][req.Value] = true
	case "cleanup":
		if f.records[req.Name] != nil {
			delete(f.records[req.Name], req.Value)
			if len(f.records[req.Name]) == 0 {
				delete(f.records, req.Name)
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{}`))
}

func (f *servedDNSWebhookFixture) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	name = strings.TrimSuffix(name, ".")
	if target := f.cnames[name]; target != "" {
		name = target
	}
	values := make([]string, 0, len(f.records[name]))
	for value := range f.records[name] {
		values = append(values, value)
	}
	return values, nil
}

func (f *servedDNSWebhookFixture) LookupCNAME(_ context.Context, name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	name = strings.TrimSuffix(name, ".")
	if target := f.cnames[name]; target != "" {
		return target + ".", nil
	}
	return name + ".", nil
}

func (f *servedDNSWebhookFixture) LookupCAA(_ context.Context, name string) ([]acmesrv.CAARecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.caaErr != nil {
		return nil, f.caaErr
	}
	name = strings.TrimSuffix(name, ".")
	return append([]acmesrv.CAARecord(nil), f.caa[name]...), nil
}

func (f *servedDNSWebhookFixture) assertPresentedAndCleaned(t *testing.T, name, value string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	name = strings.TrimSuffix(name, ".")
	var presented, cleaned bool
	for _, req := range f.requests {
		if req.Name != name || req.Value != value || req.Authorization != "Bearer "+f.bearerToken {
			continue
		}
		switch req.Action {
		case "present":
			presented = true
		case "cleanup":
			cleaned = true
		}
	}
	if !presented || !cleaned {
		t.Fatalf("DNS webhook requests = %+v, want present and cleanup for %s=%s", f.requests, name, value)
	}
	if len(f.records[name]) != 0 {
		t.Fatalf("DNS webhook still has TXT records for %s after cleanup: %#v", name, f.records[name])
	}
}

func (f *servedDNSWebhookFixture) assertNeverRequested(t *testing.T, name string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	name = strings.TrimSuffix(name, ".")
	for _, req := range f.requests {
		if strings.TrimSuffix(req.Name, ".") == name {
			t.Fatalf("DNS webhook touched %s despite delegation isolation: %+v", name, f.requests)
		}
	}
}

func startServedOutboxPump(t *testing.T, srv *Server) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				srv.dispatchOnce(ctx)
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

func startServedDirectOutboxPump(t *testing.T, srv *Server) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _ = srv.outbox.Dispatch(ctx, srv.obHandler)
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

func servedOutboxRowsByDestination(t *testing.T, h *servedHarness, prefix string) map[string]int {
	t.Helper()
	out := map[string]int{}
	if err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(),
			`SELECT destination, status, count(*)
			   FROM outbox
			  WHERE tenant_id = $1 AND destination LIKE $2
			  GROUP BY destination, status`, h.tenant, prefix+"%")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var destination, status string
			var count int
			if err := rows.Scan(&destination, &status, &count); err != nil {
				return err
			}
			out[destination+":"+status] = count
		}
		return rows.Err()
	}); err != nil {
		t.Fatalf("query outbox rows: %v", err)
	}
	return out
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
	certID, err := certinfo.ARICertID(leafDER)
	if err != nil {
		t.Fatalf("derive served ACME ARI identifier: %v", err)
	}
	postureToken := seedScopedToken(t, h.store, h.tenant, "lifecycle:read")
	posture := ariPostureForTenant(t, h, postureToken)
	var published ariPostureItem
	for _, item := range posture.Items {
		if item.ARICertificateID == certID {
			published = item
			break
		}
	}
	expectedWindow := ari.SuggestWindow(info.NotBefore, info.NotAfter, time.Now().UTC(), false)
	if published.CertificateID == "" ||
		published.CertificateStatus != "active" ||
		published.PublicationStatus != "published" ||
		!published.SuggestedWindow.Start.Equal(expectedWindow.Start) ||
		!published.SuggestedWindow.End.Equal(expectedWindow.End) {
		t.Fatalf("served ACME certificate missing from actual ARI publication posture: cert_id=%q item=%+v expected_window=%+v raw=%s",
			certID, published, expectedWindow, posture.Raw)
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
	posture = ariPostureForTenant(t, h, postureToken)
	published = ariPostureItem{}
	for _, item := range posture.Items {
		if item.ARICertificateID == certID {
			published = item
			break
		}
	}
	if published.CertificateID == "" ||
		published.CertificateStatus != "revoked" ||
		published.PublicationStatus != "published" ||
		!published.SuggestedWindow.Start.Equal(expectedWindow.Start) ||
		!published.SuggestedWindow.End.Equal(expectedWindow.End) {
		t.Fatalf("revoked certificate diverged from live ARI publication truth: cert_id=%q item=%+v raw=%s",
			certID, published, posture.Raw)
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

// TestServedACMEExternalAccountBindingCAPISS04 proves CAP-ISS-04 on the assembled
// served path: when ACME EAB is configured, /directory advertises the requirement,
// new-account rejects a bad EAB MAC, and a stock x/crypto/acme client registers with
// the configured external account binding.
func TestServedACMEExternalAccountBindingCAPISS04(t *testing.T) {
	hmacKey := bytes.Repeat([]byte{0x42}, 32)
	h := newServedHarness(t, config.Protocols{
		ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		ACMEEAB: config.ACMEExternalAccountBinding{
			Required: true,
			Keys: []config.ACMEExternalAccountBindingKey{
				{KeyID: "customer-issuer-01", HMACKey: hmacKey},
			},
		},
	})

	ctx := context.Background()
	client, err := acmekey.NewClient(h.ts.URL + "/directory")
	if err != nil {
		t.Fatalf("acme client: %v", err)
	}
	dir, err := client.Discover(ctx)
	if err != nil {
		t.Fatalf("discover served ACME directory: %v", err)
	}
	if !dir.ExternalAccountRequired {
		t.Fatal("served ACME directory does not advertise externalAccountRequired")
	}

	_, err = client.Register(ctx, &xacme.Account{ExternalAccountBinding: &xacme.ExternalAccountBinding{
		KID: "customer-issuer-01",
		Key: bytes.Repeat([]byte{0x24}, 32),
	}}, xacme.AcceptTOS)
	if err == nil {
		t.Fatal("served ACME accepted an externalAccountBinding signed with the wrong HMAC key")
	}

	client, err = acmekey.NewClient(h.ts.URL + "/directory")
	if err != nil {
		t.Fatalf("second acme client: %v", err)
	}
	acct, err := client.Register(ctx, &xacme.Account{ExternalAccountBinding: &xacme.ExternalAccountBinding{
		KID: "customer-issuer-01",
		Key: hmacKey,
	}}, xacme.AcceptTOS)
	if err != nil {
		t.Fatalf("served ACME rejected a valid externalAccountBinding: %v", err)
	}
	if acct.URI == "" {
		t.Fatal("valid EAB registration returned no account URI")
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
