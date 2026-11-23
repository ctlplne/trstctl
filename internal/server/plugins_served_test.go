// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/eventstest"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	capkg "trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/pluginhost/wasmgen"
	"trstctl.com/trstctl/internal/store"
)

// pluginWriteTarget is the path every WASM fixture below writes to, relative to
// the prefix the served grant hands it. The capability ABI carries a real path
// now, so a fixture has to name one and the grant has to cover it.
const pluginWriteTarget = "deployed.txt"

// pluginGrantDir is a per-test directory granted to the plugin, and the grant that
// permits writing inside it. Served plugins are sandboxed by an os.Root opened at
// this prefix, so an fs.write capability without a prefix is refused outright.
func pluginGrantDir(t *testing.T) (string, pluginhost.Grant) {
	t.Helper()
	dir := t.TempDir()
	return dir, pluginhost.NewGrant(pluginhost.CapFSWrite).
		WithPathPrefix(pluginhost.CapFSWrite, dir)
}

// connectorWASM is a minimal WASM connector plugin: it imports env.cap_write and
// exports run() i32 that writes one file inside the granted prefix and returns the
// status. With a grant covering that prefix it returns 0 (success); with a grant
// that does not cover it, the host denies the write. It is the served analog of
// the pluginhost test fixture, here driven through the real outbox handler.
func connectorWASMFor(dir string) []byte {
	return wasmgen.WriteGuest(filepath.Join(dir, pluginWriteTarget), "deployed", "run")
}

// caWASM is the reference CA plugin shape: it exports run() for conformance and
// issue() for the served CA path. issue() performs one granted host operation,
// then the server-side CA adapter returns a real certificate through the normal
// ca.IssuanceService rails. This keeps runtime plugins out of the crypto-provider
// business: crypto remains compile-time Go interfaces + DI (like crypto.Signer,
// Java JCA, OpenSSL ENGINE, and PKCS#11), not a runtime crypto-suite engine.
func caWASMFor(dir string) []byte {
	return wasmgen.Module("cap_write", 4,
		[]byte(filepath.Join(dir, "issued.pem")+"issued"),
		[]wasmgen.Export{
			// run() performs no privileged call, so the plugin stays conformant at
			// zero capabilities; issue() does the one granted host operation.
			{Name: "run", Const: 0},
			{Name: "issue", Args: wasmgen.WriteArgs(filepath.Join(dir, "issued.pem"), "issued")},
		})
}

// writePluginDir writes name.wasm and, when sign != nil, a detached name.wasm.sig
// into a fresh temp dir, returning the dir.
func writePluginDir(t *testing.T, name string, wasm []byte, sign func([]byte) []byte) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name+".wasm"), wasm, 0o600); err != nil {
		t.Fatal(err)
	}
	if sign != nil {
		if err := os.WriteFile(filepath.Join(dir, name+".wasm.sig"), sign(wasm), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// servedPluginStack stands up the embedded store + event log and returns them
// plus a trusted-key PEM and its signer, for the served plugin tests.
func servedPluginStack(t *testing.T) (*store.Store, *events.Log, []byte, func([]byte) []byte) {
	t.Helper()
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := eventstest.OpenFixture(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	pubDER, sign, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return st, log, crypto.MarshalPublicKeyPEM(pubDER), sign
}

// replayHasEvent reports whether an event of the given type for the tenant exists
// in the log (AN-2 assertion).
func replayHasEvent(t *testing.T, log *events.Log, tenantID, eventType string) bool {
	t.Helper()
	found := false
	if err := log.Replay(context.Background(), 0, func(e events.Event) error {
		if e.Type == eventType && e.TenantID == tenantID {
			found = true
		}
		return nil
	}); err != nil {
		t.Fatalf("replay events: %v", err)
	}
	return found
}

// TestServedPluginDeployEndToEnd is the EXC-WIRE-05 / ARCH-007 acceptance proof:
// a SIGNED WASM connector plugin, dropped in the configured plugin dir, is loaded
// + provenance-verified by server.Build (the same composition cmd/trstctl runs),
// and a SERVED connector.deploy outbox entry is pushed THROUGH the plugin's
// capability sandbox by the running dispatcher — performing its (granted)
// privileged action and recording a tenant-scoped connector.plugin_deployed event
// (AN-1/AN-2). Pre-fix the deploy was acknowledged unrouted (no plugin path
// existed); post-fix it runs the plugin.
func TestServedPluginDeployEndToEnd(t *testing.T) {
	ctx := context.Background()
	st, log, keyPEM, sign := servedPluginStack(t)

	workdir, grant := pluginGrantDir(t)
	dir := writePluginDir(t, "demo-connector", connectorWASMFor(workdir), sign)

	// Grant the plugin fs.write UNDER workdir so its gated write succeeds (the
	// "performs its action" half). The prefix is required: the sandbox contains
	// filesystem I/O inside an os.Root opened at it, so a capability with no prefix
	// has nothing to contain and is refused. A served Server with no signer still
	// wires the plugin deploy path (deployment is not signer-gated).
	srv, err := Build(ctx, Deps{Store: st, Log: log, Plugins: PluginConfig{
		Dir:            dir,
		TrustedKeyPEMs: [][]byte{keyPEM},
		Grant:          grant,
	}})
	if err != nil {
		t.Fatalf("Build with a signed plugin must succeed: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	if srv.plugins == nil || !srv.plugins.Has("demo-connector") {
		t.Fatal("the signed plugin was not loaded into the served plugin surface (ARCH-007 not wired)")
	}

	const tenantID = "22222222-2222-2222-2222-222222222222"
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "plugin-e2e"}); err != nil {
		t.Fatalf("UpsertTenant: %v", err)
	}
	payload, err := connector.EncodeDeploy("demo-connector", connector.NewDeployment("unit://target", []byte("cert"), []byte("key")))
	if err != nil {
		t.Fatal(err)
	}
	// Enqueue the connector.deploy exactly as an issued->deployed transition would
	// (AN-6), in the tenant's RLS context.
	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, e := srv.outbox.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID: tenantID, Destination: "connector.deploy",
			IdempotencyKey: "plugin-deploy-1", Payload: payload,
		})
		return e
	}); err != nil {
		t.Fatalf("enqueue connector.deploy: %v", err)
	}

	// Drive the dispatcher until the row is delivered (it runs on the outbox pool).
	deadline := time.After(10 * time.Second)
	for !replayHasEvent(t, log, tenantID, "connector.plugin_deployed") {
		srv.dispatchOnce(ctx)
		select {
		case <-time.After(50 * time.Millisecond):
		case <-deadline:
			t.Fatal("served connector.deploy never ran the plugin (no connector.plugin_deployed event); ARCH-007 deploy seam not wired")
		}
	}

	// AN-5: a redelivery with the same idempotency key must NOT re-run the plugin —
	// dispatching again leaves the row delivered and produces no second deploy. The
	// presence of exactly the recorded outcome is enough here; the idempotency store
	// dedupes on "deploy:"+key.
	if replayHasEvent(t, log, tenantID, "connector.plugin_failed") {
		t.Error("the served plugin deploy recorded a failure; the granted write should succeed")
	}
}

// TestServedReferenceWASMCAAndConnectorPluginsIssueAndDeploy is the PLUGIN-01
// acceptance proof: the running served binary admits signed reference WASM
// plugins from the separate CA and connector plugin trees, then uses them through
// the customer-facing served paths. The CA plugin is reached through
// /api/v1/external-cas/{id}/issue; the connector plugin is reached through the
// connector.deploy outbox dispatcher. Pre-fix, only a generic connector directory
// exists and no WASM-backed CA can be registered, so this test fails before the
// implementation.
func TestServedReferenceWASMCAAndConnectorPluginsIssueAndDeploy(t *testing.T) {
	ctx := context.Background()
	_, _, keyPEM, sign := servedPluginStack(t)
	workdir, grant := pluginGrantDir(t)
	caDir := writePluginDir(t, "reference-ca", caWASMFor(workdir), sign)
	connectorDir := writePluginDir(t, "reference-connector", connectorWASMFor(workdir), sign)

	var restart Deps
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.APIOptions = append(d.APIOptions, api.WithInsecureHeaderResolver())
		restart = *d
	})
	operator := seedServedAPIToken(t, ctx, h.store, h.tenant, "plugin-ca-operator", []string{"issuers:write", "issuers:read", "certs:issue"})
	approver := seedServedAPIToken(t, ctx, h.store, h.tenant, "plugin-ca-approver", []string{"issuers:write", "issuers:read"})
	spec := map[string]any{
		"common_name": "plugin tenant authority", "max_path_len": 1,
		"ttl_seconds":           int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"served.test"},
		"extended_key_usages":   []string{"serverAuth"}, "signature_algorithm": "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h, operator, "create_root", "", spec, 1, "plugin-ca-ceremony")
	approveCACeremony(t, h, approver, ceremony.ID, 1, "plugin-ca-approval")
	authority := createRootCA(t, h, operator, ceremony.ID, spec, "plugin-ca-root")
	restart.Plugins = PluginConfig{
		CADir:          caDir,
		ConnectorDir:   connectorDir,
		TrustedKeyPEMs: [][]byte{keyPEM},
		CAGrant:        grant,
		CABindings: map[string]config.PluginCABinding{
			"reference-ca": {TenantID: servedTestTenant, AuthorityID: authority.ID, DNSSuffixes: []string{"served.test"}},
		},
		ConnectorGrant:  grant,
		ReferenceCAName: "reference-ca",
	}
	pluginServer, err := Build(ctx, restart)
	if err != nil {
		t.Fatalf("restart with tenant-bound managed CA plugin: %v", err)
	}
	cleanupServedServer(t, pluginServer)
	h.srv = pluginServer
	h.ts = httptest.NewServer(pluginServer.Handler())
	t.Cleanup(h.ts.Close)

	var listed struct {
		Items []externalCAListItem `json:"items"`
	}
	code, body := doExternalCARequest(t, h, "GET", "/api/v1/external-cas", "", nil)
	if code != 200 {
		t.Fatalf("list plugin external CAs = %d, want 200; body=%s", code, body)
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatalf("decode plugin CA list: %v body=%s", err, body)
	}
	if !hasExternalCA(listed.Items, "reference-ca", "wasm-ca") {
		t.Fatalf("plugin CA registry items = %+v, want signed reference-ca", listed.Items)
	}

	cert := issueExternalCA(t, h, "reference-ca", "plugin-ca.served.test", "plugin-01-ca")
	assertServedCert(t, cert, authority.ID, "plugin-ca.served.test")
	_, rest := pem.Decode([]byte(cert.CertificatePEM))
	issuerBlock, _ := pem.Decode(rest)
	managedIssuer, _ := pem.Decode([]byte(authority.CertificatePEM))
	if issuerBlock == nil || managedIssuer == nil || !bytes.Equal(issuerBlock.Bytes, managedIssuer.Bytes) {
		t.Fatal("WASM CA leaf did not chain to its exact signer-held managed authority")
	}
	const neighbor = "9a140000-0000-4000-8000-000000000014"
	registerServedTenantID(t, h, neighbor, "WASM CA neighbour")
	if code, body := pluginCARequestAsTenant(t, h, neighbor, http.MethodGet,
		"/api/v1/external-cas", "", nil); code != http.StatusOK || bytes.Contains(body, []byte("reference-ca")) {
		t.Fatalf("neighbour saw tenant-bound plugin CA: status=%d body=%s", code, body)
	}
	if code, body := pluginCARequestAsTenant(t, h, neighbor, http.MethodPost,
		"/api/v1/external-cas/reference-ca/issue", "plugin-neighbour-issue",
		externalCAIssueRequestBody(t, "plugin-ca.served.test")); code != http.StatusNotFound {
		t.Fatalf("neighbour issued through tenant-bound plugin CA: status=%d body=%s", code, body)
	}
	if code, body := doExternalCARequest(t, h, http.MethodPost,
		"/api/v1/external-cas/reference-ca/issue", "plugin-outside-name",
		externalCAIssueRequestBody(t, "payments.other.test")); code == http.StatusCreated {
		t.Fatalf("plugin signed outside its deployment-owned DNS namespace: %s", body)
	}
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "plugin-ca.served.test", DNSNames: []string{"plugin-ca.served.test"},
		URIs: []string{"spiffe://neighbor.test/ns/payments/sa/api"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.plugins.caAdapters["reference-ca"].Issue(ctx, capkg.IssueRequest{
		TenantID: h.tenant, CSR: csr, DNSNames: []string{"plugin-ca.served.test"}, TTL: time.Hour,
	}); err == nil {
		t.Fatal("plugin CA signed a neighboring SPIFFE URI beside an allowed DNS name")
	}
	if !replayHasEvent(t, h.log, h.tenant, "ca.plugin_issued") {
		t.Fatal("the signed reference CA plugin issued without ca.plugin_issued evidence on the served log")
	}
	if got := externalCAOutboxCount(t, h, "plugin-01-ca:external-ca:reference-ca"); got != 1 {
		t.Fatalf("plugin CA ca.issue outbox rows = %d, want 1", got)
	}

	payload, err := connector.EncodeDeploy("reference-connector", connector.NewDeployment("unit://plugin-target", []byte(cert.CertificatePEM), []byte("key")))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, e := h.srv.outbox.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID: h.tenant, Destination: "connector.deploy",
			IdempotencyKey: "plugin-01-deploy", Payload: payload,
		})
		return e
	}); err != nil {
		t.Fatalf("enqueue reference connector deploy: %v", err)
	}
	deadline := time.After(10 * time.Second)
	for !replayHasEvent(t, h.log, h.tenant, "connector.plugin_deployed") {
		h.srv.dispatchOnce(ctx)
		select {
		case <-time.After(50 * time.Millisecond):
		case <-deadline:
			t.Fatal("served connector.deploy never ran signed reference connector plugin")
		}
	}
	leaf, err := certinfo.Inspect([]byte(cert.CertificatePEM))
	if err != nil {
		t.Fatal(err)
	}
	inventoried, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, leaf.SHA256Fingerprint)
	if err != nil {
		t.Fatalf("plugin leaf is absent from inventory: %v", err)
	}
	dispatcher := h.srv.obHandler.(*issuanceDispatcher)
	origins, err := dispatcher.certificateRevocationOrigins(ctx, h.tenant, []store.Certificate{inventoried})
	if err != nil || origins[leaf.SHA256Fingerprint] != (certificateRevocationOrigin{CAID: authority.ID}) {
		t.Fatalf("plugin leaf revocation resolved a different issuer: %+v, %v", origins, err)
	}
	historical := *dispatcher
	historical.externalCAs = nil // module removed after issuance; retained CA proof still revokes the old leaf
	origins, err = historical.certificateRevocationOrigins(ctx, h.tenant, []store.Certificate{inventoried})
	if err != nil || origins[leaf.SHA256Fingerprint] != (certificateRevocationOrigin{CAID: authority.ID}) {
		t.Fatalf("plugin removal changed the retained leaf's revocation CA: %+v, %v", origins, err)
	}
	code, body = pluginCARequestAsTenant(t, h, h.tenant, http.MethodPost,
		"/api/v1/certificates/bulk-revoke", "plugin-ca-revoke",
		map[string]any{"certificate_ids": []string{inventoried.ID}, "reason": "keyCompromise"})
	if code != http.StatusOK || !bytes.Contains(body, []byte(`"total_revoked":1`)) {
		t.Fatalf("plugin leaf exact-authority revoke = HTTP %d %s", code, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("publish plugin CA revocation: %v", err)
	}
	response, err := http.Get(h.ts.URL + "/crl/" + h.tenant + "/authorities/" + authority.ID)
	if err != nil {
		t.Fatal(err)
	}
	crlDER, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("plugin CA CRL = HTTP %d read %v", response.StatusCode, readErr)
	}
	managedIssuer, _ = pem.Decode([]byte(authority.CertificatePEM))
	crl, err := crypto.ParseCRL(crlDER, managedIssuer.Bytes)
	if err != nil || !protoContains(crl.RevokedSerials, cert.Serial) {
		t.Fatalf("plugin CA CRL omitted exact serial %s: %+v, %v", cert.Serial, crl, err)
	}
}

func pluginCARequestAsTenant(t *testing.T, h *servedHarness, tenantID, method, path, idem string, body any) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, h.ts.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set("X-Roles", "admin")
	req.Header.Set("X-Subject", "plugin-neighbour-admin")
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, raw
}

// TestServedPluginRefusesUnsigned is the SUPPLY-004 served assertion: an UNSIGNED
// module in the plugin dir makes Build fail closed — the binary never serves an
// unverified plugin. Pre-fix Load instantiated raw bytes with no gate; post-fix
// the served loader refuses it.
func TestServedPluginRefusesUnsigned(t *testing.T) {
	ctx := context.Background()
	st, log, keyPEM, _ := servedPluginStack(t)

	// No .sig written → unsigned.
	dir := writePluginDir(t, "unsigned-connector", connectorWASMFor(t.TempDir()), nil)
	_, err := Build(ctx, Deps{Store: st, Log: log, Plugins: PluginConfig{
		Dir: dir, TrustedKeyPEMs: [][]byte{keyPEM}, Grant: pluginhost.NewGrant(),
	}})
	if err == nil {
		t.Fatal("Build admitted an UNSIGNED plugin; it must fail closed (SUPPLY-004)")
	}
}

// TestServedPluginRefusesTampered is the SUPPLY-004 served tamper assertion: a
// module whose bytes were changed after signing no longer verifies and Build
// fails closed.
func TestServedPluginRefusesTampered(t *testing.T) {
	ctx := context.Background()
	st, log, keyPEM, sign := servedPluginStack(t)

	// Sign the original, then write a tampered module under the same name so the
	// detached signature no longer matches the bytes on disk.
	original := connectorWASMFor(t.TempDir())
	sig := sign(original)
	dir := t.TempDir()
	tampered := append([]byte(nil), original...)
	tampered[len(tampered)-2] ^= 0xFF // flip the i32.const operand
	if err := os.WriteFile(filepath.Join(dir, "tampered-connector.wasm"), tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tampered-connector.wasm.sig"), sig, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Build(ctx, Deps{Store: st, Log: log, Plugins: PluginConfig{
		Dir: dir, TrustedKeyPEMs: [][]byte{keyPEM}, Grant: pluginhost.NewGrant(),
	}})
	if err == nil {
		t.Fatal("Build admitted a BYTE-TAMPERED plugin; it must fail closed (SUPPLY-004)")
	}
}

// TestServedPluginOutOfGrantDeployFails is the capability-sandbox assertion: a
// plugin that attempts a privileged operation outside its grant fails the deploy
// (it is denied at runtime and the deploy reports failure, not success).
func TestServedPluginOutOfGrantDeployFails(t *testing.T) {
	ctx := context.Background()
	st, log, keyPEM, sign := servedPluginStack(t)

	// The plugin writes under wantsDir; the grant covers grantedDir instead. The
	// capability IS held, so the module instantiates and runs — and is then denied
	// on the resource, which is the runtime half of the sandbox. (A plugin denied
	// the capability outright cannot instantiate at all; that is
	// TestUngrantedImportFailsToInstantiate in internal/pluginhost.)
	wantsDir := t.TempDir()
	grantedDir := t.TempDir()
	dir := writePluginDir(t, "greedy-connector", connectorWASMFor(wantsDir), sign)
	srv, err := Build(ctx, Deps{Store: st, Log: log, Plugins: PluginConfig{
		Dir: dir, TrustedKeyPEMs: [][]byte{keyPEM},
		Grant: pluginhost.NewGrant(pluginhost.CapFSWrite).
			WithPathPrefix(pluginhost.CapFSWrite, grantedDir),
	}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	const tenantID = "33333333-3333-3333-3333-333333333333"
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "plugin-grant"}); err != nil {
		t.Fatal(err)
	}
	payload, _ := connector.EncodeDeploy("greedy-connector", connector.NewDeployment("unit://t", []byte("c"), []byte("k")))
	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, e := srv.outbox.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID: tenantID, Destination: "connector.deploy",
			IdempotencyKey: "greedy-1", Payload: payload,
		})
		return e
	}); err != nil {
		t.Fatal(err)
	}

	// The deploy must record a DENIAL, not a success, and the outbox row must remain
	// pending (the handler returned an error, so it was not marked delivered).
	deadline := time.After(10 * time.Second)
	for !replayHasEvent(t, log, tenantID, "connector.plugin_denied") {
		srv.dispatchOnce(ctx)
		select {
		case <-time.After(50 * time.Millisecond):
		case <-deadline:
			t.Fatal("an out-of-grant plugin deploy did not record a denial; the capability sandbox is not enforced on the served path")
		}
	}
	if replayHasEvent(t, log, tenantID, "connector.plugin_deployed") {
		t.Error("an out-of-grant plugin reported a successful deploy; it must be denied (capability sandbox)")
	}
}

// TestServedDNSProviderPluginRequiresDNSContract proves F70 admission fails closed
// for a signed module that has provenance but does not export the DNS provider
// present/cleanup contract. The server must not advertise or activate a plugin on
// signature alone.
func TestServedDNSProviderPluginRequiresDNSContract(t *testing.T) {
	ctx := context.Background()
	st, log, keyPEM, sign := servedPluginStack(t)

	workdir, grant := pluginGrantDir(t)
	dir := writePluginDir(t, "not-dns", connectorWASMFor(workdir), sign)
	_, err := Build(ctx, Deps{Store: st, Log: log, Plugins: PluginConfig{
		DNSDir:         dir,
		TrustedKeyPEMs: [][]byte{keyPEM},
		Grant:          grant,
	}})
	if err == nil {
		t.Fatal("Build admitted a signed plugin that does not implement the DNS provider present/cleanup contract")
	}
}
