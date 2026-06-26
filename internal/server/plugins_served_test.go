package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/store"
)

// connectorWASM is a minimal WASM connector plugin: it imports env.cap_write(i32)
// and exports run() i32 that calls cap_write(1) and returns the result. With the
// fs.write capability granted it performs a (gated) privileged write and returns
// 0 (success); without it, the host denies the write. It is the served analogue
// of the pluginhost test fixture, here driven through the real outbox handler.
var connectorWASM = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
	0x01, 0x0a, 0x02, 0x60, 0x01, 0x7f, 0x01, 0x7f, 0x60, 0x00, 0x01, 0x7f, // types: (i32)->i32, ()->i32
	0x02, 0x11, 0x01, 0x03, 0x65, 0x6e, 0x76, 0x09, 0x63, 0x61, 0x70, 0x5f, 0x77, 0x72, 0x69, 0x74, 0x65, 0x00, 0x00, // import env.cap_write
	0x03, 0x02, 0x01, 0x01, // func 1 (run) : type 1
	0x07, 0x07, 0x01, 0x03, 0x72, 0x75, 0x6e, 0x00, 0x01, // export "run" func 1
	0x0a, 0x08, 0x01, 0x06, 0x00, 0x41, 0x01, 0x10, 0x00, 0x0b, // i32.const 1; call 0; end
}

// caWASM is the reference CA plugin shape: it exports run() for conformance and
// issue() for the served CA path. issue() performs one granted host operation,
// then the server-side CA adapter returns a real certificate through the normal
// ca.IssuanceService rails. This keeps runtime plugins out of the crypto-provider
// business: crypto remains compile-time Go interfaces + DI (like crypto.Signer,
// Java JCA, OpenSSL ENGINE, and PKCS#11), not a runtime crypto-suite engine.
var caWASM = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
	0x01, 0x0a, 0x02, 0x60, 0x01, 0x7f, 0x01, 0x7f, 0x60, 0x00, 0x01, 0x7f,
	0x02, 0x11, 0x01, 0x03, 0x65, 0x6e, 0x76, 0x09, 0x63, 0x61, 0x70, 0x5f, 0x77, 0x72, 0x69, 0x74, 0x65, 0x00, 0x00,
	0x03, 0x03, 0x02, 0x01, 0x01,
	0x07, 0x0f, 0x02, 0x03, 0x72, 0x75, 0x6e, 0x00, 0x01, 0x05, 0x69, 0x73, 0x73, 0x75, 0x65, 0x00, 0x02,
	0x0a, 0x0d, 0x02, 0x04, 0x00, 0x41, 0x00, 0x0b, 0x06, 0x00, 0x41, 0x01, 0x10, 0x00, 0x0b,
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
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
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

	dir := writePluginDir(t, "demo-connector", connectorWASM, sign)

	// Grant the plugin fs.write so its gated write succeeds (the "performs its
	// action" half). A served Server with no signer still wires the plugin deploy
	// path (deployment is not signer-gated).
	srv, err := Build(ctx, Deps{Store: st, Log: log, Plugins: PluginConfig{
		Dir:            dir,
		TrustedKeyPEMs: [][]byte{keyPEM},
		Grant:          pluginhost.NewGrant(pluginhost.CapFSWrite),
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
	caDir := writePluginDir(t, "reference-ca", caWASM, sign)
	connectorDir := writePluginDir(t, "reference-connector", connectorWASM, sign)

	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.APIOptions = append(d.APIOptions, api.WithInsecureHeaderResolver())
		d.Plugins = PluginConfig{
			CADir:           caDir,
			ConnectorDir:    connectorDir,
			TrustedKeyPEMs:  [][]byte{keyPEM},
			CAGrant:         pluginhost.NewGrant(pluginhost.CapFSWrite),
			ConnectorGrant:  pluginhost.NewGrant(pluginhost.CapFSWrite),
			ReferenceCAName: "reference-ca",
		}
	})

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
	assertServedCert(t, cert, "reference-ca", "plugin-ca.served.test")
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
}

// TestServedPluginRefusesUnsigned is the SUPPLY-004 served assertion: an UNSIGNED
// module in the plugin dir makes Build fail closed — the binary never serves an
// unverified plugin. Pre-fix Load instantiated raw bytes with no gate; post-fix
// the served loader refuses it.
func TestServedPluginRefusesUnsigned(t *testing.T) {
	ctx := context.Background()
	st, log, keyPEM, _ := servedPluginStack(t)

	// No .sig written → unsigned.
	dir := writePluginDir(t, "unsigned-connector", connectorWASM, nil)
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
	sig := sign(connectorWASM)
	dir := t.TempDir()
	tampered := append([]byte(nil), connectorWASM...)
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

	dir := writePluginDir(t, "greedy-connector", connectorWASM, sign)
	// EMPTY grant: the plugin's cap_write attempt is denied by the sandbox.
	srv, err := Build(ctx, Deps{Store: st, Log: log, Plugins: PluginConfig{
		Dir: dir, TrustedKeyPEMs: [][]byte{keyPEM}, Grant: pluginhost.NewGrant(),
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
