// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/bulkhead"
	capkg "trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/connector"
	cryptoca "trstctl.com/trstctl/internal/crypto/ca"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/pluginhost"
)

// pluginEntrypoints are the exported function names a connector plugin may use,
// tried in order. A plugin exports one of them; the host invokes the first it
// finds. (The conformance contract requires `run`; `deploy` is the connector-
// semantic alias.)
var pluginEntrypoints = []string{"deploy", "run"}

const (
	dnsPluginPresentEntrypoint = "present_txt"
	dnsPluginCleanupEntrypoint = "cleanup_txt"
)

// PluginManager is the served WASM-plugin surface (ARCH-007): it loads operator-
// supplied connector plugins from a directory, each only after its provenance is
// verified against the trust policy (SUPPLY-004), and runs them capability-
// sandboxed on the plugin host's bounded pool (AN-7). It holds NO database pool
// and NO signer handle — a plugin fault is contained to its own wazero runtime
// (the containment the host guarantees). It is wired into the served outbox
// handler so a served `connector.deploy` whose connector names a loaded plugin is
// pushed through the sandbox; missing or declining plugins leave the row pending.
//
// Tenancy (AN-1): the manager itself is shared infrastructure (a plugin is code,
// not data), but every deploy it runs is invoked under the message's tenant and
// emits a tenant-scoped event (AN-2). Plugins never touch the store directly, so
// no cross-tenant data path is opened.
type PluginManager struct {
	host           *pluginhost.Host
	trust          *pluginhost.TrustPolicy
	log            *events.Log
	connectorGrant pluginhost.Grant
	caGrant        pluginhost.Grant
	dnsGrant       pluginhost.Grant
	mu             sync.RWMutex
	plugins        map[string]*pluginhost.Plugin
	caPlugins      map[string]*pluginhost.Plugin
	dnsPlugins     map[string]*pluginhost.Plugin
	caAdapters     map[string]*wasmCA
	caAuthorities  map[string]*cryptoca.Authority
}

// PluginConfig configures the served plugin surface. It is fail-closed: enabling
// plugins without a directory or a usable trust policy is an error, so the binary
// never serves an unverified plugin path.
type PluginConfig struct {
	// Dir is the directory scanned for `<name>.wasm` + detached `<name>.wasm.sig`
	// pairs. It is the legacy connector-plugin directory; ConnectorDir takes
	// precedence when set.
	Dir string
	// CADir is scanned for signed CA plugins. Each `<name>.wasm` becomes an
	// ExternalCA entry with id `<name>` and type `wasm-ca`.
	CADir string
	// DNSDir is scanned for signed DNS-provider plugins. Each `<name>.wasm`
	// becomes a served ACME DNS-01 provider entry selectable by tenant configs.
	DNSDir string
	// ConnectorDir is scanned for signed deployment connector plugins. When empty,
	// Dir remains the compatibility alias.
	ConnectorDir string
	// TrustedKeyPEMs are the operator's Ed25519 public keys (PEM) that admit a
	// signed module (SUPPLY-004). At least one is required.
	TrustedKeyPEMs [][]byte
	// PinnedDigestsHex optionally restricts admitted modules to an exact-content
	// allowlist (lowercase-hex SHA-256 of the `.wasm`).
	PinnedDigestsHex []string
	// Grant is the capability grant every loaded connector plugin runs under. The
	// zero grant permits nothing (the plugin can still run pure compute but no
	// privileged host op) — operators widen it deliberately.
	Grant pluginhost.Grant
	// CAGrant overrides Grant for CA plugins.
	CAGrant pluginhost.Grant
	// DNSGrant overrides Grant for DNS-provider plugins.
	DNSGrant pluginhost.Grant
	// ConnectorGrant overrides Grant for connector plugins.
	ConnectorGrant pluginhost.Grant
	// ReferenceCAName optionally asserts that the named reference CA plugin loaded.
	// It is primarily used by the served acceptance harness and sample config.
	ReferenceCAName string
	// Pool is the bounded pool plugin invocations run on (AN-7); nil uses a modest
	// default inside the host.
	Pool *bulkhead.Pool
}

// NewPluginManager builds and populates a PluginManager from cfg: it constructs
// the trust policy (failing closed if no key is usable), then loads and verifies
// every `<name>.wasm` in Dir that has a sibling `<name>.wasm.sig`. A module whose
// signature does not verify (unsigned, wrong key, tampered, or not pinned) is
// REFUSED and the load fails — the served binary will not come up with an
// unverified plugin in its directory, so provenance can't be bypassed by dropping
// a file. Returns (nil, nil) — disabled — only when cfg is the zero value.
func NewPluginManager(ctx context.Context, cfg PluginConfig, log *events.Log) (*PluginManager, error) {
	connectorDir := strings.TrimSpace(cfg.ConnectorDir)
	if connectorDir == "" {
		connectorDir = strings.TrimSpace(cfg.Dir)
	}
	caDir := strings.TrimSpace(cfg.CADir)
	dnsDir := strings.TrimSpace(cfg.DNSDir)
	if connectorDir == "" && caDir == "" && dnsDir == "" && len(cfg.TrustedKeyPEMs) == 0 {
		return nil, nil // not configured: served plugin surface stays off
	}
	if connectorDir == "" && caDir == "" && dnsDir == "" {
		return nil, fmt.Errorf("server: plugins enabled but no plugin directory configured (fail closed)")
	}
	trust, err := pluginhost.NewTrustPolicy(cfg.TrustedKeyPEMs, cfg.PinnedDigestsHex)
	if err != nil {
		return nil, fmt.Errorf("server: plugin trust policy: %w", err)
	}
	var opts []pluginhost.Option
	if cfg.Pool != nil {
		opts = append(opts, pluginhost.WithPool(cfg.Pool))
	}
	connectorGrant := cfg.ConnectorGrant
	if connectorGrant.Empty() {
		connectorGrant = cfg.Grant
	}
	caGrant := cfg.CAGrant
	if caGrant.Empty() {
		caGrant = cfg.Grant
	}
	dnsGrant := cfg.DNSGrant
	if dnsGrant.Empty() {
		dnsGrant = cfg.Grant
	}
	pm := &PluginManager{
		host:           pluginhost.New(opts...),
		trust:          trust,
		log:            log,
		connectorGrant: connectorGrant,
		caGrant:        caGrant,
		dnsGrant:       dnsGrant,
		plugins:        map[string]*pluginhost.Plugin{},
		caPlugins:      map[string]*pluginhost.Plugin{},
		dnsPlugins:     map[string]*pluginhost.Plugin{},
		caAdapters:     map[string]*wasmCA{},
		caAuthorities:  map[string]*cryptoca.Authority{},
	}
	if connectorDir != "" {
		if err := pm.loadDir(ctx, connectorDir, connectorGrant, pm.addConnectorPlugin); err != nil {
			_ = pm.Close(ctx)
			return nil, err
		}
	}
	if caDir != "" {
		if err := pm.loadDir(ctx, caDir, caGrant, pm.addCAPlugin); err != nil {
			_ = pm.Close(ctx)
			return nil, err
		}
	}
	if dnsDir != "" {
		if err := pm.loadDir(ctx, dnsDir, dnsGrant, pm.addDNSPlugin); err != nil {
			_ = pm.Close(ctx)
			return nil, err
		}
	}
	if cfg.ReferenceCAName != "" && !pm.HasCA(cfg.ReferenceCAName) {
		_ = pm.Close(ctx)
		return nil, fmt.Errorf("server: reference CA plugin %q was not loaded", cfg.ReferenceCAName)
	}
	return pm, nil
}

// loadDir loads and verifies every signed module in dir. The set is sorted for a
// deterministic load order.
func (pm *PluginManager) loadDir(ctx context.Context, dir string, grant pluginhost.Grant, add func(context.Context, string, *pluginhost.Plugin) error) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("server: read plugin dir %q: %w", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".wasm") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, fname := range names {
		name := strings.TrimSuffix(fname, ".wasm")
		wasm, err := os.ReadFile(filepath.Join(dir, fname)) // #nosec G304 -- operator-configured plugin dir; WASM and signature are verified after the read (CWE-22)
		if err != nil {
			return fmt.Errorf("server: read plugin %q: %w", name, err)
		}
		sig, err := os.ReadFile(filepath.Join(dir, fname+".sig")) // #nosec G304 -- operator-configured plugin dir; WASM and signature are verified after the read (CWE-22)
		if err != nil {
			// No detached signature alongside the module → refuse (fail closed):
			// the served path never instantiates an unsigned plugin.
			return fmt.Errorf("server: plugin %q has no detached signature (%s.sig); refusing (SUPPLY-004): %w", name, fname, err)
		}
		p, err := pm.host.LoadVerified(ctx, wasm, sig, pm.trust, grant)
		if err != nil {
			return fmt.Errorf("server: plugin %q failed provenance verification: %w", name, err)
		}
		if err := add(ctx, name, p); err != nil {
			_ = p.Close(ctx)
			return err
		}
	}
	return nil
}

func (pm *PluginManager) addConnectorPlugin(_ context.Context, name string, p *pluginhost.Plugin) error {
	pm.plugins[name] = p
	return nil
}

func (pm *PluginManager) addCAPlugin(_ context.Context, name string, p *pluginhost.Plugin) error {
	if !p.HasExport("issue") {
		return fmt.Errorf("server: CA plugin %q has no exported issue() function", name)
	}
	authority, err := cryptoca.NewAuthority(name)
	if err != nil {
		return fmt.Errorf("server: create reference CA authority for plugin %q: %w", name, err)
	}
	pm.caPlugins[name] = p
	pm.caAuthorities[name] = authority
	pm.caAdapters[name] = &wasmCA{name: name, host: pm.host, plugin: p, authority: authority, log: pm.log}
	return nil
}

func (pm *PluginManager) addDNSPlugin(_ context.Context, name string, p *pluginhost.Plugin) error {
	for _, fn := range []string{"run", dnsPluginPresentEntrypoint, dnsPluginCleanupEntrypoint} {
		if !p.HasExport(fn) {
			return fmt.Errorf("server: DNS provider plugin %q has no exported %s() function", name, fn)
		}
	}
	pm.dnsPlugins[name] = p
	return nil
}

// Has reports whether a verified plugin is loaded under name.
func (pm *PluginManager) Has(name string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	_, ok := pm.plugins[name]
	return ok
}

// HasCA reports whether a verified CA plugin is loaded under name.
func (pm *PluginManager) HasCA(name string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	_, ok := pm.caAdapters[name]
	return ok
}

// HasDNS reports whether a verified DNS-provider plugin is loaded under name.
func (pm *PluginManager) HasDNS(name string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	_, ok := pm.dnsPlugins[name]
	return ok
}

// DNSPluginInfo is the operator-facing metadata for a loaded signed DNS provider
// plugin. It contains no tenant data and no credential material.
type DNSPluginInfo struct {
	Name         string
	Capabilities []string
}

// DNSPlugins returns loaded signed DNS-provider plugins in deterministic order.
func (pm *PluginManager) DNSPlugins() []DNSPluginInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	names := make([]string, 0, len(pm.dnsPlugins))
	for name := range pm.dnsPlugins {
		names = append(names, name)
	}
	sort.Strings(names)
	caps := grantCapabilityStrings(pm.dnsGrant)
	out := make([]DNSPluginInfo, 0, len(names))
	for _, name := range names {
		out = append(out, DNSPluginInfo{Name: name, Capabilities: caps})
	}
	return out
}

func (s *Server) acmeDNS01PluginCatalog() []api.ACMEDNS01ProviderCatalogItem {
	if s.plugins == nil {
		return nil
	}
	plugins := s.plugins.DNSPlugins()
	out := make([]api.ACMEDNS01ProviderCatalogItem, 0, len(plugins))
	for _, p := range plugins {
		out = append(out, api.ACMEDNS01ProviderCatalogItem{
			Name:                      p.Name,
			DisplayName:               p.Name,
			Kind:                      "plugin",
			Served:                    true,
			PropagationPreflight:      true,
			Conformance:               "signed-present-cleanup",
			AdmissionState:            "verified",
			Provenance:                "ed25519-signature-verified",
			CredentialReferenceFields: []string{"bearer_token_ref"},
			Capabilities:              p.Capabilities,
			ProviderPackage:           "signed-wasm:" + p.Name,
			Notes:                     "Signed DNS provider plugin admitted at startup and activated from the ACME DNS-01 outbox worker.",
		})
	}
	return out
}

// ExternalCAs returns loaded WASM CA plugins as served external-CA registry
// entries. The returned CA implementations still run through ca.IssuanceService,
// so idempotency (AN-5), outbox (AN-6), and profile checks stay centralized.
func (pm *PluginManager) ExternalCAs() []ExternalCA {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	names := make([]string, 0, len(pm.caAdapters))
	for name := range pm.caAdapters {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]ExternalCA, 0, len(names))
	for _, name := range names {
		out = append(out, ExternalCA{ID: name, Type: "wasm-ca", CA: pm.caAdapters[name]})
	}
	return out
}

type wasmCA struct {
	name      string
	host      *pluginhost.Host
	plugin    *pluginhost.Plugin
	authority *cryptoca.Authority
	log       *events.Log
}

var _ capkg.CA = (*wasmCA)(nil)

func (c *wasmCA) Name() string { return c.name }

// Issue invokes the signed WASM CA plugin's issue() entrypoint under its
// capability grant, then uses an in-boundary reference authority to produce a
// real certificate for the served external-CA API. The runtime plugin is not a
// crypto provider and cannot register/select algorithms; crypto-agility remains
// compile-time Go interfaces + dependency injection, the same prior-art shape as
// crypto.Signer, Java JCA, OpenSSL ENGINE, and PKCS#11.
func (c *wasmCA) Issue(ctx context.Context, req capkg.IssueRequest) (capkg.Certificate, error) {
	before := c.plugin.Stats()
	rc, err := c.host.Invoke(ctx, c.plugin, "issue")
	after := c.plugin.Stats()
	deniedDelta := after.Denied - before.Denied
	switch {
	case err != nil:
		c.emit(ctx, req.TenantID, "ca.plugin_failed", fmt.Sprintf("invoke: %v", err))
		return capkg.Certificate{}, fmt.Errorf("server: CA plugin %q issue: %w", c.name, err)
	case deniedDelta > 0:
		c.emit(ctx, req.TenantID, "ca.plugin_denied", fmt.Sprintf("plugin attempted %d operation(s) outside its capability grant", deniedDelta))
		return capkg.Certificate{}, fmt.Errorf("server: CA plugin %q attempted an operation outside its capability grant", c.name)
	case rc != 0:
		c.emit(ctx, req.TenantID, "ca.plugin_failed", fmt.Sprintf("plugin returned non-zero %d", rc))
		return capkg.Certificate{}, fmt.Errorf("server: CA plugin %q issue returned non-zero status %d", c.name, rc)
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = 90 * 24 * time.Hour
	}
	issued, err := c.authority.IssueFromCSR(req.CSR, ttl)
	if err != nil {
		c.emit(ctx, req.TenantID, "ca.plugin_failed", err.Error())
		return capkg.Certificate{}, err
	}
	c.emit(ctx, req.TenantID, "ca.plugin_issued", "")
	return capkg.Certificate{CertificatePEM: issued.CertificatePEM, Serial: issued.Serial, NotAfter: issued.NotAfter, Issuer: c.name}, nil
}

func (c *wasmCA) emit(ctx context.Context, tenantID, evType, detail string) {
	if c.log == nil {
		return
	}
	data, err := json.Marshal(struct {
		Plugin string `json:"plugin"`
		Detail string `json:"detail,omitempty"`
	}{Plugin: c.name, Detail: detail})
	if err != nil {
		return
	}
	_, _ = c.log.Append(ctx, events.Event{Type: evType, TenantID: tenantID, Data: data})
}

// Deploy runs the connector plugin named by the deploy payload, capability-
// sandboxed, for the given tenant. It returns (handled=false) when no plugin owns
// the named connector, so the caller can fall through to the in-process connector
// path or fail the row closed. On a handled deploy it invokes the plugin's
// entrypoint on the bounded pool (AN-7), treats a non-zero return OR any grant-
// denied privileged op as a deployment failure (so an out-of-grant plugin cannot
// silently "succeed"), and emits a tenant-scoped connector.deployed / .denied
// event (AN-2). The plugin never receives a store or signer handle.
func (pm *PluginManager) Deploy(ctx context.Context, tenantID string, payload connector.DeployPayload) (handled bool, err error) {
	pm.mu.RLock()
	p := pm.plugins[payload.Connector]
	pm.mu.RUnlock()
	if p == nil {
		return false, nil
	}
	before := p.Stats()
	rc, invErr := pm.host.Invoke(ctx, p, pm.entrypoint(p))
	after := p.Stats()
	deniedDelta := after.Denied - before.Denied

	switch {
	case invErr != nil:
		// A host/plugin error can include attacker-controlled text. Persist only a
		// closed diagnostic; return the original error to retry machinery below.
		pm.emit(ctx, tenantID, "connector.plugin_failed", payload, "invoke_failed")
		return true, fmt.Errorf("server: plugin %q deploy: %w", payload.Connector, invErr)
	case deniedDelta > 0:
		// The plugin attempted a privileged operation its grant forbids: the
		// capability sandbox denied it. Fail the deploy (do not report success).
		pm.emit(ctx, tenantID, "connector.plugin_denied", payload,
			fmt.Sprintf("plugin attempted %d operation(s) outside its capability grant", deniedDelta))
		return true, fmt.Errorf("server: plugin %q attempted an operation outside its capability grant", payload.Connector)
	case rc != 0:
		pm.emit(ctx, tenantID, "connector.plugin_failed", payload, fmt.Sprintf("plugin returned non-zero %d", rc))
		return true, fmt.Errorf("server: plugin %q deploy returned non-zero status %d", payload.Connector, rc)
	default:
		pm.emit(ctx, tenantID, "connector.plugin_deployed", payload, "")
		return true, nil
	}
}

// InvokeDNS runs one DNS-provider plugin action through the same provenance-loaded,
// capability-sandboxed, bounded WASM host as other served plugins. The caller owns
// the external DNS side effect and tenant audit event; this method is only the
// plugin activation gate.
func (pm *PluginManager) InvokeDNS(ctx context.Context, name, fn string) error {
	pm.mu.RLock()
	p := pm.dnsPlugins[name]
	pm.mu.RUnlock()
	if p == nil {
		return fmt.Errorf("server: DNS provider plugin %q is not loaded", name)
	}
	before := p.Stats()
	rc, invErr := pm.host.Invoke(ctx, p, fn)
	after := p.Stats()
	deniedDelta := after.Denied - before.Denied
	switch {
	case invErr != nil:
		return fmt.Errorf("server: DNS provider plugin %q %s: %w", name, fn, invErr)
	case deniedDelta > 0:
		return fmt.Errorf("server: DNS provider plugin %q attempted %d operation(s) outside its capability grant", name, deniedDelta)
	case rc != 0:
		return fmt.Errorf("server: DNS provider plugin %q %s returned non-zero status %d", name, fn, rc)
	default:
		return nil
	}
}

// entrypoint returns the first exported entrypoint name the plugin actually
// exports, defaulting to "run" (always present per the conformance contract).
func (pm *PluginManager) entrypoint(p *pluginhost.Plugin) string {
	for _, fn := range pluginEntrypoints {
		if p.HasExport(fn) {
			return fn
		}
	}
	return "run"
}

// emit records a tenant-scoped plugin-deploy outcome as an AN-2 event (best
// effort: a nil log is a no-op, and a log error does not change the deploy
// result, which is governed by the plugin's return / denials above).
func (pm *PluginManager) emit(ctx context.Context, tenantID, evType string, payload connector.DeployPayload, detail string) {
	if pm.log == nil {
		return
	}
	data, err := json.Marshal(struct {
		Connector   string `json:"connector"`
		Target      string `json:"target"`
		Fingerprint string `json:"fingerprint,omitempty"`
		Detail      string `json:"detail,omitempty"`
	}{payload.Connector, payload.Target, payload.Fingerprint, detail})
	if err != nil {
		return
	}
	_, _ = pm.log.Append(ctx, events.Event{Type: evType, TenantID: tenantID, Data: data})
}

// Close releases the plugin runtimes and the host pool.
func (pm *PluginManager) Close(ctx context.Context) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	for _, p := range pm.plugins {
		_ = p.Close(ctx)
	}
	for _, p := range pm.caPlugins {
		_ = p.Close(ctx)
	}
	for _, p := range pm.dnsPlugins {
		_ = p.Close(ctx)
	}
	for _, a := range pm.caAuthorities {
		a.Destroy()
	}
	pm.plugins = map[string]*pluginhost.Plugin{}
	pm.caPlugins = map[string]*pluginhost.Plugin{}
	pm.dnsPlugins = map[string]*pluginhost.Plugin{}
	pm.caAdapters = map[string]*wasmCA{}
	pm.caAuthorities = map[string]*cryptoca.Authority{}
	return pm.host.Close(ctx)
}

func grantCapabilityStrings(g pluginhost.Grant) []string {
	caps := g.Capabilities()
	out := make([]string, 0, len(caps))
	for _, cap := range caps {
		out = append(out, string(cap))
	}
	return out
}
