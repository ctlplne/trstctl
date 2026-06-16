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

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/pluginhost"
)

// pluginEntrypoints are the exported function names a connector plugin may use,
// tried in order. A plugin exports one of them; the host invokes the first it
// finds. (The conformance contract requires `run`; `deploy` is the connector-
// semantic alias.)
var pluginEntrypoints = []string{"deploy", "run"}

// PluginManager is the served WASM-plugin surface (ARCH-007): it loads operator-
// supplied connector plugins from a directory, each only after its provenance is
// verified against the trust policy (SUPPLY-004), and runs them capability-
// sandboxed on the plugin host's bounded pool (AN-7). It holds NO database pool
// and NO signer handle — a plugin fault is contained to its own wazero runtime
// (the containment the host guarantees). It is wired into the served outbox
// handler so a served `connector.deploy` whose connector names a loaded plugin is
// pushed through the sandbox instead of being acknowledged unrouted.
//
// Tenancy (AN-1): the manager itself is shared infrastructure (a plugin is code,
// not data), but every deploy it runs is invoked under the message's tenant and
// emits a tenant-scoped event (AN-2). Plugins never touch the store directly, so
// no cross-tenant data path is opened.
type PluginManager struct {
	host    *pluginhost.Host
	trust   *pluginhost.TrustPolicy
	log     *events.Log
	grant   pluginhost.Grant
	mu      sync.RWMutex
	plugins map[string]*pluginhost.Plugin
}

// PluginConfig configures the served plugin surface. It is fail-closed: enabling
// plugins without a directory or a usable trust policy is an error, so the binary
// never serves an unverified plugin path.
type PluginConfig struct {
	// Dir is the directory scanned for `<name>.wasm` + detached `<name>.wasm.sig`
	// pairs. Required when plugins are enabled.
	Dir string
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
	if cfg.Dir == "" && len(cfg.TrustedKeyPEMs) == 0 {
		return nil, nil // not configured: served plugin surface stays off
	}
	if cfg.Dir == "" {
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
	pm := &PluginManager{
		host:    pluginhost.New(opts...),
		trust:   trust,
		log:     log,
		grant:   cfg.Grant,
		plugins: map[string]*pluginhost.Plugin{},
	}
	if err := pm.loadDir(ctx, cfg.Dir); err != nil {
		_ = pm.host.Close(ctx)
		return nil, err
	}
	return pm, nil
}

// loadDir loads and verifies every signed module in dir. The set is sorted for a
// deterministic load order.
func (pm *PluginManager) loadDir(ctx context.Context, dir string) error {
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
		wasm, err := os.ReadFile(filepath.Join(dir, fname))
		if err != nil {
			return fmt.Errorf("server: read plugin %q: %w", name, err)
		}
		sig, err := os.ReadFile(filepath.Join(dir, fname+".sig"))
		if err != nil {
			// No detached signature alongside the module → refuse (fail closed):
			// the served path never instantiates an unsigned plugin.
			return fmt.Errorf("server: plugin %q has no detached signature (%s.sig); refusing (SUPPLY-004): %w", name, fname, err)
		}
		p, err := pm.host.LoadVerified(ctx, wasm, sig, pm.trust, pm.grant)
		if err != nil {
			return fmt.Errorf("server: plugin %q failed provenance verification: %w", name, err)
		}
		pm.plugins[name] = p
	}
	return nil
}

// Has reports whether a verified plugin is loaded under name.
func (pm *PluginManager) Has(name string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	_, ok := pm.plugins[name]
	return ok
}

// Deploy runs the connector plugin named by the deploy payload, capability-
// sandboxed, for the given tenant. It returns (handled=false) when no plugin owns
// the named connector, so the caller can fall through to the in-process connector
// path or the unrouted ack. On a handled deploy it invokes the plugin's
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
		pm.emit(ctx, tenantID, "connector.plugin_failed", payload, fmt.Sprintf("invoke: %v", invErr))
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
	pm.plugins = map[string]*pluginhost.Plugin{}
	return pm.host.Close(ctx)
}
