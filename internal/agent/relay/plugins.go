// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/plugincensus"
	"trstctl.com/trstctl/internal/pluginhost"
)

// Third-party connectors, executed inside the customer's network (epic E4).
//
// The WASM plugin host already existed and already had the properties that
// matter: modules are signature- and digest-verified before they load, they run
// under a declared capability grant, and an out-of-grant operation is denied at
// runtime rather than audited afterwards. What it did not have was a location.
//
// It ran on the control plane, which means a partner's code executed in the
// vendor's process against the customer's estate. Every guarantee held, and the
// arrangement still asked two organisations to accept something neither should
// have to: the customer, that a third party's module runs somewhere they cannot
// see; the vendor, that they execute partner code with reach into customer
// networks.
//
// Moving it here removes the question rather than answering it. The module runs
// on the relay, inside the segment it is deploying to, under the same sandbox
// contract — and the control plane never loads it at all.
//
// THE GUARANTEES DO NOT MOVE WITH IT AUTOMATICALLY. A relay that loaded modules
// without verifying them, or ran them under a wider grant because the relay
// "already has network access", would be a downgrade wearing the same name. The
// tests in plugins_test.go exist to hold each property in the new location
// rather than to assume it travelled.

// PluginRuntime is the relay's verified WASM connector host.
//
// It deliberately does NOT reuse server.PluginManager. That type carries an
// event log, emits tenant-scoped audit events and reaches the control plane's
// store — none of which exist here, and importing it would drag the control
// plane into the agent binary, which the import-boundary test refuses. What is
// shared is internal/pluginhost, which is where the actual guarantees live.
type PluginRuntime struct {
	host  *pluginhost.Host
	trust *pluginhost.TrustPolicy

	mu      sync.RWMutex
	plugins map[string]*pluginhost.Plugin
	grants  map[string]pluginhost.Grant
	census  map[string]plugincensus.Entry
}

// PluginConfig is what an operator gives the relay to run third-party connectors.
type PluginConfig struct {
	// Dir holds `<name>.wasm` modules, each with a sibling `<name>.wasm.sig`.
	Dir string
	// TrustedKeyPEMs are the publisher keys whose signatures this relay accepts.
	// Empty means no plugin can load — fail closed, because a trust policy with
	// no keys that accepted modules would be worse than no plugin support.
	TrustedKeyPEMs [][]byte
	// PinnedDigestsHex, when non-empty, restricts loading to exactly these
	// module digests. A signature says who built it; a pin says which build.
	PinnedDigestsHex []string
	// Grant is the capability grant every third-party connector runs under.
	//
	// One grant for all of them on purpose. Per-module grants read from the
	// module or its metadata would let a publisher widen their own privileges,
	// which is the whole thing a capability system exists to prevent. The
	// operator sets this, on their own machine, for code they did not write.
	Grant pluginhost.Grant
}

// ErrPluginsNotConfigured is returned when a relay is asked for a plugin
// connector and no plugin directory is configured.
var ErrPluginsNotConfigured = errors.New("relay: third-party connectors are not configured on this agent")

// NewPluginRuntime loads and verifies every module in cfg.Dir.
//
// A module that fails verification makes the whole load fail rather than being
// skipped. Skipping would mean a relay comes up serving some connectors and
// silently missing others, and the missing one is the one somebody tampered
// with — so the failure has to be loud at start rather than mysterious at
// deploy time.
func NewPluginRuntime(ctx context.Context, cfg PluginConfig) (*PluginRuntime, error) {
	dir := strings.TrimSpace(cfg.Dir)
	if dir == "" {
		return nil, nil // not configured: the relay serves native connectors only
	}
	if len(cfg.TrustedKeyPEMs) == 0 {
		return nil, errors.New("relay: a plugin directory is configured but no publisher trust " +
			"keys are; refusing to load unverified third-party code")
	}
	trust, err := pluginhost.NewTrustPolicy(cfg.TrustedKeyPEMs, cfg.PinnedDigestsHex)
	if err != nil {
		return nil, fmt.Errorf("relay: plugin trust policy: %w", err)
	}
	if cfg.Grant.Empty() {
		// A grant that permits nothing is a legitimate configuration — a
		// connector that only computes. A grant that was never SET is a
		// mistake, and the two look identical here, so the conservative reading
		// is the one that cannot surprise anybody.
		return nil, errors.New("relay: third-party connectors need an explicit capability grant; " +
			"an unset grant is refused rather than defaulted")
	}

	rt := &PluginRuntime{
		host:    pluginhost.New(),
		trust:   trust,
		plugins: map[string]*pluginhost.Plugin{},
		grants:  map[string]pluginhost.Grant{},
		census:  map[string]plugincensus.Entry{},
	}
	if err := rt.loadDir(ctx, dir, cfg.Grant); err != nil {
		_ = rt.Close(ctx)
		return nil, err
	}
	return rt, nil
}

// loadDir verifies and loads every signed module in dir.
func (r *PluginRuntime) loadDir(ctx context.Context, dir string, grant pluginhost.Grant) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("relay: read plugin directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".wasm") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".wasm")
		modulePath := filepath.Join(dir, entry.Name())
		sigPath := modulePath + ".sig"

		wasm, err := os.ReadFile(modulePath) // #nosec G304 -- operator-configured plugin directory (CWE-22)
		if err != nil {
			return fmt.Errorf("relay: read plugin %q: %w", name, err)
		}
		sig, err := os.ReadFile(sigPath) // #nosec G304 -- sibling of an operator-configured module (CWE-22)
		if err != nil {
			// An unsigned module is refused, not skipped. Dropping a file into
			// the directory must never be a way to get code loaded.
			return fmt.Errorf("relay: plugin %q has no signature at %s; unsigned third-party code "+
				"is refused: %w", name, filepath.Base(sigPath), err)
		}
		p, provenance, err := r.host.LoadVerifiedWithProvenance(ctx, wasm, sig, r.trust, grant)
		if err != nil {
			return fmt.Errorf("relay: plugin %q failed verification: %w", name, err)
		}
		grants := make([]plugincensus.Grant, 0, len(grant.Capabilities()))
		for _, capability := range grant.Capabilities() {
			grants = append(grants, plugincensus.Grant{
				Capability: string(capability), Constraints: grant.PathPrefixes(capability),
			})
		}
		entry, err := plugincensus.Normalize([]plugincensus.Entry{{
			Name: name, Digest: provenance.Digest, Publisher: provenance.Publisher,
			ExecutionContext: plugincensus.ExecutionContextNetworkRelayWASM, Grants: grants,
		}})
		if err != nil {
			_ = p.Close(ctx)
			return fmt.Errorf("relay: plugin %q census metadata: %w", name, err)
		}
		r.plugins[name] = p
		r.grants[name] = grant
		r.census[name] = entry[0]
	}
	return nil
}

// Has reports whether this relay carries a verified plugin for a connector.
func (r *PluginRuntime) Has(name string) bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.plugins[name]
	return ok
}

// Names reports the loaded connector names, sorted.
func (r *PluginRuntime) Names() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.plugins))
	for name := range r.plugins {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Census returns the normalized metadata captured by the successful verifier
// and loader. It cannot expose module or signature bytes because neither is
// retained in the census map.
func (r *PluginRuntime) Census() []plugincensus.Entry {
	if r == nil {
		return []plugincensus.Entry{}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]plugincensus.Entry, 0, len(r.census))
	for _, entry := range r.census {
		out = append(out, entry)
	}
	normalized, err := plugincensus.Normalize(out)
	if err != nil {
		panic("relay: stored plugin census is not normalized: " + err.Error())
	}
	return normalized
}

// Deploy runs a third-party connector's deploy entrypoint.
//
// The three failure modes are kept apart because they mean different things to
// whoever reads the receipt: the module misbehaved, the module reached outside
// its grant, or the module reported failure. Collapsing them would lose the one
// that matters most — a grant denial is a supply-chain signal, not a bad day on
// an appliance.
func (r *PluginRuntime) Deploy(ctx context.Context, name string) error {
	if r == nil {
		return ErrPluginsNotConfigured
	}
	r.mu.RLock()
	p := r.plugins[name]
	r.mu.RUnlock()
	if p == nil {
		return fmt.Errorf("relay: no verified plugin for connector %q", name)
	}

	before := p.Stats()
	rc, invErr := r.host.Invoke(ctx, p, pluginEntrypoint(p))
	denied := p.Stats().Denied - before.Denied

	switch {
	case invErr != nil:
		// The error can carry text the module chose. It is not forwarded to the
		// control plane: the relay reports a closed phrase, exactly as it does
		// for a native connector's error.
		return fmt.Errorf("relay: plugin %q deploy failed", name)
	case denied > 0:
		// The sandbox refused something the module tried. A deploy that
		// continued past this would be reporting success for a connector that
		// was reaching outside what its operator authorized.
		return fmt.Errorf("relay: plugin %q attempted %d operation(s) outside its capability grant",
			name, denied)
	case rc != 0:
		return fmt.Errorf("relay: plugin %q deploy returned non-zero status %d", name, rc)
	default:
		return nil
	}
}

// pluginEntrypoint picks the exported function to invoke.
//
// "deploy" preferred, "run" accepted. Two names because the SDK shipped one and
// the reference modules use the other, and refusing a module over a function
// name would be a compatibility break with nothing behind it.
func pluginEntrypoint(p *pluginhost.Plugin) string {
	if p.HasExport("deploy") {
		return "deploy"
	}
	return "run"
}

// Close releases every loaded module.
func (r *PluginRuntime) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var firstErr error
	for name, p := range r.plugins {
		if err := p.Close(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(r.plugins, name)
		delete(r.census, name)
	}
	if err := r.host.Close(ctx); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}
