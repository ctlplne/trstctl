// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/plugincensus"
	"trstctl.com/trstctl/internal/pluginhost"
)

// Third-party connectors, executed inside the customer's network (epic E4).
//
// The WASM plugin host already existed and already had the properties that
// matter: modules are signature- and digest-verified before they load, they run
// under a declared capability grant, and an out-of-grant operation is denied at
// runtime rather than audited afterward. What it did not have was a location.
//
// It ran on the control plane, which means a partner's code executed in the
// vendor's process against the customer's estate. Every guarantee held, and the
// arrangement still asked two organizations to accept something neither should
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
// rather than to assume it traveled.

// PluginRuntime is the relay's verified WASM connector host.
//
// It deliberately does NOT reuse server.PluginManager. That type carries an
// event log, emits tenant-scoped audit events and reaches the control plane's
// store — none of which exist here, and importing it would drag the control
// plane into the agent binary, which the import-boundary test refuses. What is
// shared is internal/pluginhost, which is where the actual guarantees live.
type PluginRuntime struct {
	trust *pluginhost.TrustPolicy

	mu      sync.RWMutex
	modules map[string]*pluginModule
	status  map[string]ModuleStatus
	census  map[string]plugincensus.Entry
}

// pluginModule is one admitted connector module (A242).
type pluginModule struct {
	// host is the module's own: its bounded pool serves this module only, so
	// a module that floods or spins occupies its own workers and never
	// another module's (AN-7).
	host       *pluginhost.Host
	plugin     *pluginhost.Plugin
	manifest   pluginhost.Manifest
	provenance pluginhost.Provenance
	grant      pluginhost.Grant
	health     moduleHealth
}

// Each module's pool. The relay runs one job at a time, so two workers leave
// room for a test beside a deploy, and the queue stays small: work a module
// cannot take is refused at once rather than parked behind a stuck call.
const (
	moduleWorkers = 2
	moduleQueue   = 8
)

// Module states (A242).
const (
	// ModuleLoaded runs: signed, its manifest signed by the same publisher,
	// within this relay's grant and approved by its operator.
	ModuleLoaded = "loaded"
	// ModuleAwaitingApproval is verified but asks for something no approval
	// covers: a first install, more permissions than the approved version, a
	// different publisher or an older version. It does not run until the
	// operator reviews it (trstctl-agent --approve-connector-module).
	ModuleAwaitingApproval = "awaiting-approval"
	// ModuleIncompatible is verified but cannot run here: it needs another
	// host ABI, or more than this relay's grant gives. No approval changes
	// that; a new build or a wider operator grant does.
	ModuleIncompatible = "incompatible"
)

// ModuleStatus is what the relay knows about one module in its directory.
type ModuleStatus struct {
	Name     string
	State    string
	Reason   string
	Manifest pluginhost.Manifest
	// Digest and Publisher are the verified module's ("sha256:<hex>").
	Digest    string
	Publisher string
	// Diff is what an approval would add over the current one.
	Diff   []string
	Health ModuleHealth
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
	// ApprovalsPath is the operator's approval record (A242): for each module,
	// the version, build and permissions the operator reviewed. It lives with
	// the agent's own state rather than in Dir, so dropping files into the
	// plugin directory can never approve anything. A module no approval covers
	// is verified and reported, and does not run.
	//
	// Grant is the ceiling, not what each module gets: a module runs under
	// exactly what its signed manifest asks for, which must fit inside it.
	ApprovalsPath string
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

	approvals, err := ReadModuleApprovals(cfg.ApprovalsPath)
	if err != nil {
		return nil, err
	}
	rt := &PluginRuntime{
		trust:   trust,
		modules: map[string]*pluginModule{},
		status:  map[string]ModuleStatus{},
		census:  map[string]plugincensus.Entry{},
	}
	if err := rt.loadDir(ctx, dir, cfg.Grant, approvals); err != nil {
		_ = rt.Close(ctx)
		return nil, err
	}
	return rt, nil
}

// loadDir verifies every module in dir and loads the ones that may run.
//
// A module that fails verification (no signature, a tampered or untrusted
// one, no manifest, a manifest another key signed or that describes another
// build) fails the whole load: that is a supply-chain signal. A verified
// module that needs approval, or cannot run under this relay's grant or host
// ABI, is recorded with its state and reason and does not run; the relay
// serves the rest, and every deploy routed to it fails naming that state.
func (r *PluginRuntime) loadDir(ctx context.Context, dir string, grant pluginhost.Grant, approvals map[string]ModuleApproval) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("relay: read plugin directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".wasm") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".wasm")
		v, err := verifyModule(r.trust, dir, name)
		if err != nil {
			return err
		}
		status := v.status(grant, approvals[name])
		if status.State != ModuleLoaded {
			log.Printf("trstctl-agent: connector module %s %s is %s: %s %v", name, v.manifest.Version, status.State, status.Reason, status.Diff)
			census, err := moduleCensus(name, v.provenance, pluginhost.NewGrant())
			if err != nil {
				return err
			}
			r.status[name] = status
			r.census[name] = census
			continue
		}
		m, err := v.load(ctx, r.trust, grant)
		if err != nil {
			return err
		}
		census, err := moduleCensus(name, v.provenance, m.grant)
		if err != nil {
			m.close(ctx)
			return err
		}
		r.modules[name] = m
		r.status[name] = status
		r.census[name] = census
	}
	return nil
}

// verifiedModule is a module whose signature and manifest checked out.
type verifiedModule struct {
	name       string
	wasm, sig  []byte
	manifest   pluginhost.Manifest
	provenance pluginhost.Provenance
}

// verifyModule reads and verifies <name>.wasm, its signature and its signed
// manifest.
func verifyModule(trust *pluginhost.TrustPolicy, dir, name string) (verifiedModule, error) {
	modulePath := filepath.Join(dir, name+".wasm")
	sigPath := modulePath + ".sig"
	wasm, err := os.ReadFile(modulePath) // #nosec G304 -- operator-configured plugin directory (CWE-22)
	if err != nil {
		return verifiedModule{}, fmt.Errorf("relay: read plugin %q: %w", name, err)
	}
	sig, err := os.ReadFile(sigPath) // #nosec G304 -- sibling of an operator-configured module (CWE-22)
	if err != nil {
		// An unsigned module is refused, not skipped. Dropping a file into
		// the directory must never be a way to get code loaded.
		return verifiedModule{}, fmt.Errorf("relay: plugin %q has no signature at %s; unsigned third-party code "+
			"is refused: %w", name, filepath.Base(sigPath), err)
	}
	provenance, err := trust.VerifyProvenance(wasm, sig)
	if err != nil {
		return verifiedModule{}, fmt.Errorf("relay: plugin %q failed verification: %w", name, err)
	}
	manifestPath := filepath.Join(dir, name+".manifest.json")
	raw, err := os.ReadFile(manifestPath) // #nosec G304 -- sibling of an operator-configured module (CWE-22)
	if err != nil {
		return verifiedModule{}, fmt.Errorf("relay: plugin %q has no manifest at %s; a connector module ships a "+
			"signed manifest naming its version and permissions: %w", name, filepath.Base(manifestPath), err)
	}
	manifestSig, err := os.ReadFile(manifestPath + ".sig") // #nosec G304 -- sibling of an operator-configured module (CWE-22)
	if err != nil {
		return verifiedModule{}, fmt.Errorf("relay: plugin %q manifest has no signature: %w", name, err)
	}
	if err := trust.VerifyPublisher(provenance.Publisher, raw, manifestSig); err != nil {
		return verifiedModule{}, fmt.Errorf("relay: plugin %q manifest: %w", name, err)
	}
	manifest, err := pluginhost.ParseManifest(raw)
	if err != nil {
		return verifiedModule{}, fmt.Errorf("relay: plugin %q: %w", name, err)
	}
	if manifest.Name != name || "sha256:"+manifest.ModuleSHA256 != provenance.Digest {
		return verifiedModule{}, fmt.Errorf("relay: plugin %q manifest describes %s (sha256:%s), not this module (%s)",
			name, manifest.Name, manifest.ModuleSHA256, provenance.Digest)
	}
	return verifiedModule{name: name, wasm: wasm, sig: sig, manifest: manifest, provenance: provenance}, nil
}

// status decides whether a verified module runs under this relay's grant
// and its operator's approval.
func (v verifiedModule) status(grant pluginhost.Grant, approval ModuleApproval) ModuleStatus {
	st := ModuleStatus{Name: v.name, Manifest: v.manifest, Digest: v.provenance.Digest, Publisher: v.provenance.Publisher}
	if !v.manifest.SupportsHost() {
		st.State, st.Reason = ModuleIncompatible, fmt.Sprintf("it supports host ABI %d to %d; this relay implements %d",
			v.manifest.HostAPI.Min, v.manifest.HostAPI.Max, pluginhost.HostAPIVersion)
		return st
	}
	if _, err := pluginhost.EffectiveGrant(grant, v.manifest); err != nil {
		st.State, st.Reason = ModuleIncompatible, err.Error()
		return st
	}
	everything := pluginhost.PermissionDiff(pluginhost.Permissions{}, v.manifest.Permissions)
	st.State, st.Diff = ModuleAwaitingApproval, pluginhost.PermissionDiff(approval.Permissions, v.manifest.Permissions)
	switch {
	case approval.Version == "":
		st.Reason, st.Diff = "no approval on this relay", everything
	case approval.Publisher != v.provenance.Publisher:
		st.Reason, st.Diff = "signed by a different publisher than the approved version", everything
	case pluginhost.CompareVersions(v.manifest.Version, approval.Version) < 0:
		st.Reason = "older than the approved version " + approval.Version
	case len(st.Diff) > 0:
		st.Reason = "asks for more than the approved version " + approval.Version
	default:
		st.State, st.Reason = ModuleLoaded, ""
	}
	return st
}

// load instantiates a verified module under its effective grant and its own
// limits, on its own bounded pool.
func (v verifiedModule) load(ctx context.Context, trust *pluginhost.TrustPolicy, grant pluginhost.Grant) (*pluginModule, error) {
	effective, err := pluginhost.EffectiveGrant(grant, v.manifest)
	if err != nil {
		return nil, fmt.Errorf("relay: plugin %q: %w", v.name, err)
	}
	host := pluginhost.New(pluginhost.WithPool(bulkhead.New(bulkhead.Config{
		Name: "relay-module-" + v.name, Workers: moduleWorkers, Queue: moduleQueue,
	})))
	p, _, err := host.LoadVerifiedModule(ctx, v.wasm, v.sig, trust, effective, v.manifest.ResourceLimits())
	if err != nil {
		_ = host.Close(ctx)
		return nil, fmt.Errorf("relay: plugin %q does not load under its own limits: %w", v.name, err)
	}
	return &pluginModule{host: host, plugin: p, manifest: v.manifest, provenance: v.provenance, grant: effective}, nil
}

// close releases the module and its pool.
func (m *pluginModule) close(ctx context.Context) {
	_ = m.plugin.Close(ctx)
	_ = m.host.Close(ctx)
}

// moduleCensus is the census entry for a loaded module: its identity and the
// grant it actually runs under.
func moduleCensus(name string, provenance pluginhost.Provenance, grant pluginhost.Grant) (plugincensus.Entry, error) {
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
		return plugincensus.Entry{}, fmt.Errorf("relay: plugin %q census metadata: %w", name, err)
	}
	return entry[0], nil
}

// Modules reports every module in the directory with its state, sorted by
// name.
func (r *PluginRuntime) Modules() []ModuleStatus {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ModuleStatus, 0, len(r.status))
	for name, st := range r.status {
		if m := r.modules[name]; m != nil {
			st.Health = m.health.snapshot()
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Has reports whether this relay carries a module for a connector, loaded or
// not. A deploy routed to one that is not loaded fails with its state (Ready)
// before anything is redeemed, rather than reading as an unknown connector.
func (r *PluginRuntime) Has(name string) bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.status[name]
	return ok
}

// Ready reports whether the connector's module runs on this relay: nil when
// it is loaded, otherwise a *ModuleFailure naming its state.
func (r *PluginRuntime) Ready(name string) error {
	_, err := r.module(name)
	return err
}

// Names reports the loaded connector names, sorted.
func (r *PluginRuntime) Names() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.modules))
	for name := range r.modules {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Census returns the normalized metadata captured by the successful verifier
// and loader. It cannot expose module or signature bytes because neither is
// retained in the census map. Each entry carries its module's manifest
// metadata, state and current health (A242); a module that is not loaded is
// listed with no grants.
func (r *PluginRuntime) Census() []plugincensus.Entry {
	if r == nil {
		return []plugincensus.Entry{}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]plugincensus.Entry, 0, len(r.census))
	for name, entry := range r.census {
		st := r.status[name]
		var health ModuleHealth
		if m := r.modules[name]; m != nil {
			health = m.health.snapshot()
		}
		entry.Module = censusModule(st, health)
		out = append(out, entry)
	}
	normalized, err := plugincensus.Normalize(out)
	if err != nil {
		panic("relay: stored plugin census is not normalized: " + err.Error())
	}
	return normalized
}

// PluginCall is what one deploy or test gives a third-party connector (A193):
// the intent, the attempt's redeemed material, which the module never reads
// (the relay splices the key and adds the credential to the module's HTTP
// requests), and the agent's HTTP client, so the requests follow its egress
// policy.
type PluginCall struct {
	Intent   DeployIntent
	Material Material
	Client   *http.Client
}

// Deploy runs a third-party connector's deploy entrypoint.
//
// Its failure is a *ModuleFailure: the module trapped, timed out, reached
// outside its grant or reported a status. They are kept apart because they mean
// different things to whoever reads the receipt — a grant denial is a
// supply-chain signal, not a bad day on an appliance.
func (r *PluginRuntime) Deploy(ctx context.Context, name string, call PluginCall) error {
	m, err := r.module(name)
	if err != nil {
		return err
	}
	_, err = r.invoke(ctx, m, name, pluginEntrypoint(m.plugin), call, false)
	return err
}

// Test runs a third-party connector's test entry point under the read-only
// grant (A193): no filesystem writes, and HTTP requests limited to GET and
// HEAD. A request that would change the target is refused before it is sent,
// and fails the test as an operation outside the grant.
func (r *PluginRuntime) Test(ctx context.Context, name string, call PluginCall) error {
	m, err := r.module(name)
	if err != nil {
		return err
	}
	if !m.plugin.HasExport("test") {
		return fmt.Errorf("relay: plugin %q has no test entry point", name)
	}
	_, err = r.invoke(ctx, m, name, "test", call, true)
	return err
}

// HasTest reports whether the loaded plugin for a connector exports a test
// entry point.
func (r *PluginRuntime) HasTest(name string) bool {
	m, err := r.module(name)
	return err == nil && m.plugin.HasExport("test")
}

// HasReadback reports whether the connector's loaded module declares and
// exports a readback entry point.
func (r *PluginRuntime) HasReadback(name string) bool {
	m, err := r.module(name)
	return err == nil && m.manifest.Has("readback") && m.plugin.HasExport("readback")
}

// moduleReadbackVerdicts maps a readback entry point's status to the verdict
// native connectors report (A242): 0 this deploy's certificate is serving,
// 1 another one is bound, 2 nothing is installed, 3 installed but not bound.
var moduleReadbackVerdicts = map[uint64]connector.ReadbackVerdict{
	0: connector.ReadbackServing,
	1: connector.ReadbackDiverged,
	2: connector.ReadbackAbsent,
	3: connector.ReadbackInstalledNotBound,
}

// Readback asks the module, read-only, what the target holds for call's
// deploy, as a verdict and the operator-facing sentence. A module without a
// readback entry point answers "", "".
func (r *PluginRuntime) Readback(ctx context.Context, name string, call PluginCall) (connector.ReadbackVerdict, string) {
	if !r.HasReadback(name) {
		return "", ""
	}
	m, err := r.module(name)
	if err != nil {
		return "", ""
	}
	rc, err := r.invoke(ctx, m, name, "readback", call, true)
	var failure *ModuleFailure
	if err != nil && (!errors.As(err, &failure) || failure.Class != FailureStatus) {
		return connector.ReadbackUnknown, "the connector module could not read the target back"
	}
	verdict, ok := moduleReadbackVerdicts[rc]
	if !ok {
		return connector.ReadbackUnknown, fmt.Sprintf("the connector module's readback answered status %d", rc)
	}
	return verdict, "the connector module reads back: " + string(verdict)
}

// RetriesBlindly reports whether a retried deploy may simply run again: true
// for a replace-by-name module, false for one whose deploy creates objects or
// reads the target first (its readback is asked before a retry).
func (r *PluginRuntime) RetriesBlindly(name string) bool {
	m, err := r.module(name)
	return err != nil || m.manifest.Idempotency == "replace-by-name"
}

func (r *PluginRuntime) module(name string) (*pluginModule, error) {
	if r == nil {
		return nil, ErrPluginsNotConfigured
	}
	r.mu.RLock()
	m, st := r.modules[name], r.status[name]
	r.mu.RUnlock()
	switch {
	case m != nil:
		return m, nil
	case st.State != "":
		return nil, &ModuleFailure{Module: name, Version: st.Manifest.Version, Digest: st.Digest, Class: st.State}
	default:
		return nil, fmt.Errorf("relay: no verified plugin for connector %q", name)
	}
}

func (r *PluginRuntime) invoke(ctx context.Context, m *pluginModule, name, fn string, call PluginCall, readOnly bool) (uint64, error) {
	before := m.plugin.Stats()
	rc, invErr := m.host.InvokeWith(ctx, m.plugin, fn, pluginInvocation(call.Client, call.Intent, call.Material, readOnly))
	denied := m.plugin.Stats().Denied - before.Denied

	failure := &ModuleFailure{Module: name, Version: m.manifest.Version, Digest: m.provenance.Digest, Entry: fn}
	switch {
	case invErr != nil:
		// The error can carry text the module chose. It is not forwarded: the
		// failure names only what the host observed.
		failure.Class = pluginhost.FailureClass(invErr)
	case denied > 0:
		// The sandbox refused something the module tried. A deploy that
		// continued past this would be reporting success for a connector that
		// was reaching outside what its operator authorized.
		failure.Class, failure.Denied = FailureGrantDenied, denied
	case rc != 0:
		failure.Class, failure.Status = FailureStatus, rc
	default:
		m.health.record("")
		return rc, nil
	}
	m.health.record(failure.Class)
	return rc, failure
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
	for name, m := range r.modules {
		m.close(ctx)
		delete(r.modules, name)
		delete(r.census, name)
	}
	return nil
}

// censusModule is a module's census metadata: its manifest's declarations,
// its state and its health. Never an input's value or a credential.
func censusModule(st ModuleStatus, health ModuleHealth) *plugincensus.Module {
	m := st.Manifest
	inputs := make([]plugincensus.ModuleInput, 0, len(m.Inputs))
	for _, in := range m.Inputs {
		inputs = append(inputs, plugincensus.ModuleInput{
			Name: in.Name, Type: in.Type, Required: in.Required, Secret: in.Secret, Description: in.Description,
		})
	}
	credentials := make([]string, 0, len(m.Permissions.Credentials))
	for _, mode := range m.Permissions.Credentials {
		if c, ok := pluginhost.CanonicalCredentialMode(mode); ok {
			credentials = append(credentials, c)
		}
	}
	limits := m.ResourceLimits()
	pages := limits.MemoryPages
	if pages == 0 {
		pages = pluginhost.DefaultMemoryPages
	}
	timeoutMS := int(limits.Timeout.Milliseconds())
	if timeoutMS == 0 {
		timeoutMS = int(pluginhost.MaxCallDuration.Milliseconds())
	}
	return &plugincensus.Module{
		Version: m.Version, State: st.State, HostAPIMin: m.HostAPI.Min, HostAPIMax: m.HostAPI.Max,
		Actions: m.Actions, Idempotency: m.Idempotency, Revocation: m.Revocation, Credentials: credentials,
		Inputs: inputs, MemoryPages: pages, TimeoutMS: timeoutMS, PendingPermissions: st.Diff, StateReason: st.Reason,
		Health: plugincensus.ModuleHealth{
			Calls: health.Calls, Failures: health.Failures, ConsecutiveFailures: health.ConsecutiveFailures,
			LastFailure: health.LastFailure,
		},
	}
}
