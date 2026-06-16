package pluginhost

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"

	"trstctl.com/trstctl/internal/bulkhead"
)

// denyCode is the value a gated host function returns to the guest when the
// operation is not permitted by the plugin's grant.
const denyCode uint32 = 1

// Host runs WASM plugins. Each plugin gets its own wazero runtime (isolation),
// and every plugin invocation is submitted to a shared bounded pool so a slow or
// flooded plugin cannot starve the rest of the platform (AN-7).
type Host struct {
	pool *bulkhead.Pool
}

// Option configures a Host.
type Option func(*Host)

// WithPool runs invocations on the given bounded pool instead of the default.
func WithPool(p *bulkhead.Pool) Option { return func(h *Host) { h.pool = p } }

// New returns a Host. By default invocations run on a modest bounded pool.
func New(opts ...Option) *Host {
	h := &Host{}
	for _, o := range opts {
		o(h)
	}
	if h.pool == nil {
		h.pool = bulkhead.New(bulkhead.Config{Name: "pluginhost", Workers: 8, Queue: 256})
	}
	return h
}

// Close releases the host's worker pool.
func (h *Host) Close(_ context.Context) error {
	h.pool.Close()
	return nil
}

// Stats records what a plugin's gated host calls did.
type Stats struct {
	writes int64
	denied int64
}

// Snapshot is an immutable view of a plugin's host-call counters.
type Snapshot struct {
	Writes int64
	Denied int64
}

// Plugin is a loaded, sandboxed WASM module bound to a grant.
type Plugin struct {
	runtime wazero.Runtime
	mod     api.Module
	grant   Grant
	stats   *Stats
}

// Stats returns a snapshot of the plugin's gated host-call activity.
func (p *Plugin) Stats() Snapshot {
	return Snapshot{Writes: atomic.LoadInt64(&p.stats.writes), Denied: atomic.LoadInt64(&p.stats.denied)}
}

// HasExport reports whether the plugin exports a function named fn. The served
// connector path uses it to pick the plugin's entrypoint (a connector plugin may
// export "deploy"; every conformant plugin exports "run").
func (p *Plugin) HasExport(fn string) bool { return p.mod.ExportedFunction(fn) != nil }

// Close releases the plugin's runtime.
func (p *Plugin) Close(ctx context.Context) error { return p.runtime.Close(ctx) }

// Load instantiates a WASM plugin in its own runtime, exposing only the host
// functions its grant permits. The guest has no ambient capabilities — no
// filesystem, network, or syscalls — beyond those host functions.
func (h *Host) Load(ctx context.Context, wasm []byte, grant Grant) (*Plugin, error) {
	rt := wazero.NewRuntime(ctx)
	stats := &Stats{}
	if err := h.registerEnv(ctx, rt, grant, stats); err != nil {
		_ = rt.Close(ctx)
		return nil, err
	}
	mod, err := rt.InstantiateWithConfig(ctx, wasm, wazero.NewModuleConfig())
	if err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("pluginhost: instantiate: %w", err)
	}
	return &Plugin{runtime: rt, mod: mod, grant: grant, stats: stats}, nil
}

// registerEnv installs the host ("env") module: the capability functions, each
// gated by the plugin's grant. A guest that does not import them is unaffected.
func (h *Host) registerEnv(ctx context.Context, rt wazero.Runtime, grant Grant, stats *Stats) error {
	capWrite := func(_ context.Context, _ api.Module, _ uint32) uint32 {
		// The real fs.write reads the path from guest memory and calls
		// grant.Allows(CapFSWrite, path); the minimal ABI here gates on the
		// capability's presence.
		if !grant.Has(CapFSWrite) {
			atomic.AddInt64(&stats.denied, 1)
			return denyCode
		}
		atomic.AddInt64(&stats.writes, 1)
		return 0
	}
	_, err := rt.NewHostModuleBuilder("env").
		NewFunctionBuilder().WithFunc(capWrite).Export("cap_write").
		Instantiate(ctx)
	if err != nil {
		return fmt.Errorf("pluginhost: register env: %w", err)
	}
	return nil
}

// Invoke calls an exported function of the plugin, on the host's bounded pool. If
// the pool is saturated it returns a *bulkhead.Rejected (AN-7) without running
// the plugin.
func (h *Host) Invoke(ctx context.Context, p *Plugin, fn string) (uint64, error) {
	type result struct {
		v   uint64
		err error
	}
	ch := make(chan result, 1)
	if err := h.pool.Submit(func() {
		f := p.mod.ExportedFunction(fn)
		if f == nil {
			ch <- result{err: fmt.Errorf("pluginhost: plugin has no exported function %q", fn)}
			return
		}
		out, err := f.Call(ctx)
		if err != nil {
			ch <- result{err: fmt.Errorf("pluginhost: call %q: %w", fn, err)}
			return
		}
		var v uint64
		if len(out) > 0 {
			v = out[0]
		}
		ch <- result{v: v}
	}); err != nil {
		return 0, err
	}
	r := <-ch
	return r.v, r.err
}
