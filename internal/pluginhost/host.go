// SPDX-License-Identifier: MPL-2.0

package pluginhost

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"

	"trstctl.com/trstctl/internal/bulkhead"
)

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
	reads  int64
	writes int64
	dials  int64
	denied int64
}

// Snapshot is an immutable view of a plugin's host-call counters.
type Snapshot struct {
	Reads  int64
	Writes int64
	Dials  int64
	Denied int64
}

// Plugin is a loaded, sandboxed WASM module bound to a grant.
type Plugin struct {
	runtime wazero.Runtime
	mod     api.Module
	grant   Grant
	stats   *Stats
	sb      *sandbox
}

// Stats returns a snapshot of the plugin's gated host-call activity.
func (p *Plugin) Stats() Snapshot {
	return Snapshot{
		Reads:  atomic.LoadInt64(&p.stats.reads),
		Writes: atomic.LoadInt64(&p.stats.writes),
		Dials:  atomic.LoadInt64(&p.stats.dials),
		Denied: atomic.LoadInt64(&p.stats.denied),
	}
}

// HasExport reports whether the plugin exports a function named fn. The served
// connector path uses it to pick the plugin's entrypoint (a connector plugin may
// export "deploy"; every conformant plugin exports "run").
func (p *Plugin) HasExport(fn string) bool { return p.mod.ExportedFunction(fn) != nil }

// Close releases the plugin's runtime and the sandbox's open directory handles.
func (p *Plugin) Close(ctx context.Context) error {
	if p.sb != nil {
		p.sb.close()
	}
	return p.runtime.Close(ctx)
}

// Load instantiates a WASM plugin in its own runtime, exposing only the host
// functions its grant permits. The guest has no ambient capabilities — no
// filesystem, network, or syscalls — beyond those host functions.
//
// The environment is shaped BY the grant, not merely checked against it: a
// capability the plugin was not granted has no corresponding export in the "env"
// module, so a guest that imports it fails to instantiate and never runs at all.
// That is a stronger property than a runtime deny, because the plugin's reach is
// closed before its first instruction executes.
func (h *Host) Load(ctx context.Context, wasm []byte, grant Grant) (*Plugin, error) {
	rt := wazero.NewRuntime(ctx)
	stats := &Stats{}
	sb := newSandbox(grant, stats)
	if err := h.registerEnv(ctx, rt, sb); err != nil {
		sb.close()
		_ = rt.Close(ctx)
		return nil, err
	}
	mod, err := rt.InstantiateWithConfig(ctx, wasm, wazero.NewModuleConfig())
	if err != nil {
		sb.close()
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("pluginhost: instantiate: %w", err)
	}
	return &Plugin{runtime: rt, mod: mod, grant: grant, stats: stats, sb: sb}, nil
}

// registerEnv installs the host ("env") module, exporting one function per
// GRANTED capability and nothing else.
//
// The ABI, all arguments i32 offsets/lengths into the guest's exported memory,
// all returning a status code (0 ok, 1 denied by grant, 2 error):
//
//	cap_read(path_ptr, path_len, out_ptr, out_cap, out_len_ptr) -> i32
//	cap_write(path_ptr, path_len, data_ptr, data_len)           -> i32
//	cap_dial(addr_ptr, addr_len)                                -> i32
//
// When the grant is empty the "env" module is not instantiated at all, so any
// import a guest declares fails to resolve. That is what makes the empty-grant
// conformance run meaningful: a plugin that passes it provably declared no
// privileged import.
func (h *Host) registerEnv(ctx context.Context, rt wazero.Runtime, sb *sandbox) error {
	b := rt.NewHostModuleBuilder("env")
	exported := 0
	if sb.grant.Has(CapFSRead) {
		b = b.NewFunctionBuilder().WithFunc(sb.hostRead).Export("cap_read")
		exported++
	}
	if sb.grant.Has(CapFSWrite) {
		b = b.NewFunctionBuilder().WithFunc(sb.hostWrite).Export("cap_write")
		exported++
	}
	if sb.grant.Has(CapNetDial) {
		b = b.NewFunctionBuilder().WithFunc(sb.hostDial).Export("cap_dial")
		exported++
	}
	if exported == 0 {
		return nil
	}
	if _, err := b.Instantiate(ctx); err != nil {
		return fmt.Errorf("pluginhost: register env: %w", err)
	}
	return nil
}

// guestBytes copies size bytes at ptr out of the guest's memory. Every bound is
// checked against a guest-controlled number before it becomes an allocation.
func guestBytes(m api.Module, ptr, size, limit uint32) ([]byte, bool) {
	if size > limit {
		return nil, false
	}
	mem := m.Memory()
	if mem == nil {
		return nil, false
	}
	return mem.Read(ptr, size)
}

// hostWrite implements cap_write: read the path and the payload from guest
// memory, then let the sandbox decide and perform the write.
func (s *sandbox) hostWrite(_ context.Context, m api.Module, pathPtr, pathLen, dataPtr, dataLen uint32) uint32 {
	p, ok := guestBytes(m, pathPtr, pathLen, maxPathBytes)
	if !ok {
		return s.refuse(errBadGuestPointer)
	}
	data, ok := guestBytes(m, dataPtr, dataLen, maxWriteBytes)
	if !ok {
		return s.refuse(errBadGuestPointer)
	}
	return s.writeFile(string(p), data)
}

// hostRead implements cap_read: on success the bytes are copied into the guest's
// buffer at out_ptr and the length is written as a little-endian u32 at
// out_len_ptr, so the guest never has to guess how much it got.
func (s *sandbox) hostRead(_ context.Context, m api.Module, pathPtr, pathLen, outPtr, outCap, outLenPtr uint32) uint32 {
	p, ok := guestBytes(m, pathPtr, pathLen, maxPathBytes)
	if !ok {
		return s.refuse(errBadGuestPointer)
	}
	if outCap > maxReadBytes {
		return s.refuse(errBadGuestPointer)
	}
	data, status := s.readFile(string(p), int(outCap))
	if status != statusOK {
		return status
	}
	mem := m.Memory()
	if mem == nil || !mem.Write(outPtr, data) || !mem.WriteUint32Le(outLenPtr, uint32(len(data))) {
		return s.refuse(errBadGuestPointer)
	}
	return statusOK
}

// hostDial implements cap_dial.
func (s *sandbox) hostDial(ctx context.Context, m api.Module, addrPtr, addrLen uint32) uint32 {
	a, ok := guestBytes(m, addrPtr, addrLen, maxPathBytes)
	if !ok {
		return s.refuse(errBadGuestPointer)
	}
	return s.dial(ctx, string(a))
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
	select {
	case r := <-ch:
		return r.v, r.err
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}
