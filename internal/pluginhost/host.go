// SPDX-License-Identifier: MPL-2.0

package pluginhost

import (
	"context"
	"fmt"
	"math"
	"sync/atomic"
	"time"

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

// Plugin is a loaded, sandboxed WASM plugin bound to a grant. The module is
// COMPILED once and instantiated freshly for every invocation (AUD-201
// follow-up J2/V8): an interrupted call closes only ITS OWN instance, so a
// deploy that exceeds its deadline can no longer brick the connector for the
// process lifetime — and one call's teardown shares no module state with the
// next call. Each invocation also starts from pristine guest memory, which is
// strictly stronger isolation than the old shared instance.
type Plugin struct {
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
	grant    Grant
	stats    *Stats
	sb       *sandbox
	nameSeq  atomic.Uint64
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
func (p *Plugin) HasExport(fn string) bool {
	_, ok := p.compiled.ExportedFunctions()[fn]
	return ok
}

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
	// WithCloseOnContextDone is what makes a guest INTERRUPTIBLE. wazero's default
	// runtime runs guest code to completion regardless of the context, so a plugin
	// containing `loop { }` — a bug or a hostile plugin — occupied its bounded-pool
	// worker forever and could not be cancelled, shed, or drained at shutdown.
	// Capability grants close the plugin's reach; they do nothing about its
	// runtime, which is what this bounds (AN-7).
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCloseOnContextDone(true))
	stats := &Stats{}
	sb := newSandbox(grant, stats)
	if err := h.registerEnv(ctx, rt, sb); err != nil {
		sb.close()
		_ = rt.Close(ctx)
		return nil, err
	}
	compiled, err := rt.CompileModule(ctx, wasm)
	if err != nil {
		sb.close()
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("pluginhost: instantiate: %w", err)
	}
	// Instantiate once so a guest whose start section or imports are broken
	// fails at LOAD, exactly as before, and to prove the env module satisfies
	// the guest's imports under this grant.
	probe, err := rt.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName("load-probe"))
	if err != nil {
		sb.close()
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("pluginhost: instantiate: %w", err)
	}
	_ = probe.Close(ctx)
	return &Plugin{runtime: rt, compiled: compiled, grant: grant, stats: stats, sb: sb}, nil
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
	// The read is bounded by outCap, itself capped at maxReadBytes above, so this
	// cannot truncate. The check is written out rather than argued in a comment,
	// because "provably in range" and "in range as far as anyone remembered" look
	// identical six months later.
	n := len(data)
	if n < 0 || n > math.MaxUint32 {
		return s.refuse(errBadGuestPointer)
	}
	readLen := uint32(n)
	mem := m.Memory()
	if mem == nil || !mem.Write(outPtr, data) || !mem.WriteUint32Le(outLenPtr, readLen) {
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

// maxPluginCallDuration caps a single guest invocation when the caller supplied
// no deadline of its own. A plugin is foreign code on a shared bounded pool, so
// "runs forever" must not be one of its options.
const maxPluginCallDuration = 30 * time.Second

// Invoke calls an exported function of the plugin, on the host's bounded pool. If
// the pool is saturated it returns a *bulkhead.Rejected (AN-7) without running
// the plugin. A guest that does not return within maxPluginCallDuration (or the
// caller's deadline, whichever is sooner) is interrupted and its worker released.
func (h *Host) Invoke(ctx context.Context, p *Plugin, fn string) (uint64, error) {
	// Fast-drop dead work before it is enqueued: a caller that has already
	// given up must not occupy a worker (J2/V8).
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	type result struct {
		v   uint64
		err error
	}
	ch := make(chan result, 1)
	if err := h.pool.Submit(func() {
		// The caller may have abandoned this task while it sat in the bulkhead
		// queue (Invoke returned on ctx.Done). Calling into wazero with an
		// already-dead context CLOSES the module without the guest ever
		// executing — an abandoned queue entry must not kill a healthy module
		// as a side effect (J2/V8).
		if err := ctx.Err(); err != nil {
			ch <- result{err: err}
			return
		}
		// Bound the guest's runtime even when the caller supplied no deadline.
		// Paired with WithCloseOnContextDone above, this is what actually stops a
		// looping guest rather than merely asking it to stop.
		callCtx := ctx
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			var cancel context.CancelFunc
			callCtx, cancel = context.WithTimeout(ctx, maxPluginCallDuration)
			defer cancel()
		}
		// A fresh instance per call (J2/V8): the interrupt that stops a
		// runaway guest closes only THIS instance, so a timeout cannot brick
		// the connector for later calls, and one call's teardown shares no
		// module state with a concurrent call's execution.
		name := fmt.Sprintf("call-%d", p.nameSeq.Add(1))
		mod, err := p.runtime.InstantiateModule(callCtx, p.compiled, wazero.NewModuleConfig().WithName(name))
		if err != nil {
			ch <- result{err: fmt.Errorf("pluginhost: instantiate call module: %w", err)}
			return
		}
		defer func() { _ = mod.Close(context.WithoutCancel(callCtx)) }()
		f := mod.ExportedFunction(fn)
		if f == nil {
			ch <- result{err: fmt.Errorf("pluginhost: plugin has no exported function %q", fn)}
			return
		}
		out, err := f.Call(callCtx)
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
