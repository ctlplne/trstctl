// SPDX-License-Identifier: BUSL-1.1

// Package host runs the first-party connector module inside wazero and binds
// its connectors into the host's connector registry. A bound connector is the
// same family the host would have built in-process, but its code executes in a
// fresh sandboxed instance per operation: the only effects it can have are the
// Sandbox operations it asks the host for, which reach the same
// capability-gated sandbox (the connector's grant and the attempt's Ops) an
// in-process connector would get. It holds no database pool, signer handle,
// network socket or filesystem of its own.
package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/native"
	"trstctl.com/trstctl/internal/connector/wasm/abi"
	"trstctl.com/trstctl/internal/crypto"
)

// memoryLimitPages bounds one instance's linear memory (64 KiB pages: 256 MiB).
const memoryLimitPages = 4096

// Runtime is one compiled connector module, shared by every bound connector.
// Each operation instantiates the module afresh, so no state, credential or
// response outlives the operation that needed it.
type Runtime struct {
	rt       wazero.Runtime
	compiled wazero.CompiledModule
	digest   string
	closeMu  sync.Once
}

// New compiles module. Compilation is the expensive step and happens once.
func New(ctx context.Context, module []byte) (*Runtime, error) {
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().
		WithCloseOnContextDone(true).
		WithMemoryLimitPages(memoryLimitPages))
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, rt); err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("connector sandbox: wasi: %w", err)
	}
	if _, err := rt.NewHostModuleBuilder(abi.HostModule).
		NewFunctionBuilder().WithFunc(hostResult).Export(abi.ImportResult).
		NewFunctionBuilder().WithFunc(hostSandbox).Export(abi.ImportOp).
		NewFunctionBuilder().WithFunc(hostTake).Export(abi.ImportTake).
		Instantiate(ctx); err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("connector sandbox: host module: %w", err)
	}
	compiled, err := rt.CompileModule(ctx, module)
	if err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("connector sandbox: compile module: %w", err)
	}
	for _, export := range []string{abi.ExportAlloc, abi.ExportFree, abi.ExportCall} {
		if _, ok := compiled.ExportedFunctions()[export]; !ok {
			_ = rt.Close(ctx)
			return nil, fmt.Errorf("connector sandbox: module does not export %s", export)
		}
	}
	return &Runtime{rt: rt, compiled: compiled, digest: crypto.SHA256Hex(module)}, nil
}

// ModuleImports lists a module's imported functions as "module.name", for
// tests and review of what a module can reach.
func ModuleImports(ctx context.Context, module []byte) ([]string, error) {
	rt := wazero.NewRuntime(ctx)
	defer func() { _ = rt.Close(ctx) }()
	compiled, err := rt.CompileModule(ctx, module)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, fn := range compiled.ImportedFunctions() {
		module, name, _ := fn.Import()
		out = append(out, module+"."+name)
	}
	return out, nil
}

// Digest is the SHA-256 of the module this runtime runs.
func (r *Runtime) Digest() string { return r.digest }

// Close releases the compiled module and every instance still running.
func (r *Runtime) Close(ctx context.Context) error {
	var err error
	r.closeMu.Do(func() { err = r.rt.Close(ctx) })
	return err
}

// callState is one operation's host-side state, reached by the host functions
// through the call's context.
type callState struct {
	ctx     context.Context
	sb      connector.Sandbox
	pending []byte
	result  []byte
}

type callStateKey struct{}

func stateOf(ctx context.Context) *callState {
	state, _ := ctx.Value(callStateKey{}).(*callState)
	return state
}

// invoke runs one Call in a fresh instance with sb as the connector's sandbox.
func (r *Runtime) invoke(ctx context.Context, sb connector.Sandbox, call abi.Call) (abi.Result, error) {
	call.Version = abi.Version
	payload, err := json.Marshal(call)
	if err != nil {
		return abi.Result{}, fmt.Errorf("connector sandbox: encode call: %w", err)
	}
	defer wipe(payload)
	if len(payload) > abi.MaxCallBytes {
		return abi.Result{}, fmt.Errorf("connector sandbox: call exceeds %d bytes", abi.MaxCallBytes)
	}
	state := &callState{ctx: ctx, sb: sb}
	callCtx := context.WithValue(ctx, callStateKey{}, state)
	mod, err := r.rt.InstantiateModule(callCtx, r.compiled, wazero.NewModuleConfig().
		WithName("").
		WithStartFunctions("_initialize").
		WithSysWalltime().WithSysNanotime().WithSysNanosleep().
		WithRandSource(randomSource{}).
		WithStdout(io.Discard).WithStderr(io.Discard))
	if err != nil {
		return abi.Result{}, fmt.Errorf("connector sandbox: instantiate: %w", err)
	}
	defer func() {
		// Credentials and key material lived in this instance's memory; wipe it
		// before the runtime lets it go.
		if mem := mod.Memory(); mem != nil {
			if view, ok := mem.Read(0, mem.Size()); ok {
				clear(view)
			}
		}
		_ = mod.Close(context.WithoutCancel(ctx))
		wipe(state.pending)
		wipe(state.result)
	}()
	out, err := mod.ExportedFunction(abi.ExportAlloc).Call(callCtx, uint64(len(payload)))
	if err != nil || len(out) != 1 || out[0] == 0 || out[0] > math.MaxUint32 {
		return abi.Result{}, fmt.Errorf("connector sandbox: allocate call: %v", err)
	}
	ptr := uint32(out[0]) // #nosec G115 -- a wasm32 address, bounded by math.MaxUint32 just above (CWE-190).
	if !mod.Memory().Write(ptr, payload) {
		return abi.Result{}, errors.New("connector sandbox: call does not fit the module's memory")
	}
	status, err := mod.ExportedFunction(abi.ExportCall).Call(callCtx, uint64(ptr), uint64(len(payload)))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return abi.Result{}, fmt.Errorf("connector sandbox: %w", ctxErr)
		}
		return abi.Result{}, fmt.Errorf("connector sandbox: call: %w", err)
	}
	if len(status) != 1 || status[0] != 0 || state.result == nil {
		return abi.Result{}, errors.New("connector sandbox: the module did not complete the call")
	}
	var result abi.Result
	if err := json.Unmarshal(state.result, &result); err != nil {
		return abi.Result{}, fmt.Errorf("connector sandbox: decode result: %w", err)
	}
	return result, nil
}

// hostResult receives the guest's encoded Result.
func hostResult(ctx context.Context, m api.Module, ptr, size uint32) {
	state := stateOf(ctx)
	if state == nil || size > abi.MaxResultBytes {
		return
	}
	if data, ok := m.Memory().Read(ptr, size); ok {
		state.result = bytes.Clone(data)
	}
}

// hostSandbox performs one SandboxOp and holds its encoded result for take. It
// returns status<<32 | result length; a non-zero status means the operation
// could not even be read.
func hostSandbox(ctx context.Context, m api.Module, ptr, size uint32) uint64 {
	const refused = uint64(1) << 32
	state := stateOf(ctx)
	if state == nil || size > abi.MaxOpBytes {
		return refused
	}
	data, ok := m.Memory().Read(ptr, size)
	if !ok {
		return refused
	}
	var op abi.SandboxOp
	if err := json.Unmarshal(data, &op); err != nil {
		return refused
	}
	res := perform(state.ctx, state.sb, op)
	wipe(op.Payload)
	wipe(op.Data)
	encoded, err := json.Marshal(res)
	if res.Response != nil {
		wipe(res.Response.Body)
	}
	wipe(res.Data)
	if err != nil {
		return refused
	}
	wipe(state.pending)
	state.pending = encoded
	return uint64(len(encoded))
}

// hostTake copies the pending SandboxResult into the guest's buffer.
func hostTake(ctx context.Context, m api.Module, ptr, size uint32) uint32 {
	state := stateOf(ctx)
	if state == nil || int(size) != len(state.pending) || !m.Memory().Write(ptr, state.pending) {
		return 1
	}
	wipe(state.pending)
	state.pending = nil
	return 0
}

// perform runs op through the connector's gated sandbox.
func perform(ctx context.Context, sb connector.Sandbox, op abi.SandboxOp) abi.SandboxResult {
	fail := func(err error) abi.SandboxResult { return abi.SandboxResult{Error: abi.Encode(err)} }
	switch op.Op {
	case abi.SandboxSend:
		return fail(sb.Send(op.Target, op.Payload))
	case abi.SandboxReadFile:
		data, err := sb.ReadFile(op.Path)
		if err != nil {
			return fail(err)
		}
		return abi.SandboxResult{Data: data}
	case abi.SandboxWriteFile:
		return fail(sb.WriteFile(op.Path, op.Data))
	case abi.SandboxExec:
		return fail(sb.Exec(op.Name, op.Args...))
	case abi.SandboxHTTP:
		if op.Request == nil {
			return fail(errors.New("connector sandbox: http operation without a request"))
		}
		var requestBody io.Reader
		if op.Request.HasBody {
			requestBody = bytes.NewReader(op.Request.Body)
		}
		req, err := http.NewRequestWithContext(ctx, op.Request.Method, op.Request.URL, requestBody)
		if err != nil {
			return fail(err)
		}
		req.Header = op.Request.Header.Clone()
		if req.Header == nil {
			req.Header = http.Header{}
		}
		resp, err := sb.Request(req)
		if err != nil {
			return fail(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(io.LimitReader(resp.Body, abi.MaxBodyBytes+1))
		if err != nil {
			return fail(err)
		}
		if len(body) > abi.MaxBodyBytes {
			return fail(fmt.Errorf("connector sandbox: response body exceeds %d bytes", abi.MaxBodyBytes))
		}
		return abi.SandboxResult{Response: &abi.HTTPResponse{StatusCode: resp.StatusCode, Header: resp.Header.Clone(), Body: body}}
	}
	return fail(fmt.Errorf("connector sandbox: unknown sandbox operation %q", op.Op))
}

func wipe(b []byte) { clear(b) }

// randomSource feeds WASI random_get from the crypto boundary (AN-3).
type randomSource struct{}

func (randomSource) Read(p []byte) (int, error) {
	b, err := crypto.RandomBytes(len(p))
	if err != nil {
		return 0, err
	}
	n := copy(p, b)
	clear(b)
	return n, nil
}

// Bind returns built's family running inside the sandbox: a connector with the
// same name, grant and optional operations as built, whose code executes in the
// module. credentials are the references built resolved, by reference; the
// module receives exactly those for each operation. built itself never runs an
// operation; it supplies the name, the grant and Close.
func (r *Runtime) Bind(built connector.Connector, family string, config native.Target, credentials map[string][]byte) (connector.Connector, error) {
	if r == nil || built == nil {
		return nil, errors.New("connector sandbox: nothing to bind")
	}
	b := &bound{rt: r, native: built, family: family, config: config, credentials: credentials}
	return b.withOperations(built)
}
