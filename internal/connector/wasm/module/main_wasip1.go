// SPDX-License-Identifier: BUSL-1.1

//go:build wasip1

// Command module is the first-party connector module: every shipped connector
// family, compiled for wasip1 as a reactor and run by the host inside wazero.
// It exports an allocator and one entry point; its only imports are the
// connector host functions (see package abi) and WASI's clock and random
// source.
package main

import (
	"encoding/json"
	"runtime"
	"unsafe"

	"trstctl.com/trstctl/internal/connector/wasm/abi"
	"trstctl.com/trstctl/internal/connector/wasm/guest"
)

//go:wasmimport trstctl_connector_host result
func hostResult(ptr, size uint32)

//go:wasmimport trstctl_connector_host sandbox
func hostSandbox(ptr, size uint32) uint64

//go:wasmimport trstctl_connector_host take
func hostTake(ptr, size uint32) uint32

// buffers keeps host-written allocations reachable until freed.
var buffers = map[uint32][]byte{}

func pointer(b []byte) uint32 {
	if len(b) == 0 {
		return 0
	}
	return uint32(uintptr(unsafe.Pointer(unsafe.SliceData(b))))
}

//go:wasmexport trstctl_alloc
func alloc(size uint32) uint32 {
	if size == 0 || size > abi.MaxCallBytes {
		return 0
	}
	buf := make([]byte, size)
	ptr := pointer(buf)
	buffers[ptr] = buf
	return ptr
}

//go:wasmexport trstctl_free
func free(ptr uint32) { delete(buffers, ptr) }

//go:wasmexport trstctl_call
func call(ptr, size uint32) uint32 {
	buf, ok := buffers[ptr]
	if !ok || int(size) > len(buf) {
		return 1
	}
	result := guest.Run(buf[:size], transport)
	out, err := json.Marshal(result)
	if err != nil || len(out) > abi.MaxResultBytes {
		out, _ = json.Marshal(abi.Result{Error: &abi.Error{Message: "connector module: the result could not be encoded"}})
	}
	hostResult(pointer(out), uint32(len(out)))
	runtime.KeepAlive(out)
	return 0
}

func transport(op abi.SandboxOp) abi.SandboxResult {
	req, err := json.Marshal(op)
	if err != nil || len(req) > abi.MaxOpBytes {
		return abi.SandboxResult{Error: &abi.Error{Message: "connector module: the sandbox operation could not be encoded"}}
	}
	packed := hostSandbox(pointer(req), uint32(len(req)))
	runtime.KeepAlive(req)
	if status := uint32(packed >> 32); status != 0 {
		return abi.SandboxResult{Error: &abi.Error{Message: "connector module: the host refused the sandbox operation"}}
	}
	size := uint32(packed)
	out := make([]byte, size)
	if size > 0 && hostTake(pointer(out), size) != 0 {
		return abi.SandboxResult{Error: &abi.Error{Message: "connector module: the host lost the sandbox result"}}
	}
	var res abi.SandboxResult
	if err := json.Unmarshal(out, &res); err != nil {
		return abi.SandboxResult{Error: &abi.Error{Message: "connector module: the sandbox result was malformed"}}
	}
	return res
}

func main() {}
