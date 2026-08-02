// SPDX-License-Identifier: MPL-2.0

// Package pluginhost is the in-process WASM plugin sandbox (wazero/extism) used
// by both CA plugins and deployment connectors (F20).
//
// Plugins run under capability-based grants (for example, "write filesystem
// only at path X") that they cannot exceed: each plugin loads in its own wazero
// runtime with no ambient syscalls, and the only privileged operations available
// are host functions gated by the grant.
//
// The grant shapes the environment rather than merely being consulted by it. The
// "env" module exports one function per GRANTED capability and nothing else, so a
// guest importing a capability it was not given fails to instantiate and never
// executes an instruction.
//
// Path grants are enforced twice, and both halves are required. Grant.Allows is
// lexical (see capability.go); the sandbox then performs the I/O through an
// os.Root opened at the granted prefix (see sandbox.go), so a symlink inside the
// prefix that points outside it is refused when the path is resolved. A caller
// that consults Allows and then opens the path by name has re-opened that escape.
//
// Every invocation is submitted to a shared bounded pool, so a slow or flooded
// plugin cannot starve the platform (AN-7). The conformance suite validates that
// a plugin meets the host contract before it is admitted.
package pluginhost
