// SPDX-License-Identifier: MPL-2.0

// Package pluginhost is the in-process WASM plugin sandbox (wazero/extism) used
// by both CA plugins and deployment connectors (F20).
//
// Plugins run under capability-based grants (for example, "write filesystem
// only at path X") that they cannot exceed at runtime: each plugin loads in its
// own wazero runtime with no ambient syscalls, and the only privileged
// operations available are host functions gated by the grant. Every invocation
// is submitted to a shared bounded pool, so a slow or flooded plugin cannot
// starve the platform (AN-7). The conformance suite validates that a plugin
// meets the host contract before it is admitted.
package pluginhost
