// Package pluginhost is the in-process WASM plugin sandbox (wazero/extism) used
// by both CA plugins and deployment connectors (F20).
//
// Plugins run under capability-based grants (for example, "write filesystem
// only at path X") that they cannot exceed at runtime, and the host is
// bulkheaded per AN-7. Implementation begins in sprint S4.2; this file reserves
// the package.
package pluginhost
