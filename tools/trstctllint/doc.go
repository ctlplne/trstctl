// SPDX-License-Identifier: BUSL-1.1

// Command trstctllint is the trstctl architecture linter: a go/analysis
// multichecker that makes the architectural non-negotiables un-violable and is
// wired CI-blocking through `make lint`.
//
// It bundles ten analyzers, each implemented and tested in its own subpackage:
//
//   - cryptoboundary (AN-3): crypto/* may be imported only inside internal/crypto.
//   - tenantfilter   (AN-1): repository SQL queries must filter on tenant_id.
//   - keymaterial    (AN-8): key-handling packages must not use string for key material.
//   - idempotency    (AN-5): mutating handlers must thread an idempotency key into a dedupe sink.
//   - eventsource    (AN-2): a served mutation must not write the read model directly; it emits an event.
//   - cryptoagility  (PQC-00): crypto/signer code must not grow runtime plugin/provider/engine registries.
//   - netexec        (SEC-005): new HTTP/exec surfaces must use SSRF-safe clients (netsec/egress) or reviewed argv paths; ambient http.Client construction and the http.Get/Post package helpers fail closed too.
//   - licenseboundary (PACKAGING-007): core files carry BUSL-1.1 SPDX, clients/ files carry MPL-2.0, ee/ files carry the proprietary SPDX, core cannot import ee/, and PQC algorithms/fleet execution stay out of core while CBOM campaign records remain core.
//   - tlsverify      (SEC-CWE-295): InsecureSkipVerify may be set only in internal/crypto/tlsprobe (the discovery prober), the mtls loopback liveness probe, and _test.go files.
//   - upsertarbiter (OPP-C01): an ON CONFLICT upsert into a table with a second unique index must serialize or retry on unique_violation.
//
// As built by multichecker, the binary runs standalone over the module
//
//	go run ./tools/trstctllint ./...
//
// and also works as a `go vet -vettool`. Per-analyzer flags are available, for
// example `trstctllint -tenantfilter=false ./...` to run a single rule.
//
// Escape hatch: there is deliberately no per-line suppression (no //nolint, no
// blanket ignore). The only sanctioned way to resolve a false positive is to
// fix the offending rule in this package together with a test fixture. See
// README.md.
package main
