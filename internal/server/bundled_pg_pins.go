// SPDX-License-Identifier: BUSL-1.1

package server

// Committed provenance pins for the embedded PostgreSQL binary (SUPPLY-003).
//
// The bundled single-node/eval path (startBundledPostgres) runs a third-party
// PostgreSQL binary that the fergusstrange/embedded-postgres library downloads
// from Maven Central. That binary lives OUTSIDE go.sum (it is not a Go module), so
// it carries no module-checksum protection, and the library's ONLY integrity check
// is a SAME-ORIGIN `.sha256` sidecar fetched from the same Maven URL — which a
// Maven/MITM compromise serving a matching jar+sidecar would defeat. To close
// that, we pin the SHA-256 of the per-arch `.txz` archive the library caches and
// extracts, COMMITTED here (independent of Maven), and require authenticated acquisition before startup. NewVerifiedDatabase
// independently hashes its exact bytes and derives a fresh private executable
// tree; a cached bin/ directory never establishes trust.
//
// These hashes are the human-readable manifest's `archives[].txz_sha256` values in
// deploy/supply-chain/embedded-postgres.json; TestBundledPGPinsMatchManifest
// asserts the two never drift. Keys are the embedded-postgres cache-file arch
// segment, i.e. `<os>-<arch>` where <arch> follows the library's naming
// (amd64, arm64v8, …) — see archiveArch().
var bundledPGTxzSHA256 = map[string]string{
	// PostgreSQL 16.16.0, linux/amd64 — the single-node/eval default.
	"linux-amd64": "5249931b61bf525f65bc79c5e108f83393351c40bd9e1a2f7fd0608f1ef553e5",
	// PostgreSQL 16.16.0, linux/arm64 (zonky names it arm64v8).
	"linux-arm64v8": "b62bf0b4094df8e6bedb66b7aaaf81526f7f9cec227542ac99ce64ec836be784",
	// PostgreSQL 16.16.0, darwin/arm64 (zonky names it arm64v8).
	"darwin-arm64v8": "4b1a2377d4d647bde3ff5581c9d1af48aae3a57f5cd4e00171007555c47bcba3",
}

// bundledPGVersion is the pinned PostgreSQL version. It must equal
// postgresVersion in deploy/supply-chain/embedded-postgres.json
// (TestRuntimePinsMatchManifest asserts that).
//
// startBundledPostgres passes this constant to embeddedpostgres.Version()
// DIRECTLY, and deliberately not the library's embeddedpostgres.V16 constant.
// The fork's V16 now also names 16.16.0, but it remains a SECOND source of truth: bundledPGCacheArchive
// builds the cache filename from bundledPGVersion, so if the two ever disagreed
// the library would download and cache under a different name, the provenance
// check would find nothing at the pinned path. A missing archive is explicitly
// unverified: the served wrapper acquires it and requires a second true result
// before Start. One version source also keeps acquisition and the pin aligned.
const bundledPGVersion = "16.16.0"
