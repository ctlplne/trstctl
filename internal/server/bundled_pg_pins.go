// SPDX-License-Identifier: MPL-2.0

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
// extracts, COMMITTED here (independent of Maven), and verify the cached artifact
// against this pin before trusting the binary (see verifyBundledPostgresProvenance).
//
// These hashes are the human-readable manifest's `archives[].txz_sha256` values in
// deploy/supply-chain/embedded-postgres.json; TestBundledPGPinsMatchManifest
// asserts the two never drift. Keys are the embedded-postgres cache-file arch
// segment, i.e. `<os>-<arch>` where <arch> follows the library's naming
// (amd64, arm64v8, …) — see archiveArch().
var bundledPGTxzSHA256 = map[string]string{
	// PostgreSQL 16.4.0, linux/amd64 — the production single-node/eval default.
	"linux-amd64": "d24cafae863e1ba9502bdc27942661391748ce60345725e7a15429be637fc8b6",
	// PostgreSQL 16.4.0, linux/arm64 (zonky names it arm64v8).
	"linux-arm64v8": "5b8a4b595f847ef11d47c51f40de713ff0ef335aa86f668677470d43c681f47b",
	// PostgreSQL 16.4.0, darwin/arm64 (zonky names it arm64v8).
	"darwin-arm64v8": "2805111c0e325e191be8eb4290e0e45930cd30250a864ca30b385d828ae7b309",
}

// bundledPGVersion is the pinned PostgreSQL version (must match
// embeddedpostgres.V16 used in startBundledPostgres and the supply-chain manifest).
const bundledPGVersion = "16.4.0"
