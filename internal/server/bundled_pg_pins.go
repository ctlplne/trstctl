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
	// PostgreSQL 16.15.0, linux/amd64 — the single-node/eval default.
	"linux-amd64": "bda67fe32e23b049c25db4b98132d154a4fa824c44e1bd8fd01b0236f4676c24",
	// PostgreSQL 16.15.0, linux/arm64 (zonky names it arm64v8).
	"linux-arm64v8": "e66afbea65a143aa6cda8d5a56c2aea9985d1d9649dfb29ba487363844fd1f81",
	// PostgreSQL 16.15.0, darwin/arm64 (zonky names it arm64v8).
	"darwin-arm64v8": "07f29aed5baae53962b0ab80c901763b490b5692cf6a730cb3ece6bf455567af",
}

// bundledPGVersion is the pinned PostgreSQL version. It must equal
// postgresVersion in deploy/supply-chain/embedded-postgres.json
// (TestRuntimePinsMatchManifest asserts that).
//
// startBundledPostgres passes this constant to embeddedpostgres.Version()
// DIRECTLY, and deliberately not the library's embeddedpostgres.V16 constant.
// V16 is frozen at 16.4.0 in v1.29.0 — a release affected by CVE-2024-10979
// (CVSS 8.8) — and, worse, it is a SECOND source of truth: bundledPGCacheArchive
// builds the cache filename from bundledPGVersion, so if the two ever disagreed
// the library would download and cache under a different name, the provenance
// check would find nothing at the pinned path, take the documented cold-cache
// (false, nil) branch, and start an unverified binary. One source of truth keeps
// SUPPLY-003 from silently degrading into a no-op.
const bundledPGVersion = "16.15.0"
