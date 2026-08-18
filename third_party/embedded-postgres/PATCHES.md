# trstctl security patch

This directory is a minimal source copy of
`github.com/fergusstrange/embedded-postgres` v1.29.0 under its MIT license. It is
compiled as `trstctl.com/trstctl/third_party/embedded-postgres`, not as a replaced
Go module, so its download checksum can route through the mandatory
`internal/crypto` boundary.

The behavior changes replace the library's startup and health-check
connection from `github.com/lib/pq` with the already-reviewed
`github.com/jackc/pgx/v5/stdlib` driver. The upstream library otherwise links
`lib/pq` into the shipped control plane; the Go vulnerability database marks
every published `lib/pq` version affected by GO-2026-6166, GO-2026-6168,
GO-2026-6170, GO-2026-6171, and GO-2026-6172, with no fixed release.

The fork also makes the Maven `.sha256` sidecar mandatory, fixes the upstream
nil-response cleanup path when that fetch fails, and computes the archive digest
through `internal/crypto`. The served bundled-database path independently checks
the extracted archive against the repository's per-platform digest before it can
start.

Keep the upstream version pinned at v1.29.0 until the PostgreSQL binary
provenance manifest and all architecture hashes move together. Remove this
patch only after upstream removes `lib/pq` and the complete bundled-PostgreSQL
and supply-chain gates pass.
