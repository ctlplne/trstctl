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
nil-response cleanup path when that fetch fails, and computes archive digests
through `internal/crypto`. That sidecar establishes transport integrity only.

The served bundled-database path requires an explicit platform, version and
committed archive identity. Acquisition is bounded; the independent checksum
must match before extraction or any PostgreSQL executable runs. Each startup
derives a fresh private executable tree from authenticated bytes, checks TAR
paths, links, types and expansion bounds, and publishes only the complete tree.
Version/digest cache identity and verified publication prevent stale extracted
binaries from being accepted on a later start. Existing data and legacy caches
are preserved. Failure cleanup removes only resources created by this path.

The legacy `NewDatabase` API remains separately scoped to existing test fixtures
and developer performance tools, including explicit `V16` (16.4.0) users. It
does not acquire the served path's provenance guarantee by sharing this source
directory. The startup-order regressions exercise `startBundledPostgres`; they
do not establish provenance or extraction safety for those legacy callers.

Keep the upstream version pinned at v1.29.0 until the PostgreSQL binary
provenance manifest and all architecture hashes move together. Remove this
patch only after upstream removes `lib/pq` and the complete bundled-PostgreSQL
and supply-chain gates pass.

The served wrapper additionally holds an `OpenVerifiedCache` namespace through acquisition/startup. The operator-selected temporary anchor must be private, or root/current-user-owned and sticky; rooted child creation rejects links, foreign ownership and shared write access. Generic legacy `NewDatabase` cache behavior remains a separate finding. Actual wrapper regressions check ancestor rejection before acquisition, invalid port rejection, and native Stop errors.
