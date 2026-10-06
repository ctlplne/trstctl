# trstctl security patch

This directory is a minimal source copy of
`github.com/fergusstrange/embedded-postgres` v1.34.0 under its MIT license
(Go module sum `h1:c6RKhPKFsLVU+Tdxsx8q0UxCHsvZZ/iShAnljRBXs6s=`). It is
compiled as `trstctl.com/trstctl/third_party/embedded-postgres`, not as a replaced
Go module, so its download checksum can route through the mandatory
`internal/crypto` boundary.

The upstream v1.34.0 lifecycle error sentinels, missing `bin/pg_ctl` check,
new version constants and nested runtime directory creation are included.
The upstream archive fetch's nil-response fix is subsumed by the fork's bounded,
fail-closed fetch. The fork's legacy `pg_ctl` options use v1.34.0 double-quote
semantics for Windows. Its default and `V16` select the committed, separately
vetted PostgreSQL 16.15.0 archive instead of upstream's unpinned 18.3.0 default
and 16.9.0 V16. The served wrapper passes `bundledPGVersion` explicitly and
does not trust this mutable library constant as its archive identity.

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
and developer performance tools, including explicit `V16` (16.15.0) users. It
does not acquire the served path's provenance guarantee by sharing this source
directory. The startup-order regressions exercise `startBundledPostgres`; they
do not establish provenance or extraction safety for those legacy callers.

The source version and PostgreSQL executable version are independent pins. The
v1.34.0 source rebase leaves the served 16.15.0 binary and its committed
per-platform archive digests unchanged; the source upgrade does not authorize a
new archive. Keep this patch while upstream still imports `lib/pq`, and retain
separate checksum, official advisory and Trivy gates for the actual archive.

The served wrapper additionally holds an `OpenVerifiedCache` namespace through acquisition/startup. The operator-selected temporary anchor must be private, or root/current-user-owned and sticky; rooted child creation rejects links, foreign ownership and shared write access. Generic legacy `NewDatabase` cache behavior remains a separate finding. Actual wrapper regressions check ancestor rejection before acquisition, invalid port rejection, and native Stop errors.
