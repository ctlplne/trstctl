# trstctl security patch

This directory is a minimal source copy of
`github.com/fergusstrange/embedded-postgres` v1.29.0 under its MIT license.

The only behavior change replaces the library's startup and health-check
connection from `github.com/lib/pq` with the already-reviewed
`github.com/jackc/pgx/v5/stdlib` driver. The upstream library otherwise links
`lib/pq` into the shipped control plane; the Go vulnerability database marks
every published `lib/pq` version affected by GO-2026-6166, GO-2026-6168,
GO-2026-6170, GO-2026-6171, and GO-2026-6172, with no fixed release.

Keep the upstream version pinned at v1.29.0 until the PostgreSQL binary
provenance manifest and all architecture hashes move together. Remove this
patch only after upstream removes `lib/pq` and the complete bundled-PostgreSQL
and supply-chain gates pass.
