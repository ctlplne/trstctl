# Supply-chain artifacts

trstctl's dependencies span three surfaces, and **all three are scanned** — two of
them live outside `go.sum`, so they are easy to miss:

| Surface | What pins it | What scans it |
|---|---|---|
| Go modules | `go.sum` (fully pinned) | `govulncheck` (pinned `@v1.1.4`), reachability-aware, `make vuln` / CI |
| npm (web UI) | `web/package-lock.json` | `npm audit --omit=dev --audit-level=high`, CI `web` job / `make sca` |
| embedded-postgres binary | `embedded-postgres.json` (this dir) + `embeddedpostgres.V16` in the tests | checksum-pin + Trivy, CI `supply-chain` job / `scripts/supply-chain/verify-embedded-postgres.sh` |

## `embedded-postgres.json`

The `embedded-postgres` test dependency downloads a real PostgreSQL binary from
**Maven Central** at runtime — that binary is **not** covered by `go.sum`. This
manifest pins its exact version and source, and records the checksum + scan
policy. `scripts/supply-chain/verify-embedded-postgres.sh` enforces it:

1. Downloads the pinned PostgreSQL binary from the recorded URL.
2. Computes its SHA-256. On first run (empty `sha256`) it prints the value for a
   maintainer to pin and commit; thereafter it **fails the build** if the hash
   ever changes for the pinned version (trust-on-first-use).
3. Extracts and Trivy-scans the binaries (HIGH/CRITICAL, ignore-unfixed).

It is integration-test only and is **not** bundled in the shipped distroless
image. Run the whole pass locally with `make supply-chain` (needs network for the
embedded-postgres leg).

## Release signing & SBOM

The release pipeline (`.github/workflows/release.yml`) builds a reproducible
distroless image, attaches a **CycloneDX SBOM**, generates **build provenance**,
and **cosign-signs** it keylessly (OIDC). Verify a published image with
`scripts/verify-image.sh` (or the `cosign verify` snippet in
[`docs/install.md`](../../docs/install.md)). The full story is in
[`docs/supply-chain.md`](../../docs/supply-chain.md).
