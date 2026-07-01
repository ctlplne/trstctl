# Supply-chain artifacts

trstctl's dependencies span three surfaces, and **all three are scanned** — two of
them live outside `go.sum`, so they are easy to miss:

| Surface | What pins it | What scans it |
|---|---|---|
| Go modules | `go.sum` (fully pinned) | `govulncheck` (pinned `@v1.1.4`), reachability-aware, `make vuln` / CI |
| npm (web UI) | `web/package-lock.json` | `npm audit --omit=dev --audit-level=high`, CI `web` job / `make sca` |
| embedded-postgres binary | `embedded-postgres.json` (this dir) + `embeddedpostgres.V16` in the tests and bundled eval path | checksum-pin + Trivy, CI `supply-chain` job / `scripts/supply-chain/verify-embedded-postgres.sh` |

## `embedded-postgres.json`

The `embedded-postgres` dependency downloads a real PostgreSQL binary from
**Maven Central** at runtime for integration tests and for the served bundled
single-node eval path — that binary is **not** covered by `go.sum`. This manifest
pins its exact version and per-arch sources, and records the checksum + scan
policy. `scripts/supply-chain/verify-embedded-postgres.sh` enforces it:

1. Downloads the pinned PostgreSQL binary from the recorded URL.
2. Computes its SHA-256 and **fails the build** if the jar or inner `.txz` hash
   changes for the pinned version. The trust-on-first-use bootstrap is complete;
   empty pins are a hard failure.
3. Extracts and Trivy-scans the binaries (HIGH/CRITICAL, ignore-unfixed), writing
   one `embedded-postgres-trivy-receipt-<arch>` CI artifact per pinned
   architecture: raw Trivy JSON, Trivy version/DB metadata, and HIGH/CRITICAL
   counts. Fixable CRITICAL findings fail; HIGH and non-fixable CRITICAL findings
   are recorded for audit.

The manifest currently covers `linux-amd64`, `linux-arm64v8`, and
`darwin-arm64v8`. Run a non-default architecture with, for example:

```bash
ARCH=darwin-arm64v8 scripts/supply-chain/verify-embedded-postgres.sh
```

It is **not** bundled in the shipped distroless image; the bundled eval path
fetches it on first use and the runtime verifies the cached `.txz` against the
committed per-arch pin before trusting it. Run the whole pass locally with
`make supply-chain` (needs network for the embedded-postgres leg).

## Release signing & SBOM

The release pipeline (`.github/workflows/release.yml`) builds a reproducible
distroless image, attaches a **CycloneDX SBOM**, generates **build provenance**,
and **cosign-signs** it keylessly (OIDC). Verify a published image with
`scripts/verify-image.sh` (or the `cosign verify` snippet in
[`docs/install.md`](../../docs/install.md)). The full story is in
[`docs/supply-chain.md`](../../docs/supply-chain.md).
