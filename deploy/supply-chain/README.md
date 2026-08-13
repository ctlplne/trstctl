# Supply-chain artifacts

trstctl's dependencies span five concrete surfaces, and **all five are scanned** —
four of them live outside `go.sum`, so they are easy to miss. The npm rows are not
maintained by hand: `TestSupply105NpmAuditSurfacesMatchTrackedPackageJSON` derives
the required set from the tree and fails if a package.json exists without a
lockfile, a scanner entry, and a Dependabot entry:

| Surface | What pins it | What scans it |
|---|---|---|
| Go modules | `go.sum` (fully pinned) | `govulncheck` (pinned `@v1.6.0` by `GOVULNCHECK_VERSION` in the `Makefile`), reachability-aware, `make vuln` / CI |
| npm (web UI) | `web/package-lock.json` | pinned `npm@11.16.0 audit --omit=dev --audit-level=high`, CI `web` job + `scripts/ci/npm-audit-dependency-surfaces.sh` severity-count receipt / `make sca` |
| npm (TypeScript SDK generator) | `clients/sdk/typescript/package-lock.json` | `scripts/ci/npm-audit-dependency-surfaces.sh` with dev deps included, severity-count receipt, CI `supply-chain` job / `make sca` |
| npm (Pulumi IaC example) | `deploy/iac/pulumi/trstctl-resources/package-lock.json` | `scripts/ci/npm-audit-dependency-surfaces.sh` with dev deps included, severity-count receipt, CI `supply-chain` job / `make sca` |
| embedded-postgres binary | `embedded-postgres.json` (this dir) + `bundledPGVersion` in the served bundled eval path; `embeddedpostgres.V16` in the integration tests | checksum-pin + Trivy + fresh official PostgreSQL CNA catalog, CI `supply-chain` job / `scripts/supply-chain/verify-embedded-postgres.sh` |

## `embedded-postgres.json`

The `embedded-postgres` dependency downloads a real PostgreSQL binary from
Maven Central at runtime for integration tests and for the served bundled
single-node eval path — that binary is **not** covered by `go.sum`. This manifest
pins its exact version and per-arch sources, and records the checksum + scan
policy. `scripts/supply-chain/verify-embedded-postgres.sh` enforces it:

1. Downloads the pinned PostgreSQL binary from the recorded URL.
2. Computes its SHA-256 and fails the build if the jar or inner `.txz` hash
   changes for the pinned version. The trust-on-first-use bootstrap is complete;
   empty pins are a hard failure.
3. Extracts and Trivy-scans the binaries (HIGH/CRITICAL, ignore-unfixed), then
   evaluates the exact pin against a fresh official PostgreSQL CNA catalog.
   Each `embedded-postgres-trivy-receipt-<arch>` artifact retains raw Trivy JSON,
   Trivy/DB metadata, the raw official page and hash, normalized advisories, and
   matched rows. Fixable Trivy HIGH/CRITICAL findings and official HIGH/CRITICAL
   advisories fixed after the pin fail. A Maven wrapper coordinate is not server
   vulnerability coverage by itself.

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
distroless image, attaches a CycloneDX SBOM, generates build provenance,
and cosign-signs it keylessly (OIDC). Verify a published image with
`scripts/verify-image.sh` (or the `cosign verify` snippet in
[`docs/install.md`](../../docs/install.md)). The full story is in
[`docs/supply-chain.md`](../../docs/supply-chain.md).
