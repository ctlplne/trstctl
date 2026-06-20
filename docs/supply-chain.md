# Supply chain

trstctl ships with a signed, attested, scanned supply chain. This page is the
single source of truth for **what is signed, what is scanned, and how you verify
it**. Nothing here is aspirational — each gate runs in CI, and the scan results
are recorded below.

## Signed, reproducible releases

A version tag (`vX.Y.Z`) drives `.github/workflows/release.yml`, which:

- builds a **reproducible** distroless image (`CGO_ENABLED=0`, `-trimpath`,
  layer timestamps pinned to the commit) under an **80 MB** size budget;
- pushes it to **GHCR** (with an optional Docker Hub mirror);
- generates **build provenance** (`provenance: true`);
- attaches a **CycloneDX SBOM** of the image; and
- **cosign-signs** the image and **attests the SBOM** keylessly via GitHub OIDC —
  no long-lived signing key to leak.

> Publishing happens on a real tag push. The pipeline itself is exercised in CI on
> every change (build, size gate, SBOM generation), and the signing/attestation
> steps run on the tag. The signature is verifiable by anyone (below).

### Verify a published image (signature-on-install)

```bash
scripts/verify-image.sh ghcr.io/imfeelingtheagi/trstctl:<tag>
```

This confirms the image was signed by **this repo's release workflow** (the cosign
certificate identity is the workflow, asserted by GitHub's OIDC issuer) and that it
carries the **CycloneDX SBOM** attestation. Only an image built by
`release.yml` verifies.

For Kubernetes production admission, use digest-pinned image references plus the
Sigstore policy-controller example in `deploy/kubernetes/sigstore-policy.yaml`.
It admits only `ghcr.io/imfeelingtheagi/trstctl@sha256:*` images signed by this
repository's release workflow identity.

## Software-composition analysis (every dependency surface)

Dependencies live on three surfaces; two of them are **outside `go.sum`**, so they
get their own scans. All three run in CI and via `make sca`.

### Go modules — `govulncheck` (pinned, reachability-aware)

`govulncheck` is **pinned to `@v1.1.4`** (in `ci.yml` and the `Makefile`) so the
gate is deterministic, not a moving `@latest`. It is reachability-aware: it fails
only on advisories the code can actually call.

The Go standard library is part of the shipped artifact, so the build toolchain is
also pinned. `go.mod` requires `go 1.26.0` with `toolchain go1.26.4`, the Docker
build stage defaults to `GO_VERSION=1.26.4`, and CI/release use
`go-version-file: go.mod`. That keeps local, CI, release, and container builds on
the patched standard library line.

```
$ go version
go version go1.26.4 darwin/arm64

$ govulncheck ./...
=== Symbol Results ===
No vulnerabilities found.
Your code is affected by 0 vulnerabilities.
(advisories can exist in imported modules, but none are reachable from trstctl's code.)
```

### npm (web UI) — `npm audit`

The web dependency tree is pinned by `web/package-lock.json` and scanned with
`npm audit --omit=dev --audit-level=high` in the CI `web` job.

```
$ npm audit --omit=dev
found 0 vulnerabilities   (300 production dependencies)
```

### embedded-postgres binary — committed checksum pin (CI **and** runtime) + Trivy

The `embedded-postgres` dependency downloads a real **PostgreSQL 16.4.0** binary
from **Maven Central** at runtime — outside `go.sum`. It is used both by the
integration tests **and by the served single-node/eval path**
(`internal/server/startBundledPostgres`), so its provenance is **committed and
enforced at runtime**, not merely scanned in CI (SUPPLY-003):

- `deploy/supply-chain/embedded-postgres.json` records the exact version, Maven
  coordinates, source URLs, and a **committed per-arch SHA-256 pin** for both the
  Maven `jar` and the inner `.txz` archive the library caches and extracts. The pin
  is **populated** (the trust-on-first-use bootstrap is complete), so the gate is a
  hard fail, not a no-op. The shipped pins cover linux/amd64, linux/arm64, and
  darwin/arm64 local developer gates using the same archive names the
  `embedded-postgres` library fetches.
- `internal/server/bundled_pg_pins.go` carries the same per-arch `.txz` pins that
  the **served binary enforces at runtime**: before starting bundled PostgreSQL,
  `startBundledPostgres` verifies the cached `.txz` against the committed pin and
  **refuses to start a tampered or MITM'd binary**, fail-closed. This is independent
  of the library's same-origin `.sha256` sidecar, so a Maven/MITM compromise serving
  a matching jar+sidecar is still caught. `TestRuntimePinsMatchManifest` asserts the
  Go pins and the JSON manifest never drift.
- `scripts/supply-chain/verify-embedded-postgres.sh` (CI `supply-chain` job)
  verifies the downloaded jar **and** its inner `.txz` against the committed pins
  (failing the build on any change) and **Trivy-scans** the extracted binaries for
  HIGH/CRITICAL issues. CI stores `embedded-postgres-trivy-receipt`, containing the
  raw Trivy JSON report, Trivy version/DB metadata, severity counts, and a compact
  pass/fail receipt. HIGH and non-fixable CRITICAL findings are recorded; any
  **fixable CRITICAL** finding fails the gate because a patched upstream binary is
  available and the committed pin must move. CI defaults to `ARCH=linux-amd64`;
  developers can also run `ARCH=darwin-arm64v8
  scripts/supply-chain/verify-embedded-postgres.sh` when refreshing the macOS
  local-test pin.

This binary is **not** bundled in the shipped distroless image (which carries only
the Go binaries); it is fetched on first run of the bundled single-node/eval path.

## SBOMs

Two CycloneDX SBOMs are produced:

- the **image SBOM** the release attaches and cosign attests; and
- a **module SBOM** of the Go dependency graph (`make sbom`, uploaded by the CI
  `supply-chain` job).

## CI security & quality gates

Beyond SCA, CI enforces a security and quality bar on every pull request, repo-wide,
so a regression cannot merge. Each gate *fails the build*, not merely reports:

- **SAST — CodeQL** (`.github/workflows/codeql.yml`): static analysis of the Go and
  web-UI code with the `security-extended` query suite, on every PR, on pushes to
  `main`, and weekly.
- **Secret scanning — gitleaks** (`.github/workflows/security.yml`, `.gitleaks.toml`,
  `.gitleaksignore`): scans the full history against gitleaks' default ruleset.
  The only allowlisted matches are deterministic PEM test vectors under
  `_test.go`/`testdata`, the published connector conformance keypair pinned by
  exact body, and its old placeholder pinned by exact historical fingerprint; a
  hardcoded secret outside those narrow fixtures fails CI.
- **Dependency vulnerabilities**: the pinned `govulncheck` job (above) plus
  **Dependabot** (`.github/dependabot.yml`) raising update PRs for Go modules, npm,
  GitHub Actions, and the Docker base.
- **Container image scanning — Trivy** (`.github/workflows/security.yml`): builds the
  runtime image from **digest-pinned** builder and runtime bases (never floating
  tags) and fails on any fixable HIGH/CRITICAL vulnerability — this is what catches
  a vulnerable base image. `scripts/ci/check-base-pinned.sh` guards that the release
  path pins both `BUILD_IMAGE` and `BASE_IMAGE` by digest.
- **Critical-package coverage gate** (`make test` → `scripts/ci/coverage-critical.sh`):
  in addition to the repo-wide coverage floor, **each** security-critical package
  (crypto boundary, issuance, outbox, RLS store, signing, revocation) must independently
  meet `CRITICAL_COVERAGE_MIN`, computed from the merged `-coverpkg` profile — so a
  critical package cannot hide behind the aggregate average.

The architecture linter (`trstctllint`) and the workflow linter (`actionlint`) remain
required. The full set of **required status checks**, plus enforce-admins, linear
history, and code-owner review, is now **codified in the repository** — see
[Branch protection & required checks](branch-protection.md) for the exact list and
[`.github/branch-protection.json`](https://github.com/imfeelingtheagi/trstctl/blob/main/.github/branch-protection.json)
for the machine-applicable form (a repo admin applies it once; a reality-test keeps
the required-check list in sync with the CI job names). Code ownership of the
root-of-trust paths is codified in
[`.github/CODEOWNERS`](https://github.com/imfeelingtheagi/trstctl/blob/main/.github/CODEOWNERS).

## Run it yourself

```bash
make supply-chain   # module SBOM + Go/npm/embedded-postgres SCA (network needed for the PG leg)
make vuln           # just the pinned govulncheck gate
make sbom           # just the module SBOM
make coverage-critical   # per-package coverage gate on the critical set (needs cover.out from `make test`)
```

See `deploy/supply-chain/README.md` for the per-surface summary table.
