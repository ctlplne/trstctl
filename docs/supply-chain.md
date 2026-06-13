# Supply chain

trustctl ships with a signed, attested, scanned supply chain. This page is the
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
scripts/verify-image.sh ghcr.io/imfeelingtheagi/trustctl:<tag>
```

This confirms the image was signed by **this repo's release workflow** (the cosign
certificate identity is the workflow, asserted by GitHub's OIDC issuer) and that it
carries the **CycloneDX SBOM** attestation. Only an image built by
`release.yml` verifies.

## Software-composition analysis (every dependency surface)

Dependencies live on three surfaces; two of them are **outside `go.sum`**, so they
get their own scans. All three run in CI and via `make sca`.

### Go modules — `govulncheck` (pinned, reachability-aware)

`govulncheck` is **pinned to `@v1.1.4`** (in `ci.yml` and the `Makefile`) so the
gate is deterministic, not a moving `@latest`. It is reachability-aware: it fails
only on advisories the code can actually call.

```
$ govulncheck ./...
=== Symbol Results ===
No vulnerabilities found.
Your code is affected by 0 vulnerabilities.
(2 advisories exist in imported packages but are not reachable from trustctl's code.)
```

### npm (web UI) — `npm audit`

The web dependency tree is pinned by `web/package-lock.json` and scanned with
`npm audit --omit=dev --audit-level=high` in the CI `web` job.

```
$ npm audit --omit=dev
found 0 vulnerabilities   (300 production dependencies)
```

### embedded-postgres binary — checksum-pin + Trivy

The `embedded-postgres` test dependency downloads a real **PostgreSQL 16.4.0**
binary from **Maven Central** at runtime — outside `go.sum`. It is pinned and
scanned:

- `deploy/supply-chain/embedded-postgres.json` records the exact version, Maven
  coordinates, source URL, and the checksum/scan policy.
- `internal/projections/projections_test.go` pins `embeddedpostgres.V16`, so the
  scanned binary is the binary the tests actually run.
- `scripts/supply-chain/verify-embedded-postgres.sh` (CI `supply-chain` job)
  checksum-pins it (trust-on-first-use: fail the build if it ever changes) and
  **Trivy-scans** the extracted binaries for HIGH/CRITICAL issues.

This binary is integration-test only; it is **not** bundled in the shipped image.

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
- **Secret scanning — gitleaks** (`.github/workflows/security.yml`, `.gitleaks.toml`):
  scans the full history against gitleaks' default ruleset. The only allowlisted
  matches are deterministic PEM test vectors under `_test.go`/`testdata`; production
  source is scanned by every rule, so a hardcoded secret there fails CI.
- **Dependency vulnerabilities**: the pinned `govulncheck` job (above) plus
  **Dependabot** (`.github/dependabot.yml`) raising update PRs for Go modules, npm,
  GitHub Actions, and the Docker base.
- **Container image scanning — Trivy** (`.github/workflows/security.yml`): builds the
  runtime image from a **digest-pinned** base (never a floating tag) and fails on any
  fixable HIGH/CRITICAL vulnerability — this is what catches a vulnerable base image.
  `scripts/ci/check-base-pinned.sh` guards that the release path stays digest-pinned.
- **Critical-package coverage gate** (`make test` → `scripts/ci/coverage-critical.sh`):
  in addition to the repo-wide coverage floor, **each** security-critical package
  (crypto boundary, issuance, outbox, RLS store, signing, revocation) must independently
  meet `CRITICAL_COVERAGE_MIN`, computed from the merged `-coverpkg` profile — so a
  critical package cannot hide behind the aggregate average.

The architecture linter (`trustctllint`) and the workflow linter (`actionlint`) remain
required. Marking all of these as **required status checks** on the default branch is a
one-time repository setting (branch protection), done by a repo admin.

## Run it yourself

```bash
make supply-chain   # module SBOM + Go/npm/embedded-postgres SCA (network needed for the PG leg)
make vuln           # just the pinned govulncheck gate
make sbom           # just the module SBOM
make coverage-critical   # per-package coverage gate on the critical set (needs cover.out from `make test`)
```

See `deploy/supply-chain/README.md` for the per-surface summary table.
