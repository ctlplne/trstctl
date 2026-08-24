# Supply chain

trstctl ships a signed, attested, scanned supply chain. This page is the
source of truth for what is signed, what is scanned, and how to verify it —
nothing here is aspirational, and every gate below runs in CI.

## Signed, reproducible releases

A version tag (`vX.Y.Z`) drives `.github/workflows/release.yml`, which:

- builds a reproducible distroless image (`CGO_ENABLED=0`, `-trimpath`, layer
  timestamps pinned to the commit) under an 80 MB size budget;
- pushes it to GHCR (with an optional Docker Hub mirror);
- generates **BuildKit image provenance** (`provenance: true`) and attaches a
  **CycloneDX SBOM**;
- **cosign-signs** the image and attests the SBOM keylessly via GitHub
  OIDC — no long-lived signing key to leak; and
- uploads **SLSA in-toto provenance** for the container/manifest, the signed
  Windows agent, and the Helm chart.

> Publishing happens on a real tag push. The pipeline itself (build, size
> gate, SBOM generation) is exercised in CI on every change; the
> signing/attestation steps run on the tag, and the signature is verifiable
> by anyone (below).

### Verify a published image (signature-on-install)

```bash
scripts/verify-image.sh ghcr.io/ctlplne/trstctl:<tag>
```

This confirms the image was signed by this repo's release workflow (the
cosign certificate identity is the workflow, asserted by GitHub's OIDC
issuer) and that it carries the CycloneDX SBOM attestation. Only an image
built by `release.yml` verifies.

### Verify release SLSA provenance

Each tagged GitHub Release carries signed SLSA provenance from the official
`slsa-github-generator` workflow, whose subjects are the artifact digests
the release job computed from the actual published bytes. Download an
artifact plus its matching `*.intoto.jsonl` and run:

```bash
slsa-verifier verify-artifact trstctl-agent.msi \
  --provenance-path trstctl-agent-windows.intoto.jsonl \
  --source-uri github.com/ctlplne/trstctl \
  --source-tag vX.Y.Z
```

Use the container-and-manifest bundle for the container digest and rendered
Kubernetes agent manifest, and the Helm-chart bundle for the packaged chart.
The local release dry-run gate
(`scripts/release/slsa-dry-run_selftest.sh`) exercises the same subject
format offline, before a tag has GitHub OIDC available for the real DSSE
signature.

For Kubernetes production admission, use digest-pinned image references plus the
Sigstore policy-controller example in `deploy/kubernetes/sigstore-policy.yaml`. It
admits only `ghcr.io/ctlplne/trstctl@sha256:*` images signed by this
repository's release workflow identity.

## Software-composition analysis (every dependency surface)

Dependencies live on five concrete surfaces; four are outside `go.sum`, so
they get their own scans. All five run in CI and via `make sca`, and
`TestSupply105NpmAuditSurfacesMatchTrackedPackageJSON` fails the build if a new
npm surface appears without a lockfile, a scanner, and a Dependabot entry.

## Dependency freshness SLO

Vulnerability scanning (`govulncheck`, `npm audit`) answers "is a known
vulnerability reachable right now?" — freshness is a separate question: are
dependencies aging past their review budget? The committed report,
`deploy/supply-chain/dependency-freshness.json`, is checked by CI and `make
dependency-freshness` against `go list -m -u all`
and `npm outdated --json` discovery output. See
[Dependency freshness](security/dependency-freshness.md) for the SLO
classes, owner queue, and refresh procedure.

### Go modules — `govulncheck` (pinned, reachability-aware)

`govulncheck` is pinned to `@v1.6.0` by a single variable —
`GOVULNCHECK_VERSION` in the `Makefile` — and both the CI job and the release
pipeline consume that one pin by running `make vuln`, so the gate is
deterministic (not a moving `@latest`) and CI cannot silently scan with a
different version than a local run. It is reachability-aware: it fails only on
advisories the code can actually call.

The Go standard library is part of the shipped artifact, so the build
toolchain is also pinned: `go.mod` requires `go 1.26.0` with `toolchain
go1.26.6`, the Docker build stage defaults to `GO_VERSION=1.26.6`, and
CI/release use `go-version-file: go.mod` — keeping local, CI, release, and
container builds on the same patched standard library line.

```
$ go version
go version go1.26.6 darwin/arm64

$ govulncheck ./...
=== Symbol Results ===
No vulnerabilities found.
Your code is affected by 0 vulnerabilities.
(advisories can exist in imported modules, but none are reachable from trstctl's code.)
```

### npm (web UI + TypeScript SDK generator + Pulumi IaC) — `npm audit`

The web dependency tree is pinned by `web/package-lock.json`. The CI `web`
job scans the browser runtime closure with
`npm audit --omit=dev --audit-level=high`; the supply-chain wrapper also
scans the complete web build-and-production tree with `--include=dev`
because Vite, PostCSS, and their plugins execute while producing the
embedded release bundle. The TypeScript SDK generator tree is pinned by
`clients/sdk/typescript/package-lock.json` and the same wrapper includes its
dev dependencies because `openapi-typescript` executes from
`scripts/gen-sdk.sh`. The Pulumi IaC example under
`deploy/iac/pulumi/trstctl-resources` is the third tree: its Node runtime
resolves `@pulumi/pulumi` at deploy time, so it is pinned by its own
`package-lock.json` and audited with dev dependencies included. A tree with no
lockfile cannot be audited reproducibly at all — the wrapper fails closed on a
missing `package-lock.json` rather than resolving floating ranges at scan time.
The scanner is pinned to npm CLI `11.16.0`; the CI `supply-chain` job runs it
plus a self-test that plants `minimist@0.0.8` in a temporary SDK lockfile and
again in a temporary Pulumi lockfile, and expects npm audit to fail on the known
critical advisory in each.

The wrapper writes a machine-readable release-evidence receipt
(`npm-audit-dependency-surfaces.json`) recording each audited surface,
pass/fail status, and severity counts; CI uploads it as an artifact and
tagged releases publish it beside the chaos evidence.

```
$ bash scripts/ci/npm-audit-dependency-surfaces.sh
>> npm audit (web build and runtime dependency tree)
   severity counts: info=0 low=0 moderate=0 high=0 critical=0 total=0
>> npm audit (TypeScript SDK generator dependency tree)
   severity counts: info=0 low=0 moderate=0 high=0 critical=0 total=0
>> npm audit (Pulumi IaC example dependency tree)
   severity counts: info=0 low=0 moderate=0 high=0 critical=0 total=0
>> wrote npm audit receipt: /tmp/trstctl-npm-audit-dependency-surfaces.json
```

### embedded-postgres binary — committed checksum pin (CI and runtime) + Trivy

The external PostgreSQL runtime used by Docker Compose, the demo, and the disaster
recovery rehearsal is built from the exact official PostgreSQL 16.15 Bookworm
digest in `deploy/docker/Dockerfile.postgres`. The upstream Debian packages scan
clean, but its unused `gosu` helper was built with a vulnerable Go toolchain. Our
three-line derivative removes that helper and starts directly as the existing
non-root `postgres` account; it downloads and installs nothing else. That does not
repair or conceal the bundled path described below: its vendor wrapper remains on
16.14.0, and the supply-chain gate stays red when the official PostgreSQL catalog
reports a HIGH/CRITICAL advisory fixed after that exact pin.

The `embedded-postgres` dependency downloads a real PostgreSQL 16.14.0 binary
from Maven Central at runtime — outside `go.sum`. It backs both the
integration tests and the served single-node/eval path that starts bundled
PostgreSQL, so its provenance is committed and enforced at runtime, not
merely scanned in CI:

- `deploy/supply-chain/embedded-postgres.json` records the exact version,
  Maven coordinates, source URLs, and a committed per-arch SHA-256 pin for
  both the Maven jar and the inner `.txz` archive, covering linux/amd64,
  linux/arm64, and darwin/arm64. The pin is populated, so the gate is a
  hard fail, not a no-op.
- The served binary carries the same per-arch pins and enforces them at
  runtime: before starting bundled PostgreSQL it verifies the cached `.txz`
  against the committed pin and refuses to start a tampered or MITM'd
  binary, fail-closed — independent of the library's same-origin `.sha256`
  sidecar, so a Maven/MITM compromise serving a matching jar+sidecar is
  still caught. A test asserts the binary's built-in pins and the JSON
  manifest never drift.
- `scripts/supply-chain/verify-embedded-postgres.sh` verifies the downloaded
  jar and its inner `.txz` against the committed pins, Trivy-scans the
  extracted binaries, and fetches the supported-major security table from the
  PostgreSQL project (PostgreSQL's CVE Numbering Authority). CI runs it per
  architecture and stores the raw Trivy report, Trivy version/DB metadata, the
  raw PostgreSQL security page and SHA-256, its normalized
  exact-version advisory catalog, matched advisories, and the final receipt.
- Checksum provenance and vulnerability coverage are separate decisions. A
  matching hash proves which bytes arrived; it cannot prove those bytes have no
  published vulnerability. Fixable Trivy HIGH/CRITICAL findings and official
  HIGH/CRITICAL advisories fixed after the exact pin fail the gate.
- The receipt also records INVENTORY COVERAGE, because severity counts alone
  cannot tell "scanned the binary and found nothing" apart from "scanned
  nothing" — both read as `high=0 critical=0`.
  `coverage.packages_inventoried` is how many packages the report listed,
  `coverage.pinned_version_evidence[]` names the package(s) carrying the
  pinned server version and the Trivy Results block each came from, and
  `coverage.postgres_server_package_inventoried` says whether Trivy actually
  named the PostgreSQL server. A report with no packages or no exact-version
  evidence fails (SUPPLY-009). On the extracted Zonky archive that server flag
  is normally `false`: Trivy sees the Maven wrapper, not a server package
  database. The wrapper can pass only when a fresh (at most 24 hours old)
  official PostgreSQL catalog independently evaluates the exact pin. Missing,
  invalid, stale, wrong-version, or wrong-major authority fails closed, and the
  receipt preserves the source URL/hash plus every affected HIGH/CRITICAL row.
- If Zonky lags a PostgreSQL security release, CI intentionally turns red until
  the patched per-architecture wrapper artifacts exist and their committed
  jar/TXZ hashes can move. This is an honest external-update prerequisite, not
  a reason to relabel a provenance-valid vulnerable binary as clean.

CI retains this evidence for every supported host architecture. The tagged-release
gate reruns the Linux/amd64 verifier and publishes
`embedded-postgres-security-linux-amd64.tar.gz` beside the npm and chaos receipts;
the release stops before publication when the server advisory decision is red.

This binary is not bundled in the shipped distroless image (Go binaries
only); it is fetched on first run of the bundled single-node/eval path.

## SBOMs

Two CycloneDX SBOMs are produced: the image SBOM the release attaches and
cosign attests, and a module SBOM of the Go dependency graph (`make sbom`,
uploaded by the CI `supply-chain` job).

The module SBOM is generated by `cyclonedx-gomod`, pinned to `@v1.10.0` by
`CYCLONEDX_GOMOD_VERSION` in the `Makefile`. That generator emits CycloneDX
`specVersion` 1.6; the previous `@v1.7.0` pin emitted 1.5. Nothing in this
repository parses `dist/release-evidence/sbom.module.cyclonedx.json` — it is
uploaded as a CI artifact for consumers — so the schema bump is a recorded,
reviewed change. `make sbom` writes it under `dist/release-evidence/`, beside
the license-audit receipts, because `/dist/` is gitignored; at the repository
root the file would be untracked *and* unignored, so a bulk `git add -A` would
commit a machine-local dependency dump as if it were reviewed source.
The image SBOM the release attests is produced by a different generator
(`anchore/sbom-action`) and is unaffected.

## CI security & quality gates

Beyond SCA, CI enforces a security and quality bar on every pull request,
repo-wide, so a regression cannot merge. Each gate fails the build, not
merely reports:

- **SAST — CodeQL** (`.github/workflows/codeql.yml`): static analysis of the
  Go and web-UI code with the `security-extended` query suite, on every PR,
  on pushes to `main`, and weekly.
- **Secret scanning — gitleaks** (`.github/workflows/security.yml`,
  `.gitleaks.toml`, `.gitleaksignore`): installs the same checksum-verified
  Gitleaks `v8.27.2` release used by the served scanner, then scans the
  full history against gitleaks' default ruleset. No path is exempt from any
  rule — `_test.go` sources and `testdata/` fixtures are scanned exactly like
  production source. The only standing allowlist is the exact key body of the
  published connector conformance keypair; every other known false positive is
  pinned one finding at a time in `.gitleaksignore` by exact
  commit/path/rule/line fingerprint, so any other hardcoded secret fails CI.
- **Dependency vulnerabilities**: the pinned `govulncheck` job (above) plus
  Dependabot raising update PRs for Go modules, npm, GitHub Actions, and the
  Docker base.
- **Container image scanning — Trivy**: builds the runtime image from
  digest-pinned builder and runtime bases (never floating tags) and fails
  on any fixable HIGH/CRITICAL vulnerability. `scripts/ci/check-base-pinned.sh`
  guards that the release path pins both `BUILD_IMAGE` and `BASE_IMAGE` by
  digest.
- **Shipped-stack image pinning**: `scripts/ci/check-compose-images-pinned.sh`
  extends that rule past the production image to every container image the
  `deploy/` tree references — the compose stacks, the demo seed Dockerfile, and
  the IaC job manifests — failing CI on any `image:` or `FROM` that names a tag
  without an `@sha256:` digest (SUPPLY-008). Locally-built `*:local` refs,
  build-arg indirection, Helm-templated refs, and intra-Dockerfile stage
  references are the only exemptions. Dependabot's docker updater covers the
  compose and Dockerfile directories it can parse (`/deploy/docker`,
  `/deploy/demo`) and bumps those digest pins in place; the `deploy/iac/` pins
  are not reachable by that updater and are refreshed by hand.
- **Critical-package coverage gate**: beyond the repo-wide coverage floor,
  each security-critical package (crypto boundary, issuance, outbox, RLS
  store, signing, revocation) must independently meet
  `CRITICAL_COVERAGE_MIN`, so a critical package cannot hide behind the
  aggregate average.

The architecture linter and the workflow linter (`actionlint`) remain
required. The full set of required status checks, plus enforce-admins,
linear history, and code-owner review, is codified in the repository —
see [Branch protection & required checks](branch-protection.md) for the
exact list and
`.github/branch-protection.json`
for the machine-applicable form. Code ownership of the root-of-trust paths
is codified in
`.github/CODEOWNERS`.

## Run it yourself

```bash
make supply-chain   # module SBOM + Go/npm/embedded-postgres SCA (network needed for npm + PG legs)
make vuln           # run only the pinned govulncheck gate
make sbom           # build only the module SBOM
make dependency-freshness # build only the committed dependency freshness SLO report
make coverage-critical   # per-package coverage gate on the critical set (needs cover.out from `make test`)
```

See `deploy/supply-chain/README.md` for the per-surface summary table.
