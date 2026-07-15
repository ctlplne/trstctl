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

Dependencies live on four concrete surfaces; three are outside `go.sum`, so
they get their own scans. All four run in CI and via `make sca`.

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

`govulncheck` is pinned to `@v1.1.4` (in `ci.yml` and the `Makefile`) so the
gate is deterministic, not a moving `@latest`. It is reachability-aware: it
fails only on advisories the code can actually call.

The Go standard library is part of the shipped artifact, so the build
toolchain is also pinned: `go.mod` requires `go 1.26.0` with `toolchain
go1.26.4`, the Docker build stage defaults to `GO_VERSION=1.26.4`, and
CI/release use `go-version-file: go.mod` — keeping local, CI, release, and
container builds on the same patched standard library line.

```
$ go version
go version go1.26.4 darwin/arm64

$ govulncheck ./...
=== Symbol Results ===
No vulnerabilities found.
Your code is affected by 0 vulnerabilities.
(advisories can exist in imported modules, but none are reachable from trstctl's code.)
```

### npm (web UI + TypeScript SDK generator) — `npm audit`

The web dependency tree is pinned by `web/package-lock.json` and scanned
with `npm audit --omit=dev --audit-level=high` in the CI `web` job. The
TypeScript SDK generator tree is pinned by
`clients/sdk/typescript/package-lock.json` and scanned by
`scripts/ci/npm-audit-dependency-surfaces.sh` with dev dependencies
included, because `openapi-typescript` is a generator dependency used by
`scripts/gen-sdk.sh`. The scanner is pinned to npm CLI `11.16.0`; the CI
`supply-chain` job runs it plus a self-test that plants `minimist@0.0.8` in
a temporary SDK lockfile and expects npm audit to fail on the known
critical advisory.

The wrapper writes a machine-readable release-evidence receipt
(`npm-audit-dependency-surfaces.json`) recording each audited surface,
pass/fail status, and severity counts; CI uploads it as an artifact and
tagged releases publish it beside the chaos evidence.

```
$ bash scripts/ci/npm-audit-dependency-surfaces.sh
>> npm audit (web production dependency tree)
   severity counts: info=0 low=0 moderate=0 high=0 critical=0 total=0
>> npm audit (TypeScript SDK generator dependency tree)
   severity counts: info=0 low=0 moderate=0 high=0 critical=0 total=0
>> wrote npm audit receipt: /tmp/trstctl-npm-audit-dependency-surfaces.json
```

### embedded-postgres binary — committed checksum pin (CI and runtime) + Trivy

The `embedded-postgres` dependency downloads a real PostgreSQL 16.4.0 binary
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
  jar and its inner `.txz` against the committed pins and Trivy-scans the
  extracted binaries for HIGH/CRITICAL issues. CI runs it per architecture
  and stores a Trivy receipt artifact (raw JSON report, Trivy version/DB
  metadata, severity counts, pass/fail). Any fixable CRITICAL finding fails
  the gate, because a patched upstream binary is available and the pin
  must move.

This binary is not bundled in the shipped distroless image (Go binaries
only); it is fetched on first run of the bundled single-node/eval path.

## SBOMs

Two CycloneDX SBOMs are produced: the image SBOM the release attaches and
cosign attests, and a module SBOM of the Go dependency graph (`make sbom`,
uploaded by the CI `supply-chain` job).

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
  full history against gitleaks' default ruleset. Only deterministic PEM
  test vectors, the published connector conformance keypair, and its old
  placeholder are allowlisted by exact fingerprint; any other hardcoded
  secret fails CI.
- **Dependency vulnerabilities**: the pinned `govulncheck` job (above) plus
  Dependabot raising update PRs for Go modules, npm, GitHub Actions, and the
  Docker base.
- **Container image scanning — Trivy**: builds the runtime image from
  digest-pinned builder and runtime bases (never floating tags) and fails
  on any fixable HIGH/CRITICAL vulnerability. `scripts/ci/check-base-pinned.sh`
  guards that the release path pins both `BUILD_IMAGE` and `BASE_IMAGE` by
  digest.
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
[`.github/branch-protection.json`](https://github.com/ctlplne/trstctl/blob/main/.github/branch-protection.json)
for the machine-applicable form. Code ownership of the root-of-trust paths
is codified in
[`.github/CODEOWNERS`](https://github.com/ctlplne/trstctl/blob/main/.github/CODEOWNERS).

## Run it yourself

```bash
make supply-chain   # module SBOM + Go/npm/embedded-postgres SCA (network needed for npm + PG legs)
make vuln           # just the pinned govulncheck gate
make sbom           # just the module SBOM
make dependency-freshness # just the committed dependency freshness SLO report
make coverage-critical   # per-package coverage gate on the critical set (needs cover.out from `make test`)
```

See `deploy/supply-chain/README.md` for the per-surface summary table.
