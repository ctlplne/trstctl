# Branch protection & required checks (codified)

This page is the human-readable companion to the in-repo branch-protection policy:
**which checks must pass before merging to `main`**, who must review which paths,
and how an admin applies and verifies the rules — so the gate is **provable from
the repository**, not an invisible server-side setting.

> Why this exists. The audit (TEST-006) found "blocks merge" depended on a repo
> admin configuring required checks / enforce-admins / linear-history server-side
> — invisible to the repository and to a reviewer. A job that *runs* but is **not
> required** is theater: a red build could merge, an admin could force-push, and
> nothing in-repo would show it. Codifying the policy in
> [`.github/branch-protection.json`](https://github.com/ctlplne/trstctl/blob/main/.github/branch-protection.json)
> (owners mirrored in [`.github/CODEOWNERS`](https://github.com/ctlplne/trstctl/blob/main/.github/CODEOWNERS))
> makes the gate auditable; `docs/branch_protection_test.go` matches the
> required-check list to real CI job names in both directions, with an explicit
> reason for any non-PR exemption.

## The policy for `main`

The canonical, machine-applicable form lives in
[`.github/branch-protection.json`](https://github.com/ctlplne/trstctl/blob/main/.github/branch-protection.json).
Merging to `main` requires:

- **All required status checks green**, branch up to date (`strict`) — every CI
  gate plus the security scans below. A check that runs but isn't listed doesn't
  block merge; a listed, failing check **does**.
- **No approving-review requirement**, deliberately. trstctl has one maintainer,
  and GitHub does not let an author approve their own pull request, so
  `required_approving_review_count: 1` — together with `require_code_owner_reviews`
  and `require_last_push_approval` — made `main` unmergeable by the only person who
  can merge to it. The policy also named a `@ctlplne/security` **team that does not
  exist**, so code-owner review could not have resolved even with a second person.
  A required reviewer nobody can produce is not a control; it is a gate that gets
  routed around. `required_pull_request_reviews` is therefore `null`, and the
  compensating controls carry the weight: `enforce_admins` keeps every one of the
  required checks binding on the owner, so **CI is the review**.
  `.github/CODEOWNERS` still routes review *requests* on root-of-trust paths, so a
  change there announces itself in the pull request. Restore the review block
  verbatim the day a second maintainer exists — `docs/branch_protection_test.go`
  accepts either state and rejects "reviews off with nothing replacing them".
- **Linear history** (`required_linear_history`: squash/rebase, no merge commits),
  **no force-pushes or deletion** (`allow_force_pushes: false`,
  `allow_deletions: false`).
- **Enforce on admins** (`enforce_admins: true`) and **conversation resolution
  required** before merge.

### Required status checks

These are the exact GitHub check names (the `name:` of each CI job), kept in sync
with the workflows by `docs/branch_protection_test.go`: a required context must
match a real job, a fixed-name CI/security job must block merge or carry an
exemption, and this page must document every required context.

| Check (job name) | Workflow | What it guards |
|---|---|---|
| `build / test / lint` | `ci.yml` | Build all binaries, `make test` (race + coverage), full `make lint` (gofmt/vet/**trstctllint**, golangci-lint, actionlint), gate self-tests |
| `definition of done / wiring census` | `ci.yml` | `make dod-gate`: `go list -deps` reachability, production `buildRunDeps` assembly, and non-sentinel served-handler receipts for every required manifest row |
| `chaos (fault injection)` | `ci.yml` | `make chaos`: signer death, NATS restart/partition, PostgreSQL failover, store-write failure, restore interruption, memory-pressure bulkhead, retry-backoff assertions |
| `fuzz (smoke per-PR, deeper nightly)` | `ci.yml` | PR fuzz smoke plus deeper scheduled parser fuzzing keep fuzz targets and seed corpora wired into the merge gate |
| `ClusterFuzzLite / OSS-Fuzz (address)` | `ci.yml` | Hosted ClusterFuzzLite / OSS-Fuzz-family build and fuzz run, SHA-pinned upstream actions, uploaded build/SARIF, archived run artifacts |
| `web ui (typecheck / test / build)` | `ci.yml` | Web console typecheck, Vitest + axe, Vite build, npm SCA |
| `docs site (mkdocs build --strict)` | `ci.yml` | Docs build with no broken nav/links |
| `actionlint (workflow lint)` | `ci.yml` | Workflow + shell lint of the pipelines themselves |
| `govulncheck` | `ci.yml` | Reachability-aware vulnerability scan |
| `supply-chain (SBOM + binary SCA)` | `ci.yml` | Module SBOM + npm dependency SCA + embedded-Postgres provenance/scan |
| `embedded-postgres scan receipts` | `ci.yml` | Aggregate gate requiring every arch-specific embedded-Postgres provenance/Trivy receipt |
| `helm (lint + render + schema)` | `ci.yml` | Control-plane chart lint + kubeconform |
| `proto (buf lint + breaking-change gate)` | `ci.yml` | Signer gRPC contract (AN-4) wire-compat |
| `acme conformance (Pebble differential)` | `ci.yml` | ACME protocol differential vs the reference CA |
| `acme stock-client conformance (certbot transcript)` | `ci.yml` | Stock certbot manual DNS-01 issue/renew/revoke against the served ACME endpoint; transcripts archived |
| `est client conformance (libest estclient)` | `ci.yml` | Stock libest `estclient` simpleenroll against the served EST endpoint, checksum-pinned build |
| `cmp client conformance (OpenSSL transcript)` | `ci.yml` | Stock OpenSSL `cmp p10cr` enrollment against the served CMP endpoint; transcripts archived |
| `tsa client conformance (OpenSSL ts transcript)` | `ci.yml` | Stock OpenSSL `ts -query`/`ts -verify` against the served `/tsa` RFC 3161 endpoint; transcripts archived |
| `scep client conformance (sscep transcript)` | `ci.yml` | Stock sscep enrollment against the served SCEP endpoint; PKIOperation transcripts archived |
| `spiffe workload api conformance (go-spiffe + helper)` | `ci.yml` | Stock go-spiffe fetches/validates X.509-SVID and JWT-SVID from the served Workload API socket; spiffe-helper writes the SVID, key, trust bundle |
| `compose e2e + PKI conformance (EXC-GATE-01)` | `ci.yml` | Docker Compose stack: real PostgreSQL, JetStream, isolated signer, served issuance/revocation, PKI profile linting |
| `vault compat (real openbao client)` | `ci.yml` | Vault-compat shim acceptance against a pinned real OpenBao CLI, non-skipped |
| `ee / unit tests + vdec gates` | `ci.yml` | `make ee-test` (ee/ unit tests + coverage floor) plus VDEC wire/release gates exercise commercial code every PR |
| `restore rehearsal / full DR loop` | `ci.yml` | Backup from a populated instance restores via the shipped binary into a fresh instance that boots, reads data, and issues credentials; a corrupted backup fails closed |
| `reproducible build (byte-identical rebuild)` | `ci.yml` | Shipped binaries and image layers rebuild byte/layer-identical on every PR |
| `scheduled gates / nightly freshness` | `ci.yml` | Fails closed unless the latest scheduled run is fresh (≤26h), green, and ran every promoted gate — captured soak, spine burst, live branch-protection drift, perf live — making scheduled-only verifiers required in effect |
| `windows cross-build` | `ci.yml` | Whole module cross-compiles for Windows |
| `fips-capable build (GOFIPS140)` | `ci.yml` | All binaries build with the FIPS-capable Go toolchain setting (`GOFIPS140`) and run the FIPS self-test path |
| `windows / test + MSI` | `ci.yml` | Windows agent surface (real cert store) + MSI |
| `kubernetes / kind e2e` | `ci.yml` | In-cluster e2e + cert-manager Certificate through trstctl ClusterIssuer |
| `spire container e2e` | `ci.yml` | Real SPIRE server container loads the trstctl upstream-authority plugin, mints an X.509-SVID, and verifies the chain to the root |
| `pqc e2e (dodproof)` | `ci.yml` | PQC census proofs against the shipped artifact: stock-OpenSSL pure ML-DSA-65 EST enrollment, two-entry hybrid SVID Workload API response, CBOM→migration TLS rollout + rollback |
| `secret scan (gitleaks)` | `security.yml` | No committed secrets |
| `container image scan (Trivy)` | `security.yml` | Image vulnerability scan |

CodeQL (`codeql.yml`) also runs on every PR. Its check name is a build-matrix
template (`analyze (<language>)`), so it's recommended as required but set in the
GitHub UI, not pinned here by literal name — the sync-test omits matrix-expanded
names to stay robust.

Three scheduled/manual jobs are intentionally **not** required PR checks — none
run on pull requests: `branch protection / live policy drift` audits live GitHub
settings; `captured soak / leak gate` captures a sustained-load series and verifies
an induced leak fails the analyzer; `spine burst / replay-outbox gate` boots
embedded PostgreSQL/JetStream and analyzes a cap-small replay/outbox burst via
`scripts/perf/soak.sh --in`. All three publish evidence outside the pull-request
path, and `docs/branch_protection_test.go` pins each as an explicit exemption with
a reason, so no CI job silently escapes the merge gate.

### Release-time gate

A version tag never ships an unverified commit: `release.yml` sets three blockers
before any image, Windows agent, or Helm chart builds, signs, or publishes:

- `test` re-runs the release-local suite (`make build`, embedded-UI verification,
  `make test`) against the **exact tagged ref**.
- `required-checks` runs `scripts/ci/verify-required-checks.sh` and verifies the
  tag commit has every required CI/security check green.
- `release-evidence` runs `make chaos`, archives the `release-chaos-evidence`
  artifact, and publishes `trstctl-chaos-evidence.txt` so each GA candidate carries
  fault-injection output. It also re-runs `make vuln` and the npm audit wrapper,
  publishing `npm-audit-dependency-surfaces.json` with advisory counts by severity
  for the web/TypeScript SDK surfaces.

Every build/sign/publish job `needs: [test, required-checks, release-evidence]`: a
tag whose CI/security surface was skipped, red, pending, or missing cannot publish
a signed artifact, nor can a GA candidate publish without the chaos evidence pack.

### Drift detection

The scheduled/manual CI job `branch protection / live policy drift` runs
`scripts/ci/verify-branch-protection.sh` against the GitHub API and fails if live
`main` protection differs from `.github/branch-protection.json` (TEST-001) — a
watched control, not a one-time admin click. Each run uploads
`branch-protection-live-drift-receipt`, containing
`branch-protection-drift-receipt.json`; release review attaches the latest green
receipt so the shipped tag is backed by live GitHub state, not just committed
policy.
If the default workflow token can't read branch-protection settings, set repository
secret `TRSTCTL_BRANCH_PROTECTION_READ_TOKEN` to one with admin/branch-protection
read access.

## Code ownership

[`.github/CODEOWNERS`](https://github.com/ctlplne/trstctl/blob/main/.github/CODEOWNERS)
assigns mandatory reviewers: the AN-3 crypto boundary (`internal/crypto`), the AN-4
isolated signer (`internal/signing`, `cmd/trstctl-signer`, `proto`), the AN-1
multi-tenant store (`internal/store`), and the architecture linter
(`tools/trstctllint`) are owned explicitly. With a single maintainer this routes a
review *request* rather than blocking the merge (see above), so a root-of-trust
change is announced in the pull request instead of passing silently.
`docs/codeowners_test.go` asserts each path stays covered, and ownership now names
the maintainer's account rather than a team that was never created.

## Apply it (repo admin)

```bash
# Apply the codified protection to main (requires admin on the repo):
gh api -X PUT repos/ctlplne/trstctl/branches/main/protection \
  -H "Accept: application/vnd.github+json" \
  --input .github/branch-protection.json

# Or manage it as code via Terraform's github_branch_protection resource (same
# contexts / enforce_admins / linear-history / code-owner-review settings).
```

## Verify it (anyone with read on the API)

```bash
# The applied protection should match the codified policy (required checks,
# enforce-admins, linear history, code-owner review).
gh api repos/ctlplne/trstctl/branches/main/protection | jq '{
  contexts: .required_status_checks.contexts,
  enforce_admins: .enforce_admins.enabled,
  linear: .required_linear_history.enabled,
  code_owner_reviews: .required_pull_request_reviews.require_code_owner_reviews
}'
```

If the applied protection and `.github/branch-protection.json` ever diverge, the
in-repo file is the intended policy; re-apply it.

## See also

[Supply chain & build integrity](supply-chain.md) ·
[Vulnerability management](security/vulnerability-management.md) ·
[`SECURITY.md`](https://github.com/ctlplne/trstctl/blob/main/SECURITY.md)
