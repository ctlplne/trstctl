# Branch protection & required checks (codified)

This page is the human-readable companion to the in-repo branch-protection policy.
It explains **which checks must pass before anything merges to `main`**, who must
review which paths, and how an admin applies and verifies the rules — so the gate is
**provable from the repository**, not an invisible server-side setting.

> Why this exists. A review flagged that "blocks merge" depended on a
> repo admin having configured required checks / enforce-admins / linear-history
> server-side — invisible to the repository and to a reviewer. A job that *runs* but
> is **not required** is theater: a red build could merge, and an admin could
> force-push, with no in-repo trace. Codifying the policy here (plus
> [`.github/CODEOWNERS`](https://github.com/ctlplne/trstctl/blob/main/.github/CODEOWNERS)
> and [`.github/branch-protection.json`](https://github.com/ctlplne/trstctl/blob/main/.github/branch-protection.json))
> makes the gate auditable. Two reality-tests keep the codified policy honest:
> `docs/codeowners_test.go` (every security-critical path is owned) and
> `docs/branch_protection_test.go` (the required-check list matches the real CI job
> names in both directions, with explicit reasons for any non-PR exemption).

## The policy for `main`

The canonical, machine-applicable form lives in
[`.github/branch-protection.json`](https://github.com/ctlplne/trstctl/blob/main/.github/branch-protection.json).
In words, merging to `main` requires:

- **All required status checks green** (and the branch up to date — `strict`). The
  required set is **every CI gate** plus the security scans (see the table below). A
  check that runs but is not in this list does **not** block merge; a check in this
  list that is missing/failing **does**.
- **At least one approving review**, and — for the root-of-trust paths —
  **approval from a code owner** (`require_code_owner_reviews`). Stale approvals are
  dismissed on a new push (`dismiss_stale_reviews`), and the last push must itself be
  approved (`require_last_push_approval`), so a sneak-in commit after approval cannot
  ride in.
- **Linear history** (`required_linear_history`) — squash/rebase, no merge commits.
- **No force-pushes and no branch deletion** (`allow_force_pushes: false`,
  `allow_deletions: false`) — history cannot be rewritten under the protection.
- **Enforce on admins** (`enforce_admins: true`) — maintainers are bound by the same
  rules; nobody bypasses the gate.
- **Conversation resolution required** before merge.

### Required status checks

These are the exact GitHub check names (the `name:` of each CI job). They are kept in
sync with the workflows by `docs/branch_protection_test.go`, which fails if a
required context stops matching a real job, if a fixed-name CI/security job runs
without either blocking merge or having an explicit exemption, or if this page stops
documenting a required context. That means a gate can never silently fall out of the
required set.

| Check (job name) | Workflow | What it guards |
|---|---|---|
| `build / test / lint` | `ci.yml` | Build all binaries, `make test` (race + coverage floors), full `make lint` (gofmt/vet/**the architecture linter** that enforces per-tenant isolation, the single crypto path, idempotency keys, and wipeable secret memory, golangci-lint, actionlint), gate self-tests |
| `chaos (fault injection)` | `ci.yml` | `make chaos`: signer death, NATS restart/partition, PostgreSQL failover, store-write failure, restore interruption, memory-pressure bulkhead, and retry-backoff safe-failure assertions |
| `fuzz (smoke per-PR, deeper nightly)` | `ci.yml` | Short PR fuzz smoke plus deeper scheduled parser fuzzing, so fuzz targets and committed seed corpora stay wired into the merge gate |
| `web ui (typecheck / test / build)` | `ci.yml` | Web console typecheck, Vitest + axe, Vite build, npm SCA |
| `docs site (mkdocs build --strict)` | `ci.yml` | Docs build with no broken nav/links |
| `actionlint (workflow lint)` | `ci.yml` | Workflow + shell lint of the pipelines themselves |
| `govulncheck` | `ci.yml` | Reachability-aware vulnerability scan |
| `supply-chain (SBOM + binary SCA)` | `ci.yml` | Module SBOM + embedded-Postgres provenance/scan |
| `helm (lint + render + schema)` | `ci.yml` | Control-plane chart lint + kubeconform |
| `proto (buf lint + breaking-change gate)` | `ci.yml` | Signer gRPC contract wire-compat |
| `acme conformance (Pebble differential)` | `ci.yml` | ACME protocol differential vs the reference CA |
| `acme stock-client conformance (certbot transcript)` | `ci.yml` | Stock certbot manual DNS-01 issue, renew, and revoke against the served ACME endpoint, with public transcripts archived |
| `est client conformance (libest estclient)` | `ci.yml` | Stock libest `estclient` performs simpleenroll against the served EST endpoint with a checksum-pinned build |
| `cmp client conformance (OpenSSL transcript)` | `ci.yml` | Stock OpenSSL `cmp p10cr` enrollment against the served CMP endpoint, with request/response transcripts archived |
| `tsa client conformance (OpenSSL ts transcript)` | `ci.yml` | Stock OpenSSL `ts -query` and `ts -verify` against the served `/tsa` RFC 3161 endpoint, with public request/response transcripts archived |
| `scep client conformance (sscep transcript)` | `ci.yml` | Stock sscep enrollment against the served SCEP endpoint, with PKIOperation request/response transcripts archived |
| `spiffe workload api conformance (go-spiffe + helper)` | `ci.yml` | Stock go-spiffe and spiffe-helper fetch X.509-SVIDs from the served Workload API Unix socket |
| `compose e2e + PKI conformance` | `ci.yml` | Docker Compose eval stack boots real PostgreSQL, JetStream, isolated signer, served issuance/revocation, and PKI profile linting |
| `windows cross-build` | `ci.yml` | Whole module cross-compiles for Windows |
| `fips-capable build (GOFIPS140)` | `ci.yml` | All binaries build with the FIPS-capable Go toolchain setting (`GOFIPS140`) and run the FIPS crypto self-test path |
| `windows / test + MSI` | `ci.yml` | Windows agent surface (real cert store) + MSI |
| `kubernetes / kind e2e` | `ci.yml` | In-cluster e2e + cert-manager bridge |
| `secret scan (gitleaks)` | `security.yml` | No committed secrets |
| `container image scan (Trivy)` | `security.yml` | Image vulnerability scan |

CodeQL (`codeql.yml`) also runs on every PR; because its check name is a build-matrix
template (`analyze (<language>)`) rather than a fixed string, it is recommended as a
required check but is configured in the GitHub UI rather than pinned by literal name
here (the sync-test deliberately omits matrix-expanded names so it stays robust).

The scheduled/manual job `branch protection / live policy drift` is intentionally
not listed as a required PR check because it does not run on pull requests. It audits
the live GitHub settings separately, and `docs/branch_protection_test.go` records
that exemption with a reason so future fixed-name CI jobs do not inherit it by
accident.

### Release-time gate

A version tag does **not** ship off an unverified commit. `release.yml` has two
release blockers before any image, Windows agent, or Helm chart is built, signed, or
published:

- `test` re-runs the release-local suite (`make build`, embedded-UI verification,
  and `make test`) against the **exact tagged ref**.
- `required-checks` runs `scripts/ci/verify-required-checks.sh`, reads the required
  contexts from `.github/branch-protection.json`, and verifies the tag commit has
  every required CI/security check green.

Every build/sign/publish job `needs: [test, required-checks]`, so a tag placed on a
commit whose broader CI/security surface was skipped, red, pending, or missing cannot
publish a signed artifact.

### Drift detection

The scheduled/manual CI job `branch protection / live policy drift` runs
`scripts/ci/verify-branch-protection.sh` against the GitHub API and fails if the live
`main` protection differs from `.github/branch-protection.json`. That
turns branch protection into a watched control instead of a one-time admin click.
If the default GitHub workflow token cannot read branch-protection settings, set the
repository secret `TRSTCTL_BRANCH_PROTECTION_READ_TOKEN` to a token with read access
to administration/branch-protection settings.

## Code ownership

[`.github/CODEOWNERS`](https://github.com/ctlplne/trstctl/blob/main/.github/CODEOWNERS)
assigns mandatory reviewers. The security-critical paths — the single crypto
boundary, the isolated signer process and its `cmd/trstctl-signer` binary and gRPC
contract, the multi-tenant store, and the architecture linter that enforces the
guardrails in CI — are owned explicitly, so with `require_code_owner_reviews`
enabled no change to the root of trust merges without a security review. A
reality-test asserts each of these paths stays covered.

## Apply it (repo admin)

```bash
# Apply the codified protection to main (requires admin on the repo):
gh api -X PUT repos/ctlplne/trstctl/branches/main/protection \
  -H "Accept: application/vnd.github+json" \
  --input .github/branch-protection.json

# Or manage it as code with Terraform's github_branch_protection resource, mirroring
# the same contexts / enforce_admins / linear-history / code-owner-review settings.
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
