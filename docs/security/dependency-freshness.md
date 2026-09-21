# Dependency freshness

Dependency freshness is not the same thing as vulnerability scanning.

`govulncheck`, `npm audit`, Trivy, and the embedded-postgres checksum plus official
PostgreSQL CNA advisory gate answer the security question: "is a known bad
dependency reachable or shipped right now?" A checksum alone answers provenance,
not vulnerability status.
Freshness answers the engineering question: "are important dependencies becoming old
enough that the next security fix will be expensive?"

The source of truth is the committed report at
`deploy/supply-chain/dependency-freshness.json`. It is checked by
`node scripts/ci/check-dependency-freshness.mjs`, by `make dependency-freshness`, and by
the CI `supply-chain` job.

## SLO classes

| Class | Owner | Age budget | Examples |
|---|---|---:|---|
| `critical-go-runtime` | Platform/Security | 45 days | embedded-postgres, NATS Server, OPA, wazero, pgx, gRPC |
| `web-runtime` | Web/Console | 60 days | React, React DOM, React Router, Vite, Vitest, Tailwind |
| `developer-tooling` | Build/Quality | 90 days | TypeScript, linters, formatters, test coverage tooling |
| `release-infrastructure` | Release/Supply-chain | 45 days | GitHub Actions, Docker bases, SBOM, SCA, signing tools |

## How the age budget is enforced

The age budget is not advisory. Every `tracked_upgrades` row whose `status` is not
`current` carries `behind_since` (`YYYY-MM-DD`), and
`scripts/ci/check-dependency-freshness.mjs` measures today minus that date against the
`max_age_days` of the row's `freshness_slo_class`. Over budget fails the gate, so
rolling `next_review_by` forward no longer keeps a stale dependency compliant.

- `behind_since` is required on every non-`current` row. Omitting it is a hard failure,
  not an unmeasurable row that quietly passes.
- A `current` row must leave `behind_since` empty, so a dependency cannot be marked
  caught-up while still carrying a start date.
- The only way past the budget is `status: accepted_deferral` with a `deferral_until`
  that still covers today. An expired or missing `deferral_until` fails, and relabeling
  the row back to `planned` fails on age instead.

`behind_since` records the earliest date this repository observed the row as not
`current`, which is a conservative lower bound: where a dependency actually fell behind
before that date, the real date is earlier and the recorded value understates the debt.
Move it earlier whenever a better-evidenced date is known; never move it later to buy
time.

## A review may not be scheduled past its own deadline

`next_review_by` must land on or before the date the row is actually due:
`behind_since + max_age_days` normally, or `deferral_until` when a deferral is live.
A later review fails the gate.

This exists because the policy was, for a while, unable to satisfy itself. Five
`critical-go-runtime` rows shared `behind_since: 2026-06-21` and were authored into a
report observed on `2026-07-27` — already 36 days into a 45-day budget — with
`next_review_by: 2026-08-26`. They were always going to breach on 2026-08-05, three days
after the gate was made real, and 21 days before anyone was scheduled to look. Nothing
was misfiled. A 45-day budget measured from the upstream release date, combined with a
30-day report cycle, guarantees that outcome for any row already 15 or more days behind
when the report is written.

The guard also caught a latent second case: `react-router-dom` was comfortably inside
its 60-day budget but had its review booked six days after that budget expired, so it
would have gone red on 2026-08-20 with nobody due to look until the 26th.

The check is skipped for a row that has already breached with no live deferral — there
the age failure is the point, and scheduling advice would only be noise.

The remedy is never to widen `max_age_days` so the red goes away. Move the review
earlier, record a dated `accepted_deferral` that covers it, or do the upgrade.

## The major-version gap cap

The age budget and the major-version gap are different debts. A row can sit well inside
its class age budget and still be several majors behind, which is where the TypeScript
row was: `5.9.3` against a published `7.0.2`, comfortably inside the 90-day
`developer-tooling` budget, and the gate printed OK.

`scripts/ci/check-dependency-freshness.mjs` parses the leading integer of
`current_version` and `latest_observed_version` and applies a cap of one major:

- A gap of zero or one major is ordinary upgrade-queue work, governed by the age budget.
- A gap of more than one major fails the gate unless the row carries
  `accepted_deferral` status with a `deferral_until` that still covers today. That is the
  same single escape hatch the age budget uses, so a multi-major pin is always a dated,
  argued decision rather than drift.
- A `current_version` whose major is newer than `latest_observed_version` fails: the
  observation is stale and has to be re-taken.
- A version whose leading component is not an integer fails closed rather than being
  skipped.

The rationale is where the reason lives. A row parked more than one major behind must
name the intermediate release it will hop through and the work the upgrade is waiting
on, because once the gap cap applies, that rationale and its `deferral_until` are the
only things standing between the pin and a red gate.

A tracked npm row is measured against `web/package-lock.json`. Other npm trees in this
repository -- `clients/sdk/typescript` and `deploy/iac/pulumi/trstctl-resources` -- have
their own lockfiles and are not covered by a `web/` row, so do not read a tracked
version as repository-wide.

## How to refresh the report

Run the discovery commands:

```bash
go list -m -u all
npm --prefix web outdated --json
```

Then keep the security gates separate:

```bash
make vuln
npm --prefix web audit --omit=dev --audit-level=high
```

Update `deploy/supply-chain/dependency-freshness.json` with the new observation date,
observed latest versions, owners, next-review dates, and any accepted deferral windows.
A row that newly falls behind gets a `behind_since` of the date it was observed
behind; a row that has caught up moves to `status: current` and clears `behind_since`.
Major upgrades must name an owner and a reason. An accepted deferral is allowed only
when it has an explicit `deferral_until` date and explains the compatibility work that
keeps the upgrade from being a safe automatic Dependabot merge.

The checker validates the report offline against `go.mod` and `web/package-lock.json`.
That means CI can prove the owner queue is current without relying on live registry
availability during every pull request.
