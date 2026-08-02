# Dependency freshness

Dependency freshness is not the same thing as vulnerability scanning.

`govulncheck`, `npm audit`, Trivy, and the embedded-postgres checksum pins answer the
security question: "is a known bad dependency reachable or shipped right now?"
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
  that still covers today. An expired or missing `deferral_until` fails, and relabelling
  the row back to `planned` fails on age instead.

`behind_since` records the earliest date this repository observed the row as not
`current`, which is a conservative lower bound: where a dependency actually fell behind
before that date, the real date is earlier and the recorded value understates the debt.
Move it earlier whenever a better-evidenced date is known; never move it later to buy
time.

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
A row that has just fallen behind gets a `behind_since` of the date it was observed
behind; a row that has caught up moves to `status: current` and clears `behind_since`.
Major upgrades must name an owner and a reason. An accepted deferral is allowed only
when it has an explicit `deferral_until` date and explains the compatibility work that
keeps the upgrade from being a safe automatic Dependabot merge.

The checker validates the report offline against `go.mod` and `web/package-lock.json`.
That means CI can prove the owner queue is current without relying on live registry
availability during every pull request.
