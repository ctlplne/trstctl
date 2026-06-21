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
Major upgrades must name an owner and a reason. An accepted deferral is allowed only
when it has an explicit `deferral_until` date and explains the compatibility work that
keeps the upgrade from being a safe automatic Dependabot merge.

The checker validates the report offline against `go.mod` and `web/package-lock.json`.
That means CI can prove the owner queue is current without relying on live registry
availability during every pull request.
