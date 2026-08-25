# Frontend capability parity

This package prevents the trstctl backend and console from becoming two different products.

The technical ELI5 model is: every product capability gets one contract card. The card says which tool owns it, where an operator enters it, which permissions and edition control it, what side effects and secret-data rules apply, and whether an operator can complete each of nine workflow stages:

`discover → understand → configure → preview → execute → observe → recover → verify → automate`

The source of truth is `feature-map-backlog.json`. Do not create a second capability list in Go, TypeScript, documentation, or the QA harness.

## What fails closed

`ValidateCatalog` rejects unknown tools, maturity labels, or stage statuses. It also rejects a completed stage with no evidence, an incomplete stage with completion evidence, a primary operator stage hidden as “API only,” an invalid candidate SHA, and a maturity or release-blocking decision that contradicts the nine stage cells.

The web generator writes `web/src/lib/feature-contracts.gen.ts` from that same catalog. Console navigation uses the generated feature-ID type. Vitest then checks both directions:

- Backend without UI: every primary contract must have a registered real console surface at its canonical route.
- Ghost UI: every visible console surface must have a canonical capability contract.

Deliberately broken controls prove those gates detect unknown tools, statuses, routes, maturity claims, release decisions, and UI feature IDs.

## Commands

Run the complete parity gate:

```sh
make feature-parity-check
```

After an intentional catalog change, regenerate and review both web contracts:

```sh
make web-contract
```

Create the standalone, offline reviewer panel:

```sh
make feature-parity-report FEATURE_PARITY_REPORT_OUT=/absolute/path/frontend-parity-control-panel.html
```

The HTML contains no secret values, external scripts, remote fonts, or second feature list. It shows all 79 capabilities, computed maturity, release blockers, the nine stage cells, security boundaries, evidence, and exact candidate metadata. The Make target stamps the current commit as the report candidate; direct tool calls must supply the exact 40-character SHA with `--candidate`. Each row separately retains the catalog SHA where its contract evidence was recorded, so an evidence reader cannot confuse an older proof snapshot with the candidate currently under qualification. Supplying `--console-base` to `tools/featureparityreport` makes route links target a specific live candidate.

## Runtime capability view

`GET /api/v1/capabilities` is the customer-safe projection of this same catalog. It is authenticated by the dedicated `capabilities:read` permission and then joins every catalog operation to the declared route, the optional service actually wired into this control-plane process, and the current principal's RBAC grants. A route can remain visible in OpenAPI and fail closed for direct callers while the capability view truthfully marks its operation unavailable; “documented” never means “configured.” Independent posture reads remain available when their optional mutation service is off.

The response tells the console which actions are allowed, resource-scoped, denied, not attached, dependency-disabled, or deliberately unimplemented. It also carries the current license tier/state and the sanitized nine-stage ledger. It does **not** return evidence, repository paths, owner names, candidate SHAs, permission-authority implementation details, or secret-handling internals. Resource scope, ABAC, tenant key state, mutation gates, idempotency, and live dependencies are still enforced when the user runs an action; this read is a preflight, not an authorization bypass.

The web client consumes the generated `CapabilityView` type, and `make sdk` propagates the served OpenAPI contract into the TypeScript, Python, and Java SDK artifacts.

## Updating a capability safely

1. Change the existing capability row and its explicit stage evidence.
2. Regenerate the TypeScript contract.
3. Implement or correct the registered console surface.
4. Run `make feature-parity-check` and the normal Go/web release gates.
5. Generate the HTML panel from the same exact candidate and retain it with the QA evidence.

Never mark a stage complete because a page merely mentions the capability. A complete stage needs usable operator behavior and exact evidence. When uncertain, keep the stage `missing` or `blocked` with a precise reason.
