# trstctl — Closeout Sprint Cards: everything 06 deliberately left out

**Companion to:** `06-ia-sprint-plan.md` (the IA train, fully shipped as of `48f4d976` + `d8af066e`), `04-ia-proposal.md` (§ sequencing + metrics), `02-findings.md` (DA-02, DA-10, DA-13/14 evidence).
**Format:** Cards follow `AGENTS.md §7` — self-contained, tests-first, one focused PR per card, `make lint test` green, no scope expansion.
**Scope decision (2026-07-14, Shankar):** full closeout of the six deferred items. `/admin/*` split is **committed**; entity-noun consolidation is **spike-gated** (decision doc this train, implementation explicitly not).
**Ship strategy:** rolling — each card lands on main individually green and individually revertable. No single release cut is required except C-R1, which gates the docs/CHANGELOG/screenshot refresh after the last feature card.

## Execution status (2026-07-14)

| Card | Status | Commit |
|---|---|---|
| C-D1 readiness panel on global home | **DONE** | `a889986d` |
| C-P1 incident pickers (DA-10) | **DONE** | `37ea9406` |
| C-A1 /admin split + redirects | **DONE** | `97d5bb4a` (i18n 1243→1242) |
| C-N1 noun spike (decision doc) | **DONE** | `fee0efdf` → `08-entity-noun-decision.md`; verdict: keep 4 nouns, Fleet-merge card C-N2 pre-written behind evidence checklist |
| C-S1 grant console (Job 2 interim) | **DONE** | `21418fec` (i18n 1242→1240) |
| C-S2 auth-method read projection (Go) | open | — |
| C-S3 session ledger + revocation (Go) | open | — |
| C-S4 auth-method console UI | open — blocked by S1 ✓, S2, S3 | — |
| C-I1 sweep: components+lib | open | — |
| C-I2 sweep: top pages | open — unblocked (C-P1 ✓, C-A1 ✓) | — |
| C-I3 sweep: remainder → budget 0 | open — blocked by C-S4 | — |
| C-R1 docs/tour/ratchets/closeout | open | — |

Per-card suites, typecheck, eslint, and the i18n ratchet ran green at every commit; the FULL `make lint test` sweep is C-R1's gate.

---

## Backlog shape

| Phase | Cards | Goal |
|---|---|---|
| **D — Deadline** | C-D1 | 47-day readiness panel on the global home (04's metric: "well before 2027-03-15"; the 200-day step is already in force). |
| **P — Pickers** | C-P1 | DA-10: incident intake stops taking raw UUIDs on faith. |
| **A — Admin split** | C-A1 | `/platform?tab=` grab-bag → three real `/admin/*` routes with permanent redirects. **First URL-changing card since the audit.** |
| **N — Nouns** | C-N1 | Spike only: evidence + naming proposal + go/no-go for Identities/Workloads/Agents/Owners. |
| **S — Secrets auth (DA-02)** | C-S1 … C-S4 | The flagship: Job 2 fully in-console (C-S1, reuse-only), then the faithful auth-method console (C-S2/S3 backend, C-S4 UI). |
| **I — i18n sweep (DA-14)** | C-I1 … C-I3 | Budget 1243 → 0. Monotone ratchet; three tranches sequenced *behind* the cards that rewrite the same files. |
| **R — Release** | C-R1 | Docs/tour/CHANGELOG/screenshots reconciled; ratchets extended; closeout audit row flipped. |

### Dependency graph

```
C-D1 ──────────────────────────────────────────────┐
C-N1 ──────────────────────────────────────────────┤
C-P1 ──┬───────────────────────────────────────────┤
C-A1 ──┼── C-I2 ───────────────────────────────────┤
C-I1 ──┘                                           ├── C-R1
C-S2 ──┬── C-S3 ── C-S4 ── C-I3 ───────────────────┤
C-S1 ──┴─────────────↑                             │
       (C-S1 independent; C-S4 needs S1+S2+S3) ────┘
```

C-D1, C-N1, C-P1, C-A1, C-I1, C-S1, C-S2 can all start immediately, in parallel. Recommended solo order (deadline first, then unblock the sweep): **C-D1 → C-P1 → C-A1 → C-I1 → C-N1 → C-S1 → C-S2 → C-S3 → C-S4 → C-I2 → C-I3 → C-R1.**

### The invariants every card inherits (amended from 06)

1. **URL changes are banned except in C-A1**, and there only with permanent in-app redirects (`/platform` and `/platform?tab=…` keep resolving forever). Every other card: zero URL changes.
2. **Backend changes are banned except in C-S2/C-S3**, and there only under the parent `AGENTS.md` non-negotiables: tenant RLS on every query (AN-1), event-sourced state — ledger/status are projections, never directly-written tables (AN-2), idempotency key on every mutation (AN-5), bounded work (AN-7), architecture linter green. No new datastore. Signer untouched.
3. **`ee/` stays at the attach seam** (AN-9). No `lic.Has` outside `attachEE`; `make editions-gate` + `scripts/check_editions_imports.sh` green where touched.
4. **Tests first** (§7.3). Existing named suites stay green untouched: `route_parity`, `nav_completeness`, `module_map`, `naming_parity`, `ia_ratchets`, `docs_ia_parity`, `i18n`, `route_focus`, `shell_a11y_and_theme`, `rtl_logical_layout`, `global_search`, `journeys`.
5. **i18n budget is monotone downward.** `extractedMessages.budget.json` sits at its exact ceiling (1243 entries / 1243 max — zero headroom). Every card ships new copy as typed `messages.ts` keys with es-ES entries (DESIGN rule 10); every C-I card lowers `maxExtractedMessages` to the new post-sweep count in the same PR.
6. **No demo data outside demo mode** (S-N0 principle; `ia_ratchets.test.ts` already enforces the Dashboard gate — nothing in this train may weaken it).
7. **DESIGN rules hold** — esp. rule 6 (object list first on list pages; N/A to the global dashboard, which has no dashboard-specific rule), rule 7 (StatePrimitives), rule 13 (never make the operator retype a value the console already knows — the DA-10 rule).

---

# Phase D — Deadline

## C-D1 — 47-day readiness panel on the global home — **S**

**Why now.** 04's success metric: "a wired 'Expiring ≤7d/30d' KPI and a 47-day readiness panel on the global home **well before 2027-03-15** (the 100-day step — the 200-day step has been in force since 2026-03-15)." The KPI half shipped in S-N0. This is the other half, and it is nearly free: `Dashboard.tsx` already fetches both inputs — `api.certificates` and `api.rotationRuns({limit:100})` (`Dashboard.tsx:136-143`, threaded at `:154-155` into `DashboardTrendCharts` at `:281`).

**Delivers.**
- `<ReadinessPanel certificates={servedCertificates} rotationRuns={servedRotationRuns} />` (`components/certs/index.tsx:116-146`) rendered on the global dashboard for **all** modes — its numbers are derived from served data, so it needs no `useDemo` gate, and must not acquire one.
- `manualAtRisk` line links into `/certificates?expiry=30d` (or the readiness tab: `/certificates?tab=readiness` — whichever the existing tab id is; verify against `CertificatesTab`) so the number is a door, not a dead end (03's "dashboard-numbers-as-links").
- The **simulator stays on Certificates** — the global home gets the posture statement, not the interactive tool (04: "no dashboard sprawl").
- Panel placement: below the KPI row, above the activity stream; no new fetches, no new endpoints, no layout framework changes.

**Excludes.** Migrating `certs/index.tsx`'s 22 hardcoded literals to `messages.ts` (that is C-I1's tranche — reusing the component adds zero new literals to the extraction count, so the budget is untouched); any change to `ReadinessPanel` internals beyond an optional `linkTo` prop.

**Tests first.** Dashboard suite: (a) panel renders from fixture certs+rotationRuns with the expected auto/manual split; (b) renders in real mode with `preview=false` (not demo-gated); (c) `manualAtRisk` link resolves to the certificates filter; (d) `ia_ratchets` stays green (no new `demoData` reads).

**Exit gate.** Seeded stack: global home shows the same readiness numbers as Certificates → Renewal readiness; no number on the panel can disagree with `/api/v1` responses. 04's last unmet dashboard metric flips to done, ~8 months ahead of the 100-day step.

---

# Phase P — Pickers

## C-P1 — Identity pickers + typed selects on Incidents (DA-10) — **M**

**Goal.** Incident intake stops being "paste a UUID and hope" (02: `input[type=text]` with placeholder `00000000-…`, evidence `[43-incident-fields.txt]`).

**Delivers.**
- **New `IdentityPicker` component** (`web/src/components/IdentityPicker.tsx`): DESIGN-rule-13 datalist pattern, copied from the cert-owner picker precedent (`Certificates.tsx:1077-1091`) — `<input list>` + `<datalist>` of `{id → name (kind, status)}` options, still accepts free typing (fixtures that set raw UUIDs keep working). Props: `identities`, `value`, `onChange`, `id`, optional `filterKinds`.
- `Incidents.tsx` loads the roster it never had: `useResource(api.identities)` (same call as Dashboard/Approvals/Certificates), and both free-text identity inputs become pickers: "Affected identity" (`:525-530`, feeds `graphBlastRadius` + `executeIncident`) and playbook "Target identity" (`:620-624`).
- Free-text **method fields become typed selects** where the vocabulary is closed: "Delivery method" / "Playbook delivery method" (placeholder "aws-iam") render as `<select>` over the served connector/delivery vocabulary if one is served, else a datalist over the known method ids; "Inventory ID" gets a datalist fed from the NHI inventory the console already loads elsewhere (`readNhiInventory`).
- Picker is exported for reuse — C-S1/C-S4 and the future approvals card consume it (this is the "picker groundwork" 06 promised).

**Excludes.** The approvals server-side pending list (the other half of DA-10's fix — it needs a backend list endpoint; noted for the next train); any change to incident mutation payloads (`IncidentExecutionRequest` etc. unchanged).

**Tests first.** Incidents suite: (a) identity fields render datalist options from fixture identities; (b) typing a raw UUID still submits unchanged (backward compat with existing fixtures at `incidents.test.tsx:75-76,120-122`); (c) selecting an option submits the **id**, displays the name; (d) delivery-method select offers only served vocabulary; (e) keyboard + label a11y on all replaced fields.

**Exit gate.** Seeded stack: an incident can be filed end-to-end without typing a single UUID; 02's DA-10 row flips to fixed (incidents half).

---

# Phase A — Admin split

## C-A1 — `/admin/*` route split with permanent redirects (DA-13 completion) — **M/L**

**Goal.** "Where do I administer X?" gets three real, deep-linkable, individually permission-gated routes. This finishes what S-A3 started with tabs.

**Delivers.**
- **Three new routes**: `/admin/access` (Access administration), `/admin/system` (System posture), `/admin/editions` (Editions & license). Each is its own page component with its own fetch scope (today one `loadAccessAdmin()` `Promise.all` at `Platform.tsx:202-230` loads everything for all three tabs — split it so `/admin/system` doesn't fetch members/tokens, etc.). `editions` data is consumed by both access and editions surfaces — fetch it where used, no shared-state module.
- **`/platform` becomes a thin redirector** and keeps working forever: reads `?tab=` (`platformTabFromSearchParam`, `Platform.tsx:98-102`) and returns `<Navigate to="/admin/{access|system|editions}" replace/>` — the `App.tsx:107` idiom. `/platform` stays in `appRoutePaths` and `globalBandRoutes` so `module_map` and old deep links / docs / muscle memory survive.
- **Nav:** the single Platform row (`navigation.ts:368`) is replaced by three rows in Govern & administer, labels `nav.item.adminAccess` / `adminSystem` / `adminEditions` (+ es-ES). Permissions: `routePermissionAny` gets `/admin/access: ["access:read"]`; system/editions inherit today's platform gate unless a finer served permission already exists.
- **Config repointing sweep** (the real bulk of this card): `realGuiSurfaces` — 9 surfaces route to `/platform` (F8, F10, F11, F13, F14, F15, F20, F40, F41; `navigation.ts:444-635`) — each repointed to its true `/admin/*` home; `apiWorkflowCoverage` — 3 entries (`apiWorkflowCoverage.ts:15,24,328`); `globalBandRoutes` gains the three routes; feature-map evidence (`scripts/check-feature-map-route-evidence.mjs` + `internal/featureparity/feature-map-backlog.json`) updated where it names `/platform`.
- S-B5's locked-module upsell keeps pointing at editions — retarget its link to `/admin/editions`.

**Excludes.** Content rewrites of the ~11 System disclosures (still DA-13 follow-up); any change to what the three surfaces render beyond the mechanical split; scale/HA surface re-homing beyond its current tab.

**Tests first.** (a) New `admin_split.test.tsx`: each `/admin/*` route renders its surface; `/platform`, `/platform?tab=posture`, `?tab=editions` redirect to the right route; unknown tab → `/admin/access`. (b) `route_parity` / `nav_completeness` / `module_map` / `naming_parity` updated for the new shape and green — naming_parity automatically enforces H1 == nav label == title for the three new routes. (c) Permission fixture: a user without `access:read` sees no admin rows they can't open. (d) Editions strings absent from `/admin/access` and `/admin/system` DOM (S-A3's guard, re-asserted per-route).

**Exit gate.** Every historical `/platform?tab=` URL in docs, Journeys, and screenshots resolves to the right `/admin/*` page; `grep -r '"/platform"' web/src` returns only the redirector + redirect tests; the three routes appear in the rail and in Cmd+K.

---

# Phase N — Nouns

## C-N1 — Entity-noun consolidation spike (decision doc only) — **S**

**Goal.** Turn "Identities vs Workloads vs Agents vs Owners" from a vibe into a decision. **No implementation this train** (per scope decision).

**Delivers.** `docs-internal/design-audit/08-entity-noun-decision.md`:
- **Inventory** walked from `realGuiSurfaces` metadata (featureId → component → routes → evidence): what each noun's surface actually operates on — Identities (F4/F6/F47/F59), Workloads (F25/F30/F61 — attestation/SVID/broker), Agents (F3/F54 — fleet/enrollment), Owners (F59, shares the Identities component).
- **Overlap evidence:** where the same object appears under two nouns; what the Fleet module (Agents+Workloads, live since S-B2) has already merged in practice; the `Identity.kind` enum (`api-types.gen.ts:1807` — six kinds including `workload_identity`) as the type system's own opinion.
- **Options with costs:** (1) keep four nouns + one-line disambiguators; (2) fold Agents+Workloads into a single Fleet surface (nav-level merge, URLs redirect); (3) single Identities surface with kind filters + Owners kept as the human/team plane. For each: URL impact, `realGuiSurfaces`/module-map impact, docs blast radius, es-ES impact.
- **A recommendation and a go/no-go checklist** (what evidence — support tickets, tour confusion, search queries — would flip it), and if "go": the sprint card, pre-written, for the next train.

**Excludes.** Any rename, any route change, any nav change. (The three hardcoded H1s discovered during research — `Identities.tsx:592`, `Agents.tsx:270`, `Owners.tsx:147` — are C-I2's to fix; the spike only records them.)

**Tests first.** N/A (doc-only card; the doc must cite live evidence, not vibes).

**Exit gate.** The doc exists, is self-consistent with 04's design decision that Identities/Owners are global-never-per-module, and 06's "revisit after B settles" line can point somewhere concrete.

---

# Phase S — Secrets auth-method console (DA-02, the flagship)

**Grounding.** The blocker text (`Secrets.tsx:1572-1575`): "Auth-method administration isn't in the console yet — Configured token methods, audience rules, issued-session ledger, and revoked methods are not available in the console yet." Backend reality (mapped 2026-07-14): the **only** served auth-method endpoint is `POST /api/v1/secrets/login` (`api.go:1138`); methods are built from static YAML at startup (`internal/server/machine_auth.go:20-120`); `authmethod.Session` is a return value that is **never persisted** — no list, no ledger, no revoke. "Grant workload access" today means hand-editing `secrets.machine_auth[]` server YAML (`docs/journeys/manage-secrets.md:59-75`). Authz is coarse tenant+scope (`authz.go:54-65`) — there is no per-secret ACL. Hence the split: one reuse-only card that closes Job 2 now, two backend cards that make the console honest, one UI card that assembles it.

## C-S1 — Grant console over existing endpoints (Job 2 in-console) — **M**

**Goal.** 02's Job 2 — "create secret, grant workload access, verify" — completes inside the console with **zero backend changes**.

**Delivers.**
- Secrets → Access tab gains a **"Grant workload access"** flow next to the existing login test: mint a scoped credential via the mutations already in the FE client — `createAPIToken` (`/api/v1/access/api-tokens`, `api.ts:1393`) for standing access or `issueEphemeralAPIKey` (`/api/v1/ephemeral/api-keys`, `:1529`) for TTL-bound access — with subject picked via C-P1's `IdentityPicker`, scopes picked from the served scope vocabulary (`secrets:read` at minimum), token shown once with copy affordance.
- **Grant ledger (what exists today):** list + revoke of API tokens via `apiTokens`/`revokeAPIToken` — a table on the Access tab: subject, scopes, expiry, revoke button (idempotent; `mutate()` already attaches `Idempotency-Key`, `api.ts:914-929`).
- Optional evidence trail: "file an access-change request" (`createAccessChangeRequest`) checkbox, since that is the served NHI-governance object.
- The `UnavailableState` placeholder shrinks to cover only what is still true post-S1 (methods/audience/session ledger — until C-S4), and gains the interim CLI documentation 02 asked for: the exact `trstctl-cli` commands + a link to the `manage-secrets` journey.
- **Verify step:** the existing login exchange, relabeled as step 3 of the grant flow ("create → grant → verify"), so the tab reads as Job 2 in order.

**Excludes.** Anything requiring new endpoints (methods list, session ledger, method revoke → C-S2/S3/S4); per-secret ACLs (not expressible in the authz model — recorded as a product gap in the card's deferral note, not smuggled in).

**Tests first.** Secrets suite: (a) grant flow mints a token with chosen subject+scopes and renders it once; (b) mutation carries an idempotency key; (c) token table lists + revokes (fixture); (d) ephemeral path sends `ttl_seconds`; (e) placeholder no longer claims grant is impossible; (f) permission fixture: no `access:write` → flow hidden, tab still renders read state.

**Exit gate.** Seeded stack: create secret → grant workload a scoped token → workload login/read verified, all in-console. 02's Job-2 verdict flips to PASS (interim). DA-02's "L (interim S)" interim milestone is done.

## C-S2 — Backend: auth-method read projection — **S/M**

**Goal.** The console can *see* the truth that lives in YAML: `GET /api/v1/secrets/auth-methods`.

**Delivers.**
- New read endpoint (no mutation): projects the per-tenant `[]authmethod.Method` the server already builds (`SecretsBackend.MachineAuthMethods`, `internal/api/secrets.go:88-99`) into `[{name, type, issuer, audience_rules, scopes_by_principal, source: "config"}]`. Read-only; secrets never serialized; gated on `secrets:read` (or `access:read` — match the Access tab's existing gate).
- OpenAPI spec + regenerated SDK + regenerated FE types (`api-types.gen.ts`) + `api.ts` client method, following the existing generator flow (`clients/sdk/openapi.json`).
- CLI parity: `secrets auth-methods list` row in the command table (`internal/cli/command.go`) — the table is data-driven, one entry.

**Excludes.** Any method *mutation* (create/edit stays config-plane — the honest statement is "methods are declared in server config"; the console projects, it does not edit); session anything (C-S3).

**Tests first.** Go: handler test — tenant A cannot see tenant B's methods (AN-1); response redacts anything secret-shaped (jwks paths OK, key material never present); OpenAPI round-trip test. FE: types regen committed, `route_parity`'s api-coverage check picks up the new op.

**Exit gate.** `curl /api/v1/secrets/auth-methods` on the seeded stack returns the YAML-declared methods; architecture linter green; no new datastore.

## C-S3 — Backend: issued-session ledger + revocation — **M/L**

**Goal.** Machine-login sessions become observable and revocable — the "issued-session ledger" and "revoked methods" halves of the DA-02 placeholder.

**Delivers.**
- **Session issuance becomes an event** (AN-2): the login path emits `secrets.machine_session.issued` (tenant, session id, principal, method, scopes, expiry) to the existing event log; a projection materializes the ledger. No new datastore, no direct table writes.
- `GET /api/v1/secrets/sessions` — the ledger (active/expired/revoked, filterable), tenant-scoped (AN-1).
- `POST /api/v1/secrets/sessions/{id}/revoke` — idempotent mutation (AN-5, `mutation:true`), emits `…session.revoked`.
- **Method disable overlay:** `POST /api/v1/secrets/auth-methods/{name}/disable` (+ enable) — an event-sourced tenant-level overlay on the config-declared methods; the login path (`machineLogin`) consults the overlay and rejects logins against a disabled method. This is the honest version of "revoked methods" without config-plane editing.
- **Enforcement scope, stated honestly:** revocation is enforced at every point that accepts a machine session credential. During the card, verify how `session_id` is consumed post-login; if sessions are pure TTL-bearer with no server-side check, the card adds the denylist check to that consumption path — and if no consumption path exists (login is informational), the ledger ships as observability + the disable overlay carries the enforcement weight, with that fact documented in the endpoint description. No silent security theater either way.
- Bounded projection worker per AN-7 conventions; CLI rows: `secrets sessions list|revoke`, `secrets auth-methods disable|enable`.

**Excludes.** Per-secret ACLs; method CRUD; any change to the login exchange's contract beyond the disable check.

**Tests first.** Go: event→projection round-trip; revoke idempotency (replay returns original result); disabled method rejects login with structured error; RLS isolation on the ledger; linter (idempotency-key rule fires on the new mutations). Integration against real PostgreSQL + NATS per §6 — no mocks.

**Exit gate.** Seeded stack: login → session appears in ledger → revoke → replay of revoke is a no-op → disabled method refuses new logins. Audit stream shows the events.

## C-S4 — Auth-method console UI (DA-02 faithful) — **M**

**Goal.** The placeholder dies. All four promised sub-surfaces exist.

**Delivers.** Secrets → Access tab (keeping C-S1's grant flow + login test) gains, over C-S2/S3's endpoints: **Configured methods table** (name, type, issuer, audiences, per-principal scopes, source=config, enabled/disabled state + disable/enable action); **Audience rules** rendered per method (read-only projection of config); **Issued-session ledger** (principal, method, scopes, issued/expires, status; revoke action with confirm); **Revoked view** (ledger filter, not a separate surface). All states from `StatePrimitives`; all new copy keyed with es-ES; all mutations through `mutate()`.

**Excludes.** Method create/edit forms (config-plane, by design — the UI says so inline); moving the surface out of `/secrets` (it stays a tab; module = Secrets per the S-B1 map).

**Tests first.** Secrets suite: methods table renders C-S2 fixture; disable action round-trips and reflects state; ledger renders, revoke dispatches idempotent mutation and updates row; `UnavailableState` for auth-methods is **gone** (assert the placeholder string is absent); a11y on tables + actions; permission fixtures (read-only user sees tables, no actions).

**Exit gate.** 02's DA-02 row: fixed. The Access tab contains zero "isn't in the console yet" text. Job 2 passes with a *method-scoped* grant story, not just token minting.

---

# Phase I — i18n sweep (DA-14)

**Mechanics.** The ratchet counts literals via `web/scripts/extract-i18n-messages.mjs` (four patterns: jsx-text, attributes, copy-properties, state-copy) into `extractedMessages.gen.ts` (1,243 entries, 1,869 source refs) and fails CI if entries exceed `extractedMessages.budget.json → maxExtractedMessages` (1,243 — currently zero headroom; enforced by `i18n.test.tsx:198-200` + `i18n:check`). The sweep = migrate literals to `messages.ts` keys **with hand-written es-ES entries** (`esESCatalog`, `messages.ts:6912-8710`), regenerate, and **lower the budget number in the same PR**. Ref counts by area: pages 1,354 · lib 392 · components 122 · auth 1.

**Sequencing rule.** A file is swept only *after* every card in this train that rewrites its surfaces has landed (sweeping first would churn the same lines twice). New code in every card ships keyed strings from day one (invariant 5), so the sweep is monotone.

## C-I1 — Sweep: components + lib + auth — **M**

**Delivers.** All 122 component refs (top: `certs/index` 22 — unblocks C-D1's copy debt, `secrets/index` 19, `DataGrid` 12, `GraphView` 10, `CommandPalette` 8…) and the 392 `lib/` refs (mostly copy-properties in config objects) + 1 auth ref migrated to keys; es-ES entries; budget lowered ≈1243 → ≈730. Shared components first because every page inherits their strings.

**Tests first.** `i18n.test.tsx` budget assertion updated to the new number *before* the sweep (red) → sweep → green. Pseudo-locale (en-XA) spot render on DataGrid/certs to prove keys resolve.

**Exit gate.** `npm run i18n:check` green at the lowered budget; zero component/lib refs in the regenerated catalog.

## C-I2 — Sweep: top pages (post-feature) — **M/L** — *blocked by C-P1, C-A1*

**Delivers.** The five heaviest page files, swept after their feature cards: Platform 114 (as the three post-split `/admin/*` pages), Incidents 91 (post-picker), CAHierarchy 82, Identities 81, Certificates 64 — ≈432 refs. Includes killing the three hardcoded H1s (`Identities.tsx:592`, `Agents.tsx:270`, `Owners.tsx:147` → `title={t("nav.item.…")}`, the `Workloads.tsx:290` pattern), which converts `naming_parity` from coincidence to construction. Budget lowered ≈730 → ≈430.

**Exit gate.** Budget at the new floor; `naming_parity` green with H1s sourced from keys.

## C-I3 — Sweep: remainder + ratchet to zero — **L** — *blocked by C-S4*

**Delivers.** Everything left: Secrets 167 (post-C-S4, so the new Access surfaces are swept once), Graph 62, Connectors 59, Assistant 55, Discovery 49, Posture 48, Policy 46, SSHTrust 45, Protocols 45, Workloads 37, Dashboard 36, Wizard 30 (the original DA-14 evidence)… down the tail. **`maxExtractedMessages: 0`**; the budget file's `policy` prose updated to "the budget is zero; it never rises"; the extraction script's exemption list re-audited (Styleguide stays excluded by design).

**Tests first.** Budget assertion → 0 (red) → sweep → green; `i18n.test.tsx` hard ceiling (`< 1273`) replaced by `=== 0`.

**Exit gate.** `extractedMessages.gen.ts` is empty (or deleted + script asserts emptiness); DA-14 closed as a *class*, not a count; es-ES catalog complete for every migrated string.

---

# Phase R — Release

## C-R1 — Docs, tour, ratchets, closeout — **S/M**

**Delivers.**
- `docs/demo-click-through.html` + `docs/web-console.md` + mkdocs pages updated for `/admin/*` (the only URL change) and the new Secrets Access surfaces; `docs_ia_parity.test.ts` extended: no doc outside historical audit files says `/platform?tab=` or "isn't in the console yet".
- `docs/journeys/manage-secrets.md` rewritten around the console grant flow (CLI path preserved as the automation variant).
- Ratchet consolidation: `ia_ratchets.test.ts` gains (a) the `=== 0` i18n floor reference, (b) a redirect guard (`/platform?tab=editions` must keep resolving), (c) the placeholder-absence guard from C-S4.
- CHANGELOG + release notes: closeout summary, the one URL change + its permanent redirects, rollback statement per card.
- Fresh screenshot set → `docs-internal/design-audit/screenshots-post2/`; a `09-closeout-verification.md` row flipping each of the six deferred items to its end state (five closed, nouns = decision doc + next-train card).

**Tests first.** The docs-grep extensions land red against pre-C-R1 docs, then the docs are fixed.

**Exit gate — the closeout gate.** (1) All cards merged; `make lint test`, architecture linter, `editions-gate` green. (2) The 15-stop tour re-run against the shipped nav + `/admin/*` + Secrets Access on the seeded stack. (3) **Job 1 and Job 2 both pass live with no CLI asterisk** — the asterisk 06 shipped with is gone. (4) i18n budget = 0. (5) Every 02 finding this train claims is re-verified against the running stack, and the six-item deferral list in 06 §"What is deliberately NOT in this train" annotated with where each landed.

---

## What is deliberately NOT in this train

Entity-noun **implementation** (C-N1's go/no-go decides; card pre-written in the decision doc); approvals **server-side pending list** (DA-10's other half — needs its own backend card; C-P1's picker is its groundwork); per-secret **ACLs** (not expressible in the coarse tenant+scope authz model — a product decision, not a console gap; recorded in C-S1); auth-method **config-plane editing** (methods stay YAML-declared by design; the console projects and overlays, it does not edit); System-disclosure **content rewrites** (DA-13's remaining half); DA-27 approvals queue enrichment (already shipped separately if 04's sequencing held — verify during C-R1, else next train).
