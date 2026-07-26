# Changelog

All notable changes to trstctl are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches
1.0. trstctl is **pre-1.0 and under active hardening**: minor versions may carry
breaking changes, and the tagged versions below are development milestones, not
supported release lines (see [SECURITY.md](SECURITY.md) for the support policy and
[docs/limitations.md](docs/limitations.md) for what the running binary serves today).

This file is the human-readable companion to the git tags; the
[README roadmap](README.md#roadmap) describes what is planned.

## [Unreleased]

### SPIRE upstream-authority plugin ships (B2, 2026-07-26)
- **The SPIRE plugin is now an obtainable artifact, not a build-from-source
  exercise.** `trstctl-spire-upstream-authority` joins `make build`'s `CMDS`
  and the reproducible-binary check, and every release tag publishes
  `trstctl-spire-upstream-authority-linux-{amd64,arm64}` GitHub Release assets
  with a SHA-256 manifest and their own SLSA provenance
  (`trstctl-spire-upstream-authority.intoto.jsonl`), gated on the same
  test/required-checks contexts as every other publishing job. SPIRE loads the
  plugin from its own host (`plugin_cmd`), so it deliberately stays out of the
  container image; docs/limitations.md now states the exact distribution
  contract instead of a bare "served".

### CBOM licensed posture — real FIPS targets (A0.1, 2026-07-26)
- **A licensed binary's CBOM now names its migration targets.** The MPL core
  still emits edition-neutral `licensed-*` placeholders and recognizes no
  licensed algorithm family — that fence is deliberate and unchanged. A new
  seam, `cbom.InstallLicensedPosture`, is filled from the tagged PQC attach
  block with `ee/pqc.CBOMTargetFor` + `ee/pqc.CBOMClassifyKey`, so with
  FeaturePQC licensed the inventory maps classical signatures →
  **ML-DSA-65 (FIPS 204)**, key establishment → **ML-KEM-768 (FIPS 203)**, and
  deprecated DSA → **SLH-DSA-SHA2-128s (FIPS 205)**; ML-DSA / ML-KEM / SLH-DSA
  / SPHINCS+ / Kyber / Dilithium / hybrid labels classify as strong and not
  quantum-vulnerable instead of "unrecognized"; and pure post-quantum assets
  carry `future-ready` — which makes `percent_migrated` a live number instead
  of a structural zero. Hybrid assets deliberately stay `migration-required`:
  they are quantum-safe today but the migration endpoint is the pure
  post-quantum algorithm. Covered by `ee/pqc/cbom_test.go`, including a mixed
  classical + post-quantum estate reporting 25% migrated.

### Static console demo enablement (demo.trstctl.com, 2026-07-25)
- **The console can now ship as a zero-backend static demo.** A build-time
  flag (`VITE_TRSTCTL_DEMO=1`, set only by the demo-site build in
  trstctl-website) makes preview mode available in a production bundle,
  lands the visitor signed-in on the showcase, and — new for preview
  everywhere — activates transport isolation: the API client refuses every
  server call before fetch, with translated error copy (2 new keys per
  catalog; digests re-pinned, machine translations flagged for review).
  The product embed never sets the flag, and a new embed-purity gate
  (`internal/webui/demo_purity_test.go`) fails the build if the committed
  console ever carries the preview identity.

### Design-review remediation (R-01…R-09, 2026-07-25)
- **Every form control in the console now actually has a style.** An external
  design review found — and we verified — that `.ui-input`, the class worn by
  ~145 inputs/selects/textareas across 11 pages, was defined in no stylesheet,
  ever: every form field rendered as raw native browser chrome (white fields
  in the flagship dark theme). The family now exists (token-correct field,
  36px to pair with buttons, themed select/textarea/file variants,
  aria-invalid state), native checkboxes/radios ride a gold `accent-color`,
  and a new foundation guard fails the build if any referenced `ui-*` class
  has no rule — it immediately caught a second stillborn class (`ui-button`,
  10 raw buttons now on the Button primitive).
- **Forms became primitives (DESIGN.md rule 14).** `Input`/`Select`/
  `Textarea` plus a `Field` unit that owns label/description/error and their
  aria wiring; piloted on Request Credential's zod+RHF form; raw-control
  counts in pages are budget-ratcheted downward (migrate-when-touched).
- **Focus is its own token (rule 2, both themes).** Focus rings rode
  `--brand-accent`, which is gold-family in light mode — collapsing the
  gold-acts/mint-focuses semantics. A dedicated `--focus` token keeps mint in
  both themes, swept through every focus ring, with a 3:1 non-text contrast
  guard and a mint-hue-family pin.
- **Discipline sweeps.** Eyebrow: nine hand-rolled tracked-uppercase clusters
  (Secrets ×8, Login) plus shell/pqc/styleguide stragglers migrated to the
  primitive, with a tracking ratchet. Shell toggles moved to the Button
  primitive, killing a focus ring class that resolved to no configured color.
  Dead tokens deleted (`--console-accent`, unused density rungs) — the suite
  was certifying them as alive. Rule 15 codifies Card-vs-`ui-panel` and
  DataGrid-vs-`ui-table` criteria; monolith pages split as touched
  (web/AGENTS.md). Repo-wide prettier normalization un-reds CI's
  format:check after the dependency refresh.

### Live dashboard tiles (S-N1, 2026-07-24)
- **Home's numbers stay current without an operator reflex.** The Dashboard's
  eight resources moved off `useResource` onto the query layer with a live-tile
  contract (certctl's PERF-H1 pattern): KPIs poll every 30s and the audit rail
  every 60s while the tab is visible, hidden tabs poll nothing, and returning
  to the tab refreshes exactly the live queries immediately. The optional-probe
  readers (NHI inventory, secrets count, open incidents, recent audit) now fail
  soft to their empty fallbacks, so a missing or erroring optional endpoint can
  never stall the first-run gate or error the whole dashboard.

### Per-locale catalog split (S-C10, 2026-07-24)
- **The entry chunk drops a third: 239 → 163 kB brotli.** The es-ES and de-DE
  production catalogs moved to per-locale modules loaded on demand by the
  I18nProvider; English (the source catalog) and the pseudo transforms stay
  eager. Until a lazy catalog resolves, lookups fall back to English — never
  to raw keys — and the tree re-renders translated the moment the module
  lands (covered by a new in-session locale-switch test). Strings are
  byte-identical to their pre-split location, so the translation-review
  digests did not move; the `satisfies` completeness contract survives in the
  split modules, and the entry size-limit budget is lowered to 185 kB to lock
  in the win.

### Console engineering train (S-C4 / S-C5 / S-C8 / S-C9, 2026-07-24)
- **S-C5 — the data and form layers arrive.** TanStack Query is the console's
  query layer (`src/lib/query.tsx`; provider in `AppRoutes`), piloted on
  Owners: the cache is the row truth, mutations write through and invalidate —
  the refetch `useResource` never had. Mutation forms go schema-first with
  zod + react-hook-form, piloted on Request Credential with per-field errors.
  Adoption policy in `web/AGENTS.md`: new surfaces use the new layers;
  existing pages migrate when touched.
- **S-C9 — typography primitives and a real merge fix.** `Eyebrow` and `Num`
  encode the micro-label and inline-data rules; `text-2xs` replaces the five
  `text-[10px]` arbitraries. The Eyebrow test exposed a latent bug: cn()'s
  tailwind-merge dropped the custom font-size tokens as color conflicts —
  fixed by registering the token scale, for every cn() call site.
- **S-C8 — Storybook workbench.** Storybook 10 (react-vite + a11y addon)
  renders stories against the real tokens with a dark/light toolbar; six
  starter story files cover the primitives and shared components. Coverage
  extended 2026-07-24 to the data-heavy set — DataGrid (sorting, selection +
  bulk slot, and all five list states), the full chart palette (tones,
  StatTile, Meter, BucketBar, time bars, Donut, Sparkline/AreaTrend),
  CredentialChip, the DetailDrawer/Dialog overlays, and StatePrimitives —
  10 titles / 38 stories in the static build.
- **S-C4 — Playwright e2e + visual regression, authored.** Shell smoke (rail,
  scoped sidebars, palette, the `?tab=` redirect) and masked dark-theme visual
  baselines, targeting the seeded demo stack (`npm run e2e`). Browsers were
  not installable in the authoring sandbox — first local run generates
  baselines (`--update-snapshots`).
- **Contracts.** `web/AGENTS.md` is the console's leaf contract; DESIGN.md
  rules 5/6/12 updated to the primitives and the workspaces-vs-lenses ruling;
  the root AGENTS.md now states the AN-4/6/7 enforcement asymmetry plainly;
  the visual-asset audit (design-audit/10) confirms nothing reader-facing
  depicts the retired chips shell.

### IA train closeout (S-C3 / S-C6 / S-C7, 2026-07-24)
- **S-C3 — the console code-splits by page.** Every authenticated surface is a
  lazy route chunk (70 chunks; the entry is the shell + vendor + the typed
  i18n catalogs), with a Suspense boundary at the shell outlet that announces
  loading. The compressed budget is enforced by `npm run size` (size-limit:
  entry, largest page chunk, and total shipped JS); Vite's raw-size warning
  threshold sits just above the entry so a new oversized chunk still trips it.
  Follow-up noted: per-locale catalog splitting would shrink the entry further.
- **S-C6 — the command palette groups by space and speaks verbs.** Route
  results render under space headings in rail order (Home first; spaceless
  routes last under Routes), Enter-activates-first agrees with the visible
  order, and four permission-gated verb entries land where the verb happens:
  Rotate a secret, Grant workload access, Issue SSH user certificate, and
  Preview blast radius.
- **S-C7 — the workspaces-vs-lenses rule is now written down.** A tab becomes
  a sidebar route only when it is a distinct served workspace (own evidence,
  own workflows, own name); an alternate view over the same object domain
  stays a URL-addressable in-page tab. Rulings: Secrets' six workspaces are
  routes (S-C2); Certificates' four tabs and Discovery's four tabs are lenses
  and stay. Home's five inventory counters now deep-link into their spaces,
  completing the every-number-is-a-link pass.

### Secrets workspaces as routes (S-C2, 2026-07-23)
- **The Secrets mega-page's six workspaces are sidebar routes now.** The store
  keeps `/secrets`; **Secret engines** (`/secrets/engines`), **Machine access**
  (`/secrets/access`), **One-time shares** (`/secrets/sharing`), **CI scanning**
  (`/secrets/scanning`), and **Sync targets** (`/secrets/sync`) each own a row
  in the Secrets space sidebar, grouped Store & engines / Access & sharing /
  Delivery & scanning. The in-page tab strip is gone; historical
  `/secrets?tab=` deep links redirect permanently with their remaining query
  intact (the C-A1 `/platform` precedent). Every route carries its own H1 and
  title (naming parity), RBAC gate, and feature evidence; the rail-row budget
  consciously grows by five (ceiling 38).

### Unified shell (spaces IA, 2026-07-23)
- **The console is now five spaces behind an icon rail.** The S-B2
  chips-in-sidebar module switcher became a left rail of spaces that each own
  every surface of one concern — *Certificates & PKI*, *Secrets*,
  *Workload & SSH*, *Posture & response*, and *Platform* — with Home carrying
  the Dashboard, Journeys, and the needs-action worklists. The URL decides the
  active space (deep links light up their owning space; picking a space lands
  on its first permitted route), the per-space audit lenses and 34-row rail
  budget survive, and no route URL, nav label, or feature ID changed, so
  bookmarks and API couplings are untouched. Operator docs (web-console, the
  demo click-through, platform-and-api) describe the new shell.
- **DA-02 closed — the secrets auth-method console.** Secrets → Access now grants
  workload credentials in-console (scoped standing tokens or TTL-bound ephemeral
  keys, reveal-once, list + revoke), projects the configured machine-auth methods
  (issuer, audience rules, scopes, source) with a per-tenant, event-sourced
  disable/enable overlay enforced at the login exchange, and serves the
  issued-session ledger (`GET /api/v1/secrets/sessions`) with idempotent,
  event-sourced revocation (`machine_sessions` projection, migration 0086).
  New API surface: `GET /api/v1/secrets/auth-methods`,
  `POST /api/v1/secrets/sessions/{id}/revoke`,
  `POST /api/v1/secrets/auth-methods/{name}/disable|enable` — with CLI parity
  (`secrets auth-methods list|disable|enable`, `secrets sessions list|revoke`).
- **The `/platform` grab-bag became three routes** — `/admin/access`,
  `/admin/system`, `/admin/editions` — each deep-linkable and fetch-scoped.
  This is the train's only URL change and every historical `/platform` (and
  tab) link redirects permanently; rollback is a nav-config revert.
- **DA-10:** incident intake uses identity pickers and served vocabularies —
  no more pasting raw UUIDs on faith. **DA-14 closed as a class:** the i18n
  extraction ratchet (now AST-based) reads zero hardcoded user-facing strings
  and is sealed at zero. **47-day readiness** panel now lives on the global
  home, ahead of the 2027-03-15 100-day step.
- **Locales:** Spanish is joined by **German (de-DE)** as a production locale;
  both catalogs are completeness-enforced by the type system. Long-tail
  machine-seeded entries are enumerated for human translation passes.
- Rail budget consciously re-set 32 → 34 rows for the admin split; entity-noun
  consolidation deliberately deferred behind an evidence checklist.

### Security & hardening
- Remediation pass (R0–R9) hardening the served, multi-tenant profile: served
  end-to-end **revocation** (a revoked credential stops validating in the product's
  inventory/records), an idempotent first-API-token bootstrap, served X.509 issuance
  with CDP/AIA/SKI and certificate-profile enforcement, quorum-gated cross-signing,
  versioned event envelopes with version-aware projections, bounded/tenant-scoped
  lifecycle history, and TTL'd idempotency keys.
- Supply chain: GitHub Actions and base/runtime images pinned by digest, the
  embedded-PostgreSQL binary pinned against a committed provenance manifest, a
  CycloneDX SBOM and `govulncheck` gate in CI, CODEOWNERS over the root-of-trust
  paths with required code-owner review, and checksum-verified CI tool installs.
- Docs/observability honesty: a reality-tested `docs/limitations.md` that states
  served-vs-library status for every advertised capability, so the binary cannot
  silently over-claim.

### Added
- `CHANGELOG.md` (this file), linked from the README and SECURITY.md (DOCS-005).

### Changed — web console information architecture (IA train)

*Superseded within this release: the module-switcher chrome below evolved into
the five-space unified shell (see "Unified shell (spaces IA)" above). The
defect-class guards it introduced — `naming_parity`, `nav_completeness`,
`module_map`, demo-data isolation, docs IA parity — carry forward unchanged
and still gate the spaces IA.*

- **Option A — refined rail.** The sidebar is re-grouped into four question-shaped
  bands (Inventory / Issue & automate / Detect & respond / Govern & administer) and
  every previously hidden product surface (CA hierarchy, certificate profiles, SSH
  trust, code signing, operations, notifications, privacy, integrate, API explorer)
  is now visible in navigation. One name per surface: nav label, page `<h1>`, and
  document title agree everywhere (a permanent `naming_parity` guard enforces it).
  Platform gains a dedicated **Editions & license** tab, quarantining commercial
  licensing rows off the operational Access and System tabs.
- **Option B — module workspaces.** A top-of-rail **Module** switcher (Certificates &
  PKI, Secrets, SSH, Signing, Fleet) scopes the middle band to one product; the
  cross-domain global planes (identities, discovery, risk, posture, graph, incidents,
  approvals, governance, audit) stay visible under every module. Module homes carry a
  thin served KPI strip that deep-links into filtered lists. The shared audit stream
  gains per-module lenses via `?module=` with a clearable scope chip — one stream, one
  hash chain, N lenses, never per-module silos.
- **Dashboard integrity & renew.** Real-mode dashboards render served data only (the
  fabricated demo trend/activity/bands are gone) and the four action KPIs are wired to
  live counts; the expiring-certificate worklist and detail drawer now offer Renew,
  wired to the identity lifecycle transition.
- **No route/URL changes.** The entire IA change is navigation chrome; every route
  keeps its path, so deep links, journeys, and muscle memory survive. Permanent CI
  guards (`naming_parity`, `nav_completeness`, `module_map`, demo-data isolation, docs
  IA parity) keep the fixed defect classes from returning.

## [0.5.0] - 2026-06-13
- Hardening milestone toward an enterprise-GA bar for the self-hosted, multi-tenant
  profile: isolated signer custody (sealed CA key persisted across restarts), the
  assembled control-plane server (`cmd/trstctl` → `internal/server`) serving the
  event spine, projections, orchestrator, and REST API, and the architecture linter
  (`tools/trstctllint`) enforcing AN-1/AN-3/AN-5/AN-8 in CI.

## [0.4] - 2026-05-31
- Pre-release development milestone.

## [0.3] - 2026-05-31
- Pre-release development milestone.

## [0.2] - 2026-05-31
- Pre-release development milestone.

## [0.1] - 2026-05-31
- Initial tagged development milestone.

[Unreleased]: https://github.com/ctlplne/trstctl/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/ctlplne/trstctl/releases/tag/v0.5.0
[0.4]: https://github.com/ctlplne/trstctl/releases/tag/v0.4
[0.3]: https://github.com/ctlplne/trstctl/releases/tag/v0.3
[0.2]: https://github.com/ctlplne/trstctl/releases/tag/v0.2
[0.1]: https://github.com/ctlplne/trstctl/releases/tag/v0.1
