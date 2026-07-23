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
