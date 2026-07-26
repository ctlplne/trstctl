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

### Contribution terms: DCO for core, CLA only for `ee/` (D2, 2026-07-26)
- **The IP terms are written down before the first outside contribution.**
  `CONTRIBUTING.md` states the split plainly: core is MPL-2.0 and accepts
  patches under the **Developer Certificate of Origin** (`git commit -s`, no
  copyright assignment), while the proprietary `ee/` tree requires a signed
  CLA — with the honest note that most `ee/` requests can be met by a core
  change plus a seam, which stays DCO-only. A blanket CLA would tax every
  drive-by fix in core; DCO-only everywhere would leave the commercial tree
  undistributable. README links it and a PR template carries the checklist.

### Migration runs get a CLI (A0.4a, 2026-07-26)
- **`/api/v1/pqc/migrations` is no longer curl-only.** `trstctl-cli migration
  start | status | rollback` drives the licensed crypto-migration surface
  through the same route table every other command uses, with the
  `Idempotency-Key` discipline the mutating routes require. Against an
  unlicensed server the routes are absent, so the CLI reports 404 — the
  honest answer for a feature that edition does not serve. Documented in
  docs/cli.md with a worked example and mapped into the feature catalog
  (F16), so the CLI-vs-feature parity gate covers it.

### Break-glass succession is wireable; the dead migration twin is gone (A0.4b, 2026-07-26)
- **PCAS class-downgrade break-glass can now actually be configured.** The
  production minter passed a nil verifier, so a downgrade was refused
  unconditionally and `NewSignedBreakGlassAuthorizer` had only test callers.
  The signer now loads an operator-provisioned break-glass authority PUBLIC
  key from `<signer-keystore>/pcas-breakglass-authority.pem` (the same
  operator-provisions-trust pattern as the XREC plan bundle — never a
  control-plane input) and, when present, accepts a valid single-use token
  signed by that authority with durable spent-state inside the custody dir.
  Absent stays fail-closed; **present-but-unparseable fails startup** rather
  than looking configured while behaving as if it were not.
- **Deleted the dead fleet-migration twin.** `ee/pqcmigration.Orchestrator`
  (the discover→stage→reissue→track loop) and the whole `ee/fleet` package
  had zero non-test callers — both were shadowed by the differently
  architected served implementation (`ee/pqcmigration` api/server/plan) and
  by core's served CA-compromise fleet re-issuance. Removing them deletes
  ~400 lines of code that read as shipped and was not.

### Agent collector scope stated; api_key failures name their cause (A0.2c, 2026-07-26)
- **The unwired agent collectors are disclosed, not implied.** PKCS#11 token,
  Windows certificate/trust store, and in-cluster Kubernetes Secret
  collection exist as the injected-enumerator boundary in
  `internal/agent/discovery` but the shipped agent constructs no enumerator
  for them — limitations.md now says **not offered** and the package says so
  at the constructors, so nobody reads them as served. Adding one is an
  enumerator plus a flag, which is the point of the seam.
- **An `api_key` source with neither observations nor findings now says so.**
  It used to fall through to the generic "no server-side connector is
  configured for discovery source kind api_key", which read as "api_key is
  not served" when the real cause was an empty config.

### secret_store sources gain a real executor (A0.2b, 2026-07-26)
- **The creatable-but-never-runnable kind is gone.** `secret_store` sources
  now dispatch through the same served secret-manager connectors as
  `cloud_secret` (aws-secrets-manager, gcp-secret-manager, azure-key-vault,
  hashicorp-vault — the kinds share the providers config shape), instead of
  dead-ending in the generic "no server-side connector" fallback. Providers
  outside the served set (infisical, kubernetes-secrets, cicd-store) fail
  with the connector's specific "unsupported provider" refusal; building
  those listers stays demand-driven P-track work. Empty-provider errors are
  now kind-aware.

### Discovery schedules tick server-side (A0.2a, 2026-07-26)
- **"Continuous monitoring" stops needing an external cron.** A leader-only
  scheduler (`RunDiscoveryScheduler`, started with the CRL and lifecycle
  workers) sweeps every minute and queues a run for each enabled schedule
  whose source has no in-flight run and no run newer than its
  `interval_seconds` — through the exact event + projection + outbox path an
  operator-initiated run takes (AN-2/5/6), tagged
  `requested_by: discovery-scheduler`. A failed run counts as an attempt so a
  broken source retries next interval instead of hot-looping; one sweep
  queues at most 100 runs per tenant (AN-7 ahead of the bulkheaded worker).
  The due decision is a real-PostgreSQL integration test under RLS,
  including in-flight suppression, failed-run backoff, the sweep limit, and
  tenant isolation.

### Decision: the issuing CA key stays classical, on purpose (A0.3g, 2026-07-26)
- **Post-quantum keys are subject keys, not issuer keys, and that is now a
  recorded decision instead of an undisclosed ceiling.** Rationale: (1) a
  pure ML-DSA issuer breaks every stock TLS client that must chain to it,
  while an ML-DSA *subject* under a classical issuer interoperates today —
  the hybrid/pure subject leaf is where the market is; (2) the harvest-now/
  decrypt-later threat targets confidentiality (KEM), not the issuer
  signature: a classical issuing CA can be rotated to a PQ issuer when
  clients are ready, and nothing already issued becomes forgeable
  retroactively before then; (3) the mechanics (`signOpaqueTBS`'s classical
  allowlist, the hardcoded ECDSA-P256 issuing handle) are one contained
  boundary change behind `internal/crypto` when the CA-hierarchy PQC work
  (P8/F57 follow-up) schedules it — the crypto-agility property this
  architecture sells. limitations.md already discloses the ceiling; the
  roadmap owns the lift.

### The PQC census proofs run in CI on every push (A0.3f, 2026-07-26)
- **"PQC issuance is proven" stops depending on someone remembering a build
  tag.** A new required check, `pqc e2e (dodproof)`, runs
  `TestDODPQCProductionAssembly` — stock-OpenSSL pure ML-DSA-65 EST
  enrollment, the two-entry hybrid SVID Workload API response, and the
  CBOM→migration TLS rollout with rollback — against the exact shipped
  artifact on every push. The job gates loudly on an ML-DSA-capable stock
  OpenSSL (>= 3.5) so runner drift cannot silently skip the proof; the check
  is pinned into branch-protection.json, docs, and a guard test.

### The additional Workload-API SVID is audited like the classical one (A0.3e, 2026-07-26)
- **The licensed second SVID stops being invisible to the event log.** The
  Workload API's additional-issuer mint now emits the same
  `spiffe.svid.issued` audit event and credential-graph node the classical
  SVID gets, with its hint in the payload (`x509-additional:<hint>`), so
  posture can tell the pair apart. Profile parity note: the classical SVID's
  EKUs are equally fixed by the SVID signing profile, so the additional
  issuer's serverAuth/clientAuth EKUs are parity, not drift; and like every
  Workload-API SVID it is deliberately ephemeral — audited, graphed, but not
  an inventory row.

### Direct-API issuance scope decided; dead licensed twin removed (A0.3d, 2026-07-26)
- **The identity API's server-side classical keygen is a decision, not a
  gap.** `issuanceDispatcher.issueLicensed` was assigned at boot and called
  nowhere — a dormant seam diligence would flag. It is deleted; the
  dispatcher documents that ephemeral NHI identities take server-generated
  classical keys by design, and CSR-based enrollment (including licensed
  subject algorithms) belongs to the enrollment protocols through
  `protocolIssuer`, whose licensed twin is live and tested.

### ACME's algorithm transparency is pinned by test (A0.3c, 2026-07-26)
- **"ACME never parses the CSR" is now a contract, not an accident.** A new
  test drives a full RFC 8555 order with a real client and finalizes with a
  CSR whose proof-of-possession the core parser rejects; the order completes
  and the CA seam receives byte-identical CSR data. If anyone "hardens"
  finalize with a core-parser check — breaking the licensed issuer's
  ownership of subject-algorithm verification — this test fails and names
  the seam contract.

### Profiles can name post-quantum algorithms when licensed (A0.3b, 2026-07-26)
- **`allowed_key_algorithms` stops failing closed on licensed labels.**
  `crypto.Classify` gains a licensed-classifier seam
  (`InstallLicensedAlgorithmClassifier`, filled by attachPQC with
  `ee/pqc.ClassifyAlgorithm`), so profile authoring accepts ML-DSA / SLH-DSA
  / hybrid signature labels — and still rejects ML-KEM labels, which cannot
  sign certificates. Enforcement stays exact-match: a profile listing
  `ML-DSA-65` admits pure ML-DSA-65 CSRs; a hybrid enrollment carries a
  classical subject key and remains governed by its classical family label.
  Unlicensed binaries keep failing closed on all of it.

### CMP gains the licensed-CSR seam (A0.3a, 2026-07-26)
- **CMP can now carry subject algorithms the core toolchain cannot check.**
  `ParseCMPRequest` previously verified the carried PKCS#10 with the strict
  core parser *before* any licensed parser could see it, so CMP hard-rejected
  what EST already accepted. `ParseCMPRequestWithVerifier` delegates exactly
  the inner-CSR check to an injected verifier — PKIMessage protection stays
  core-verified, unconditionally — and the served mount binds the same
  licensed-aware verifier EST uses. Covered by seam tests proving the
  verifier is consulted with the exact CSR bytes, a refusing verifier fails
  closed, and tampered protection still dies even with an accepting
  verifier. (SCEP intentionally keeps the core-only path: its CMS reply
  cannot be delivered to a signature-only subject key — a protocol limit
  documented in limitations.md, not a code gap.)

### Terraform provider + Python SDK become published artifacts (B6, 2026-07-26)
- **The provider's acceptance test now actually runs.** CI drives a REAL
  `terraform apply` (pinned terraform 1.9.8, SHA256SUMS-verified download)
  through the provider's plan/apply/read/delete loop on every push —
  previously `TRSTCTL_RUN_TERRAFORM_ACC` was set nowhere and the test was
  dead weight.
- **Release tags publish the provider in the Terraform Registry layout.**
  `scripts/release/terraform-registry-assets.sh` builds per-OS/arch zips
  (binary named `terraform-provider-trstctl_v<version>`), the protocol-6.0
  registry manifest, and a GPG-signed SHA256SUMS; the release job uploads them
  as GitHub Release assets with SLSA provenance. Signing requires the
  protected `terraform-registry-signing` environment — unsigned assets are
  refused rather than emitted.
- **The Python SDK ships to PyPI and the Release.** A release job stamps the
  tag version into `clients/sdk/python`, builds sdist+wheel, `twine check`s
  them, uploads them as Release assets with SLSA provenance, and pushes to
  PyPI via the protected `pypi-publishing` environment (`PYPI_API_TOKEN`) —
  missing credentials fail loud, never skip silently.

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
