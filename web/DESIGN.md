# trstctl design system

The console shares one design language with trstctl.com: ink-black blue
surfaces, warm cream ink, **gold** primary (`#ffd166`), **mint** accent
(`#5eead4`), and the Sora / DM Mono / Syne type trio. Dark is the flagship
theme (a direct port of the website palette); light is the same language on
warm paper. The living spec renders at **`/styleguide`** — every swatch and
component there comes from the real implementation.

This file is the console's whole in-repo contract: the visual system and the
shell, data, i18n, and test rules the S-C1…S-C10 trains established. When a
rule here and a guard test disagree, the guard is the truth — fix the rule in
the same change.

## Where things live

| Layer                                                     | File                                                                                                                               |
| --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Tokens (colors, type, density, radius, elevation, motion) | `src/index.css` (`:root` + `.dark`)                                                                                                |
| Tailwind mapping (every token becomes a utility)          | `tailwind.config.js`                                                                                                               |
| Primitives                                                | `src/components/ui/` (Button, Card, Skeleton)                                                                                      |
| Shared components                                         | `src/components/` (PageHeader, PageTabs, StatusBadge, CredentialChip, DataGrid, DetailDrawer, Dialog, EmptyState, StatePrimitives) |
| Typography primitives (S-C9)                              | `src/components/typography.tsx` (Eyebrow — the one tracked micro-label; Num — inline mono tabular data values)                     |
| Charts                                                    | `src/components/charts/` (StatTile, Meter, BucketBar, TimeBar, Stacked, Donut, Sparkline, AreaTrend + tone palette)                |
| Contract tests                                            | `src/__tests__/design_system_foundation.test.tsx` (token presence, WCAG AA pairs, primitive reuse)                                 |

## Rules

1. **No raw colors.** Every color is a semantic token consumed as
   `hsl(var(--token))` or a Tailwind utility (`bg-primary`, `text-risk-high`).
   The foundation test fails the build on drift; keep it that way.
2. **Gold means "act", mint means "focus" — in both themes.** The primary
   button is gold with near-black ink in both themes (≈13:1). Focus
   indicators ride the dedicated `--focus` token (`ring-focus` /
   `border-focus`, and the global `:focus-visible` outline), which stays in
   the mint family in light mode too — `--brand-accent` is brand chrome, not
   the focus channel (its light value is gold-family, which used to collapse
   the two semantics). Selection uses the primary. Never introduce a second
   call-to-action color.
3. **Destructive is a variant, not a className.** Revoke/delete/offboard
   actions use `variant="destructive"` (confirmations) or
   `variant="destructive-outline"` (row-level openers). Async buttons take
   `loading`, which renders the spinner and sets `aria-busy`.
4. **Credential material renders as a `CredentialChip`.** Fingerprints,
   serials, node IDs, tokens: DM Mono, middle-truncated, copyable. Never nest
   it inside another interactive element.
5. **Digits align, data is mono (S-C9).** All tables inherit `tabular-nums`;
   standalone numerals opt in with the utility class, and inline data values
   in sans copy (counts, TTLs, serials, timestamps) render through `Num`.
   Micro-labels use the single `Eyebrow` cluster — do not hand-roll new
   uppercase/tracking combinations (PageHeader's accent eyebrow is the one
   sanctioned brand-flavored variant). `Eyebrow` and `Num`
   (`src/components/typography.tsx`) are the ONLY sanctioned micro-label and
   inline-data styles. `text-2xs` is the smallest type rung and there are no
   `text-[Npx]` arbitraries. `cn()` (`src/lib/utils.ts`) extends tailwind-merge
   with the token font sizes — without that, `text-caption` and a color utility
   silently conflict — so a new token scale is registered there in the same
   change that adds it.
6. **The page's object list renders first; workspaces are routes, lenses are
   tabs (S-C7).** A view that is a distinct served workspace — its own feature
   evidence, workflows, and name — is a sidebar route in its space (Secrets'
   six workspaces). An alternate view over the same object domain stays a
   `PageTabs` lens with state synced to `?tab=` so it deep-links
   (Certificates' four lenses, Discovery's four pipeline stages). The full
   rule and rulings live beside the space registry in `src/lib/navigation.ts`;
   changing one is an IA change (registry comment, guards, docs, one commit).
7. **Loading keeps the page's shape.** Tables and cards use `Skeleton` blocks,
   not spinner lines. The five list states come from `StatePrimitives` /
   `EmptyState` only.
8. **Motion is subtle and safe.** 160ms/220ms tokens, entrance animations on
   drawers/dialogs/overlays only, everything behind `motion-safe`.
9. **Charts pull from the tone palette.** Use `ChartTone` names, never
   hand-picked hues; several tokens alias in dark mode, so check `/styleguide`
   when composing multi-series charts.
10. **New user-facing strings are typed message keys.** English goes in
    `src/i18n/messages.ts`; the `es-ES`/`de-DE` entries go in the per-locale
    modules `src/i18n/catalog.es-ES.ts` / `catalog.de-DE.ts` (S-C10 — a
    missing key is a type error there). Skip either and the extraction
    ratchet in `extractedMessages.budget.json` or the type-checker will fail —
    never raise the budget. The production-catalog sha256 digests in
    `src/__tests__/i18n.test.tsx` are a REVIEW RATCHET: adding or changing a
    translation legitimately breaks them, so re-pin them in the same change
    with a comment saying what was reviewed. Machine-authored translations are
    flagged for human review before release. Storybook stories are excluded
    from extraction — keep fixture copy out of the catalog.
11. **Multi-input operator tasks are wizards, not flat forms.** Anything with
    three or more decisions renders as a `StepShell` stepper (see Setup,
    Request Credential, Add Certificate): one job per step, validation gates
    Next, and the last step is always a review of exactly what will happen.
12. **Journeys beat menus.** Cross-page workflows live in the `/journeys` hub
    (`src/lib/journeys.ts`): each step deep-links to the exact surface — a
    space route or a `?tab=` lens — and steps with a detector check themselves
    off from served data. New multi-page flows get a journey definition, not a doc-only
    walkthrough.
13. **Never make the operator retype a value the console already knows.**
    Known entities render as selects or `datalist` autocomplete fed from
    loaded data (owners, members, secret names), and created identifiers carry
    forward into the next step.
14. **Form controls are primitives.** New fields are `Input` / `Select` /
    `Textarea` inside a `Field` (`src/components/ui/`): Field owns the
    label/description/error unit and its aria wiring, the controls wear the
    `.ui-input` family from `index.css`, and errors flip `aria-invalid`
    (rendered as a destructive border). Never hand-assemble control styling
    or label/error markup. Existing raw `<input>`s migrate when their page is
    next touched — the raw-control budget in
    `design_system_foundation.test.tsx` only goes down. Native checkboxes and
    radios ride the gold `accent-color` base rule until a Checkbox primitive
    exists.
15. **One panel, one table — the criteria (R-05).** `Card` is the panel:
    new sectioned surfaces use `Card`/`CardHeader`/`CardTitle` (headings get
    `text-title` for free instead of a hand-set size). `.ui-panel` is a
    legacy alias with the identical visual spec — do not add new call sites;
    migrate to `Card` when the surface is next touched (exemplar:
    Request Credential's boundary panel). `DataGrid` renders any list that
    LOADS (it owns the five list states, sorting, selection, virtualization);
    `.ui-table` is only for static definition-style data that can never be
    loading/empty/error. A `.ui-table` fed by a fetch is a bug: it has no
    state story.
16. **The shell is the IA (S-C1/S-C2).** The console is one unified shell: an
    icon rail of five spaces over a space-scoped sidebar, with Home
    (Dashboard, Journeys, needs-action worklists) as the only global plane.
    The single source of IA truth is the space registry `navSpaces` in
    `src/lib/navigation.ts`; `navGroups` and the module helpers derive from
    it. Every customer route lives in exactly one space group (`module_map`
    guard: global XOR one space), the URL decides the active space so
    switching spaces navigates, and a route's nav label, its page H1, and its
    `document.title` are the SAME message key (`naming_parity` guard). The
    rail-row budget is a ceiling of 38 (`accept/UX-03`, `accept/U8-6`) — spend
    it consciously, never raise it silently.
17. **New surfaces read through the TanStack Query layer (S-C5a).**
    `src/lib/query.tsx` owns data access: `AppQueryProvider` mounts in
    `AppRoutes`, and `useApiQuery` deliberately mirrors the old `useResource`
    `{ data, loading, error }` shape so a migration is a small diff. Existing
    pages migrate off `lib/useResource` when they are next touched; do not add
    new `useResource` callers. Mutations write through `setQueryData` for
    instant UI and then `invalidateQueries` for server truth (exemplar:
    `pages/Owners.tsx`). Live tiles pass `{ live: { intervalMs } }` —
    visible-tab polling plus an immediate refresh on return to visibility —
    and never a hand-rolled `setInterval`.
18. **Mutation forms are schema-first (S-C5b).** zod owns the field contract,
    react-hook-form wires inputs and per-field errors, and the submit handler
    only ever sees valid, trimmed values (exemplar:
    `pages/RequestCredential.tsx`). API failures stay separate from validation
    errors. This is rule 14's markup contract with a validation contract on
    top of it.
19. **Pages are lazy chunks, so tests await (S-C3).** Routes load through
    `lazyPage` in `App.tsx` and the Suspense boundary lives at the shell
    outlet, so a test's FIRST read of route DOM must be an `await findBy…` —
    never a synchronous read. Query results also land on a macrotask, so the
    same rule governs the first read of query-fed DOM: S-C3 applies to data,
    not just to chunks. The compressed bundle budget is `npm run size`; spend
    it consciously.
20. **Monolith pages split as they are touched (R-09).** Secrets, CAHierarchy,
    Discovery, and Incidents are past the size where per-file conventions stay
    reviewable, and design drift concentrates there. When a change materially
    edits one of them, first extract the section being edited into
    `pages/<page>/…Parts` files (the `pages/secrets/SecretsPageParts.tsx`
    pattern), then make the edit. No standalone big-bang refactor.

## Test surfaces

- **Vitest** owns behavior. The guards that pin the system and the IA
  (`design_system_foundation`, `module_map`, `nav_completeness`,
  `naming_parity`, `ia_ratchets`, `accept/UX-03`, `accept/U8-6`, the size
  budget, the i18n digests) are updated IN the change that moves the thing
  they pin, with the rationale in the diff — never loosened to "make it pass".
- **Playwright (S-C4)** owns real-browser smoke and pixels: run
  `npm run e2e:install` once, then `npm run e2e` against the seeded demo stack
  (or `TRSTCTL_E2E_URL`). Visual baselines are committed, so a diff is a design
  decision. Type-check the suite with `npx tsc -p e2e/tsconfig.json --noEmit`.
  Keep specs shallow — depth belongs in Vitest.
- **Storybook (S-C8)** is the component workbench: `npm run storybook`, static
  build via `npm run storybook:build`. Stories render against the real tokens
  (the preview imports `index.css`) with axe on every story. New shared
  components get a story.

## Verifying changes

```
npm run i18n:extract                     # after moving/adding UI strings
npm run typecheck && npm run test        # behavior + guards
npm run lint && npm run format:check     # style
npm run i18n:check                       # catalog discipline
npm run build && npm run size            # bundle + budget
npx tsc -p e2e/tsconfig.json --noEmit    # e2e suite types
npx vitest run src/__tests__/design_system_foundation.test.tsx
```

Then eyeball `/styleguide` in both themes (dark first — it's the flagship).
`make web` from the repository root rebuilds and verifies the embedded
artifact — the built console under `internal/webui/dist` IS committed, so
rebuild it in the change that alters the bundle.
