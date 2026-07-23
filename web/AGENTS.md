# AGENTS.md — web/ (the console)

Leaf contract for the React console, per the root `AGENTS.md` hub-and-spoke
rule. Read the root file first; design rules live in `web/DESIGN.md`; this
file is the engineering contract the S-C1…S-C9 trains established. When a rule
here and a guard test disagree, the guard is the truth — fix the rule in the
same change.

## The shell and IA (S-C1/S-C2/S-C7)

The console is a unified shell: an icon rail of five spaces over a
space-scoped sidebar, with Home (Dashboard, Journeys, needs-action worklists)
as the only global plane. The single source of IA truth is the space registry
in `src/lib/navigation.ts` (`navSpaces`); `navGroups` and the module helpers
derive from it.

- Every customer route lives in exactly one space group (`module_map` guard:
  global XOR one space). The URL decides the active space; switching spaces
  navigates.
- A route's nav label, its page H1, and its `document.title` are the SAME
  message key (`naming_parity` guard).
- Workspaces vs lenses: a view with its own served evidence, workflows, and
  name is a sidebar route; an alternate view over one object domain is a
  URL-addressable `?tab=` lens. The rulings live beside the registry —
  changing one is an IA change (registry comment, guards, docs, one PR).
- Rail-row budget: the `UX-03`/`U8-6` ceilings are spent consciously, never
  raised silently. Current ceiling: 38.

## Data, forms, and pages

- **Queries (S-C5a):** new surfaces use the TanStack Query layer
  (`src/lib/query.tsx` — `AppQueryProvider` mounts in `AppRoutes`;
  `useApiQuery` mirrors the old `useResource` shape). Existing pages migrate
  off `lib/useResource` when next touched; do not add new `useResource`
  callers. Mutations write through `setQueryData` for instant UI and then
  `invalidateQueries` for server truth (see `pages/Owners.tsx`).
- **Forms (S-C5b):** mutation forms are schema-first — zod owns the field
  contract, react-hook-form wires inputs and per-field errors, and the submit
  handler only sees valid, trimmed values (see `pages/RequestCredential.tsx`).
  API failures stay separate from validation errors.
- **Pages are lazy chunks (S-C3):** routes load through `lazyPage` in
  `App.tsx`; the Suspense boundary lives at the shell outlet. Tests must
  `await findBy…` after mounting a route — never read the DOM synchronously.
  The compressed bundle budget is `npm run size`; spend it consciously.

## Typography and tokens (S-C9)

`Eyebrow` and `Num` (`src/components/typography.tsx`) are the only sanctioned
micro-label and inline-data styles — do not hand-roll uppercase/tracking
clusters or ad-hoc mono numerals. `text-2xs` is the smallest type rung; no
`text-[Npx]` arbitraries. Note: `cn()` (`src/lib/utils.ts`) extends
tailwind-merge with the token font sizes — without that, `text-caption` and a
color utility silently conflict. If you add a token scale, register it there.

## i18n workflow

User-facing strings are typed message keys in `src/i18n/messages.ts` with
`es-ES` and `de-DE` entries; the extraction budget is sealed at zero. The
production-catalog sha256 digests in `i18n.test.tsx` are a REVIEW RATCHET:
adding or changing translations legitimately breaks them — re-pin in the same
change with a comment saying what was reviewed. Machine-authored translations
must be flagged for human review before release. Storybook stories are
excluded from extraction; keep fixture copy out of the catalog.

## Test surfaces

- **Vitest** owns behavior (140+ files). Guards that pin the IA
  (`module_map`, `nav_completeness`, `naming_parity`, `UX-03`, `U8-6`,
  `ia_ratchets`, budgets, i18n digests) are updated IN the change that moves
  the IA, with the rationale in the diff — never loosened to "make it pass".
- **Playwright (S-C4)** owns real-browser smoke and pixels: `npm run
  e2e:install` once, then `npm run e2e` against the seeded demo stack (or
  `TRSTCTL_E2E_URL`). Visual baselines are committed; a diff is a design
  decision. Type-check the suite with `npx tsc -p e2e/tsconfig.json --noEmit`.
  Keep specs shallow — depth belongs in Vitest.
- **Storybook (S-C8)** is the component workbench: `npm run storybook`, static
  build via `npm run storybook:build`. Stories render against the real tokens
  (preview imports `index.css`) with axe on every story. New shared components
  get a story.

## Verifying changes

```
npm run typecheck && npm run test        # behavior + guards
npm run lint && npm run format:check     # style
npm run i18n:check                       # catalog discipline
npm run build && npm run size            # bundle + budget
npx tsc -p e2e/tsconfig.json --noEmit    # e2e suite types
```

`make web` from the repo root rebuilds and verifies the embedded artifact —
the built console under `internal/webui/dist` IS committed; rebuild it in the
change that alters the bundle.
