# trstctl design system

The console shares one design language with trstctl.com: ink-black blue
surfaces, warm cream ink, **gold** primary (`#ffd166`), **mint** accent
(`#5eead4`), and the Sora / DM Mono / Syne type trio. Dark is the flagship
theme (a direct port of the website palette); light is the same language on
warm paper. The living spec renders at **`/styleguide`** — every swatch and
component there comes from the real implementation.

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
2. **Gold means "act", mint means "focus".** The primary button is gold with
   near-black ink in both themes (≈13:1). Focus rings and selection use the
   accent. Never introduce a second call-to-action color.
3. **Destructive is a variant, not a className.** Revoke/delete/offboard
   actions use `variant="destructive"` (confirmations) or
   `variant="destructive-outline"` (row-level openers). Async buttons take
   `loading`, which renders the spinner and sets `aria-busy`.
4. **Credential material renders as a `CredentialChip`.** Fingerprints,
   serials, node IDs, tokens: DM Mono, middle-truncated, copyable. Never nest
   it inside another interactive element.
5. **Digits align, data is mono.** All tables inherit `tabular-nums`;
   standalone numerals opt in with the utility class, and inline data values
   in sans copy (counts, TTLs, serials, timestamps) render through `Num`.
   Micro-labels use the single `Eyebrow` cluster — do not hand-roll new
   uppercase/tracking combinations (PageHeader's accent eyebrow is the one
   sanctioned brand-flavored variant).
6. **The page's object list renders first; workspaces are routes, lenses are
   tabs (S-C7).** A view that is a distinct served workspace — its own feature
   evidence, workflows, and name — is a sidebar route in its space (Secrets'
   six workspaces). An alternate view over the same object domain stays a
   `PageTabs` lens with state synced to `?tab=` so it deep-links
   (Certificates' four lenses, Discovery's four pipeline stages). The full
   rule and rulings live beside the space registry in `src/lib/navigation.ts`.
7. **Loading keeps the page's shape.** Tables and cards use `Skeleton` blocks,
   not spinner lines. The five list states come from `StatePrimitives` /
   `EmptyState` only.
8. **Motion is subtle and safe.** 160ms/220ms tokens, entrance animations on
   drawers/dialogs/overlays only, everything behind `motion-safe`.
9. **Charts pull from the tone palette.** Use `ChartTone` names, never
   hand-picked hues; several tokens alias in dark mode, so check `/styleguide`
   when composing multi-series charts.
10. **New user-facing strings are typed message keys.** Add to
    `src/i18n/messages.ts` with `es-ES` and `de-DE` entries or the extraction
    ratchet in `extractedMessages.budget.json` will fail — never raise the
    budget.
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

## Verifying changes

```
npm run i18n:extract   # after moving/adding UI strings
npx tsc --noEmit
npx vitest run src/__tests__/design_system_foundation.test.tsx
```

Then eyeball `/styleguide` in both themes (dark first — it's the flagship).
