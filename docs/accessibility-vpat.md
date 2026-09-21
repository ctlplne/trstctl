# Accessibility VPAT Evidence Packet

Owner: PRODUCT
Last reviewed: 2026-07-02
Retest cadence: every release candidate, and after any shell, navigation, dialog,
grid, theme, or form-control change.

This packet is the repository evidence source for a Voluntary Product
Accessibility Template (VPAT) response for the trstctl web console. It is not a
legal attestation or a third-party audit certificate. When a buyer requests a
formal VPAT, product and legal map this evidence into the requested VPAT version
and attach the CI receipt named `a11y-evidence-receipt`.

## Scope

The scope is the served React web console under `web/`, embedded into the control
plane binary from `internal/webui/dist`. The packet covers:

- authenticated shell navigation, skip link, banner, main landmark, and route
  focus management;
- data grids, drawers, dialogs, loading states, empty states, and primary
  workflows exercised by Vitest and Testing Library;
- theme, reduced-motion, keyboard-only, and RTL behavior;
- source-level i18n extraction debt and typed runtime message keys.

Out of scope for this packet: native terminal CLI accessibility, external
browser extensions, downstream connector consoles, customer-created content, and
third-party identity-provider screens outside trstctl.

## WCAG 2.1 AA Control Mapping

| Area | Current evidence | Status |
| --- | --- | --- |
| 1.1.1 Non-text Content | Icon buttons and non-text controls have accessible names in the shared shell and grid tests. | Supported |
| 1.3.1 Info and Relationships | Landmark structure, headings, labels, captions, and table semantics are covered by `web/src/__tests__/shell_a11y_and_theme.test.tsx` and `web/src/__tests__/design_system_foundation.test.tsx`. | Supported |
| 1.4.3 Contrast | Shared token contrast and axe gates are part of the web test suite. | Supported by automated gate |
| 2.1.1 Keyboard | Primary navigation, command palette, route changes, dialogs, and grid controls are keyboard reachable in component tests. | Supported |
| 2.2.2 Pause, Stop, Hide | Reduced-motion CSS disables animation and transition duration for users who request reduced motion. | Supported |
| 2.4.1 Bypass Blocks | The shell provides a skip link to the routed main region. | Supported |
| 2.4.3 Focus Order | Route focus moves to the new page heading or main region after SPA navigation. | Supported |
| 2.4.7 Focus Visible | Global focus-visible styling is defined in `web/src/index.css`. | Supported |
| 3.3.2 Labels or Instructions | Forms in the tested served paths use explicit labels, field names, and status messages. | Supported |
| 4.1.2 Name, Role, Value | Axe checks run over shell, dashboards, cards, dialogs, and selected pages. | Supported by automated gate |

## Manual Assistive-Technology Audit Receipts

### A11Y-MANUAL-KEYBOARD-2026-07-02

Method: keyboard-only review of the authenticated shell contract documented in
`docs/web-console.md`, backed by the user-event tab, Enter, Escape, and route
focus checks in `web/src/__tests__/reduced_motion_and_a11y.test.tsx`,
`web/src/__tests__/shell_a11y_and_theme.test.tsx`, and
`web/src/__tests__/route_focus.test.tsx`.

Receipt: the default shell route exposes a named primary navigation landmark,
named links, a skip target, visible focus, dismissible overlays, and a live route
announcement. The current receipt has no blocking keyboard-only defect.

### A11Y-MANUAL-SCREEN-READER-2026-07-02

Method: screen reader audit checklist for the served console shell, using the DOM
accessibility tree as the committed source of truth. The checklist verifies that
the primary navigation is named, page changes announce the new heading, loading
states expose `role="status"`, data tables carry captions or labeled headings,
and icon-only controls have programmatic labels. Automated axe checks are not used
as the sole proof; they are the repeatable regression gate for this manual
assistive-technology receipt.

Receipt anchors:

- `web/src/components/AppShell.tsx` owns the skip link, primary navigation label,
  route focus, and live route announcement.
- `web/src/components/DataGrid.tsx` owns labeled grid controls, column chooser
  labels, and table semantics.
- `web/src/__tests__/reduced_motion_and_a11y.test.tsx` proves the primary
  navigation has accessible names and the default shell route has no axe
  violations.
- `web/src/__tests__/shell_a11y_and_theme.test.tsx` proves keyboard reachability
  and axe coverage on the authenticated shell.

Current result: no blocking screen-reader defect is recorded for the shell
contract. A buyer-specific VPAT response must still identify the exact browser,
operating system, and assistive-technology versions used for that procurement
cycle.

## Automated Evidence

The default web CI job runs:

```sh
npm run lint
npm run format:check
npm run typecheck
npm run test:coverage
npm run build
```

The `test:coverage` run includes axe accessibility checks and keyboard traversal
tests. CI then runs `scripts/accessibility/write-a11y-evidence-receipt.mjs` and
uploads `${RUNNER_TEMP}/accessibility-evidence-receipt.json` as
`a11y-evidence-receipt`.

## Known Exceptions

- This repository packet is the engineering evidence source. It is not a signed
  third-party VPAT form.
- The manual screen reader audit receipt above records the shell and shared
  component contract. Before a procurement-specific VPAT is sent, product must
  rerun the checklist with the buyer-requested browser, operating system, and
  assistive-technology versions.
- Customer-provided certificate names, owner names, and connector labels can
  affect table wrapping. The grid keeps semantics and keyboard controls, but
  content quality remains the customer's responsibility.

## Release Checklist

Before release or a procurement response:

1. Run the web gate from the repo root: `cd web && npm run lint && npm run typecheck && npm test && npm run build`.
2. Generate the current receipt: `node scripts/accessibility/write-a11y-evidence-receipt.mjs --out /tmp/accessibility-evidence-receipt.json`.
3. Attach the generated `accessibility-evidence-receipt.json` to the release or
   CI run.
4. If the buyer requires a formal VPAT form, map this packet into the requested
   VPAT version and record the exact assistive-technology versions used.
