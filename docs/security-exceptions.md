# Security advisory exceptions

This register records time-bounded security debt. An entry is not a claim that
the dependency is fixed, and it does not make a red scanner green. We may accept
an advisory only while all four statements below remain true:

1. Upstream has not published a compatible patched release.
2. The vulnerable code path cannot be reached in trstctl's exact use of the
   package, with the call path explained below.
3. The exception names what we are waiting for and has a review date.
4. Every audit and SCA gate remains enabled and reports the advisory normally.

The iteration's O-lane operational probe checks every open entry against the
upstream registry and advisory database. If a compatible patched release is
published, the probe runs `audit-harness/harness.sh reopen <card> "<reason>"`;
the card becomes pickable again immediately. Per-entry review dates are a
backstop, not permission to skip the per-iteration probe.

## Open exceptions

### GHSA-qwww-vcr4-c8h2 — React Router RSC action handling

- **Cards:** `SEC-5b43d4b3`, `S-7268c77e`
- **Accepted:** 2026-07-28
- **Review by:** 2026-08-04
- **Package and version:** `react-router@7.18.1` through
  `react-router-dom@7.18.1`
- **Why no compatible patch exists:** the advisory names `8.3.0` as the first
  patched release, but that version is not published in the npm registry.
  `7.18.1` is the newest published line available to this repository.
- **Why the vulnerable path is unreachable:** the advisory is limited to React
  Router's unstable React Server Components action APIs. trstctl's console
  imports `BrowserRouter`, `Routes`, `Route`, and `Navigate` in
  `web/src/App.tsx`. It has no React Router server bundle, request handler,
  unstable RSC import, server-action endpoint, SSR entry point, or hydration
  entry point. The Go control plane serves the already-built static assets.
  Therefore an HTTP request cannot enter React Router's vulnerable
  server-action-before-error-response path: that server path is neither
  imported nor started.
- **What we are waiting for:** a published patched React Router release,
  followed by the route, navigation, typecheck, test, and production-build
  compatibility run. The earlier `GHSA-wrjc-x8rr-h8h6` and
  `GHSA-337j-9hxr-rhxg` findings are not exceptions; the current `7.18.1`
  dependency has already remediated them.
- **Gate remains reporting:** the complete web build-and-runtime dependency
  tree is still scanned with dev dependencies included. `npm audit` reports
  this high advisory and exits non-zero; no advisory, package, or dependency
  scope is ignored.

### GHSA-mh99-v99m-4gvg — ESLint-chain brace expansion

- **Card:** `S-7268c77e`
- **Accepted:** 2026-07-28
- **Review by:** 2026-08-04
- **Package and version:** `brace-expansion@1.1.16`, reached through
  `minimatch@3.1.5` from `eslint@9.39.5`,
  `eslint-plugin-import@2.32.0`, `eslint-plugin-jsx-a11y@6.10.2`, and
  `eslint-plugin-react@7.37.5`
- **Why no compatible patch exists:** the fixed `brace-expansion@5.0.8` is not
  a drop-in replacement for the `minimatch@3` dependency. The newest published
  import, JSX accessibility, and React ESLint plugins still cap their peer
  support at ESLint 9. A forced transitive override was tested and made lint
  crash with `expand is not a function`; it is not a compatible patch.
- **Why the vulnerable path is unreachable:** these copies exist only in the
  development lint tree and are absent from the shipped console assets.
  trstctl invokes ESLint as `eslint . --max-warnings=0`; the starting path and
  ignore/config globs are repository-controlled, not values accepted from an
  HTTP request, API payload, tenant record, environment-driven operator
  pattern, or generated customer data. The vulnerable unbounded
  attacker-selected brace pattern therefore never reaches these copies in the
  release build. A contributor able to change the repository's executable
  ESLint config or package scripts already has build-time code execution; that
  is a trusted-code-review boundary, not a remotely reachable parser surface.
- **What we are waiting for:** ESLint-10-compatible releases of the three
  plugins and a normal lockfile upgrade that moves every `minimatch@3` chain to
  a compatible fixed brace-expansion implementation.
- **Gate remains reporting:** the web audit includes dev dependencies and
  remains non-zero for this advisory. We do not add an npm audit ignore,
  exclude the lint closure, or lower the severity threshold.
