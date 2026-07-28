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

### GHSA-52cp-r559-cp3m — SDK generator YAML merge handling

- **Card:** `S-a72284e3`
- **Accepted:** 2026-07-28
- **Review by:** 2026-08-04
- **Package and version:** `js-yaml@4.2.0`, reached through
  `@redocly/openapi-core@1.34.16` from `openapi-typescript@7.5.0`
- **Why no compatible patch exists:** current `openapi-typescript` 7.x releases
  still select the advisory-affected Redocly 1.34 line. No compatible Redocly
  1.34 release containing the fixed `js-yaml` is published. Forcing the fixed
  transitive version was tested and broke the generator at runtime with
  `types.merge is undefined`.
- **Why the vulnerable path is unreachable:** `scripts/gen-sdk.sh` invokes the
  generator with the repository-owned `clients/sdk/openapi.json`, which is
  copied from the served OpenAPI golden. The repository has no Redocly YAML
  configuration, and the command does not accept a user-selected input path.
  JSON cannot express YAML aliases, anchors, or merge keys, so the vulnerable
  YAML merge chain cannot be constructed by this invocation. The generator
  runs only while producing checked-in SDK source; it is absent from every
  trstctl runtime artifact.
- **What we are waiting for:** an `openapi-typescript`/Redocly release pair
  that supports a patched `js-yaml` without changing or breaking the generated
  SDK output.
- **Gate remains reporting:** the TypeScript SDK generator lockfile remains a
  dedicated SCA surface. `npm audit` reports this high advisory and exits
  non-zero; no override, omit flag, or advisory suppression is present.

### GHSA-3jxr-9vmj-r5cp and GHSA-mh99-v99m-4gvg — SDK generator brace expansion

- **Card:** `S-a72284e3`
- **Accepted:** 2026-07-28
- **Review by:** 2026-08-04
- **Package and version:** `brace-expansion@2.1.1`, reached through
  `minimatch@5.1.9` from `@redocly/openapi-core@1.34.16`
- **Why no compatible patch exists:** the compatible Redocly 1.34 line still
  pins the affected minimatch/brace-expansion chain. The fixed forced
  transitive overrides break Redocly at runtime, so a numerically newer package
  tree is not a compatible generator.
- **Why the vulnerable path is unreachable:** Redocly uses this `minimatch` to
  compare a remote URL with HTTP-header patterns from Redocly configuration.
  trstctl has no Redocly config, supplies no header patterns, and passes a local
  `clients/sdk/openapi.json` file. Redocly's header list is empty, so its loop
  never calls the vulnerable matcher. This generator dependency is also
  build-only and is not linked or copied into a trstctl runtime artifact.
- **What we are waiting for:** a compatible `openapi-typescript`/Redocly
  release that moves this minimatch chain to fixed brace-expansion versions,
  followed by byte-stability and SDK behavior gates.
- **Gate remains reporting:** the SDK-generator audit keeps dev dependencies
  in scope and remains non-zero for both advisory IDs. The findings are not
  silenced or removed from the receipt.
