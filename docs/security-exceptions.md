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

There are no open security-advisory exceptions. Audit and SCA gates remain
enabled and may reopen this section when a new finding cannot be patched safely.

## Closed exceptions

### GHSA-mh99-v99m-4gvg — ESLint-chain brace expansion

- **Card:** `S-7268c77e`
- **Accepted:** 2026-07-28
- **Closed:** 2026-08-20
- **Resolved versions:** every `minimatch@3.1.5` path now resolves
  `brace-expansion@1.1.18`; the independent modern path resolves
  `brace-expansion@5.0.9`.
- **Why it is closed:** the [GitHub-reviewed advisory](https://github.com/advisories/GHSA-mh99-v99m-4gvg)
  marks `1.1.17` and `5.0.8` as the patched floors. The exact lockfile tree is
  above both floors without a forced override or peer-incompatible ESLint
  upgrade.
- **Verification:** `npm ls` proves the versions on every ESLint, import,
  accessibility, React, and TypeScript lint path; the complete audit reports
  zero vulnerabilities; and the unchanged strict lint command remains green.

### GHSA-qwww-vcr4-c8h2 — React Router RSC action handling

- **Cards:** `SEC-5b43d4b3`, `S-7268c77e`
- **Accepted:** 2026-07-28
- **Closed:** 2026-08-20
- **Resolved version:** `react-router@7.18.2` through
  `react-router-dom@7.18.2`
- **Why it is closed:** the [upstream GitHub advisory](https://github.com/remix-run/react-router/security/advisories/GHSA-qwww-vcr4-c8h2)
  now names `7.18.2` as the patched 7.x release. The console's direct package floor and lockfile both
  resolve `react-router-dom` and its `react-router` dependency to `7.18.2`, so
  the compatible React 18 line no longer carries this advisory.
- **Verification:** every route test, the full console suite, TypeScript, lint,
  the production build, the embedded-console identity test, and the supported
  live-browser matrix must remain green. `npm audit` and the SCA gates remain
  enabled; closure does not add an ignore or suppress a future router finding.
