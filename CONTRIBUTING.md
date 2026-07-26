# Contributing to trstctl

Thanks for considering a contribution. trstctl is open core: the platform under
`LICENSE` is MPL-2.0 and free, while the `ee/` tree is proprietary,
license-gated material. That split decides how contributions are handled, so it
is the first thing this page explains.

## Two trees, two rules

**Core (everything outside `ee/`) — MPL-2.0, sign off with the DCO.**
Contributions to core are accepted under the
[Developer Certificate of Origin 1.1](https://developercertificate.org/): a
lightweight statement that you wrote the patch, or have the right to submit it
under the project's license. You certify it by adding a `Signed-off-by` line to
each commit, which `git` writes for you:

```bash
git commit -s -m "fix(store): ..."
```

The line must carry your real name and an email you can be reached at:

```
Signed-off-by: Jane Doe <jane@example.com>
```

No copyright assignment is requested and none is implied. Your contribution
stays yours, licensed to everyone under MPL-2.0 like the rest of core.

**Enterprise (`ee/`) — proprietary, requires a signed CLA.**
Because `ee/` ships under a commercial license, a contribution there must come
with a signed Contributor License Agreement granting the rights needed to
distribute it under that license. Open an issue before writing `ee/` code and a
maintainer will send the CLA. If you would rather not sign one — an entirely
reasonable position — say so in the issue: most `ee/` requests can be met by a
change in core plus a seam, which stays DCO-only.

This split is deliberate. A blanket CLA over the whole project would tax every
drive-by fix in core; DCO-only everywhere would make the commercial tree
undistributable. Core stays cheap to contribute to; only the proprietary tree
carries paperwork.

## Before you write code

Read [`AGENTS.md`](AGENTS.md). It is the standing engineering contract:
architecture invariants AN-1 through AN-9 (multi-tenancy under PostgreSQL RLS,
event-sourced state, the single `internal/crypto` boundary, the isolated signer
process, idempotent mutations, the outbox for external effects, bounded worker
pools, locked and zeroed key material, and the core-vs-`ee/` fence). Several of
those are enforced by a custom `go/analysis` linter and a pull request cannot
merge while one is violated. `web/AGENTS.md` and the leaf `AGENTS.md` files
under high-risk packages carry the local rules.

If you believe a linter finding is a false positive, fix the rule in its own
change with a test fixture rather than adding a blanket ignore.

## The loop

1. Open an issue describing the problem before a large change, so design
   feedback lands before the code does.
2. Write the failing test first. Property tests for parsers and the policy
   engine, differential tests against reference implementations where one
   exists, and integration tests against real PostgreSQL and real embedded NATS
   for anything touching the spine — not mocks.
3. Make the smallest change that passes without weakening an invariant.
4. Run `make lint test`. Both must be green, including the architecture linter.
   (`make lint-partial` is for fast local feedback when the optional lint tools
   are missing; it is not the gate.)
5. Update the docs the change touches, add a CHANGELOG entry under
   `[Unreleased]`, and update a package's `AGENTS.md` if it grew a convention.
6. Open one focused pull request. Do not bundle unrelated changes; note adjacent
   work as a follow-up instead.

## Security

Do not open a public issue for a vulnerability. Follow
[SECURITY.md](SECURITY.md) for private disclosure. Changes to the signing
service, `internal/crypto`, the store's RLS policies, or the linter itself
require review from the owners listed in
[`.github/CODEOWNERS`](.github/CODEOWNERS).

## Getting started

The authoring guides for
[connectors](docs/guides/connector-authoring.md) and
[plugins](docs/guides/plugin-authoring.md) are the gentlest entry points:
both extend the platform without touching the invariants.
