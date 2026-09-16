# Contributing to trstctl

**trstctl is not accepting contributions or contributors at this time.**

That is a deliberate position, not an oversight, and this page exists to say so
plainly rather than leave someone to discover it after writing a patch.

## Why

trstctl is dual-licensed source-available software. The core outside `ee/` is
MPL-2.0; the `ee/` tree is proprietary and commercially licensed (see
[LICENSE](LICENSE) and [ee/LICENSE](ee/LICENSE)). Parts of the mechanism are also
the subject of pending patent applications.

Accepting outside code into a codebase in that position creates ownership
questions that are cheap to avoid now and expensive to unpick later: who holds
the copyright in a given line, whether it can be relicensed into the commercial
tree, and whether a contribution encumbers a claim. Refusing contributions
outright is the cleanest answer available while that remains true.

It is also honest about capacity. The project has a single author. A review
queue nobody can service is worse for a would-be contributor than a clear no.

## What to do instead

- **Found a bug, or something the documentation gets wrong?** Open an issue.
  Issues are welcome and are the most useful thing anyone outside the project can
  send. A good reproduction is worth more than a patch here.
- **Found a security problem?** Do not open an issue. Follow
  [SECURITY.md](SECURITY.md).
- **Want a capability that does not exist?** Open an issue describing the
  problem rather than the solution. What an operator actually needs is more
  useful than an implementation of what they think would provide it.
- **Want to use the core in your own work?** You already may, under MPL-2.0,
  without asking. The `ee/` tree is separate and needs a commercial agreement.

## Unsolicited pull requests

Pull requests will be closed unread, with a pointer to this page. That is not a
judgment of the code; it is that reading it creates exactly the ownership
ambiguity described above.

If this position changes, this page changes with it, and it will say so here
first. Until then, treat the absence of a Contributor License Agreement as
meaning contributions are not being taken — not as an invitation to send one.

## If you are reading this as a maintainer

The engineering contract below still governs every change, including the
author's own.

## Before you write code

Read [How it's built](README.md#how-its-built). It is the standing engineering contract:
architecture invariants AN-1 through AN-9 (multi-tenancy under PostgreSQL RLS,
event-sourced state, the single `internal/crypto` boundary, the isolated signer
process, idempotent mutations, the outbox for external effects, bounded worker
pools, locked and zeroed key material, and the core-vs-`ee/` fence). Several of
those are enforced by a custom `go/analysis` linter and a pull request cannot
merge while one is violated. [`web/DESIGN.md`](web/DESIGN.md) carries the
console's local rules, and each package's `doc.go` header carries its own.

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
   `[Unreleased]`, and update the package's `doc.go` header if it grew a convention.
6. Open one focused pull request. Do not bundle unrelated changes; note adjacent
   work as a follow-up instead.

`make lint` stops when file enumeration, formatting, analyzer allocation or
analyzer compilation fails. The EE gate requires a complete golangci-lint JSON
report with the configured linters enabled before comparing its issue count to
`.ee-lint-baseline`; a scanner error cannot count as a clean scan. It retains
scanner diagnostics, rejects malformed reports and uses the existing 25-minute
scanner limit. It limits captured output to 64 MiB and cleans its scanner process
group on timeout, cancellation or abnormal exit. This gate requires Python 3
on a POSIX host. A lower count is reported for a
reviewed baseline change; lint never rewrites the baseline itself.

`make test` runs the server suite in two isolated processes so database startup
and lifecycle checks can make progress together. It lists the compiled tests,
examples and fuzz seed targets, then requires exactly one start and completion
for every selected target. Both processes retain race detection and full
first-party coverage under one shared 15-minute execution deadline. The separate
row-501 fairness proof keeps its 10-minute deadline; performance and coverage
floors are unchanged.

This runner also requires Python 3 on a POSIX host. It copies only compressed
public PostgreSQL archives into separate temporary directories; the product
authenticates and extracts them again. Database and signer state are independent.
Compilation/listing is timed separately from execution. Logs, the census, skips
and completion counts remain in `cover.out.server.shards/`. Timeout, cancellation,
missing tests or failed processes reject the merged profile and clean up only
the runner's own processes. Its self-tests run at the start of `make test`.

## Security

Do not open a public issue for a vulnerability. Follow
[SECURITY.md](SECURITY.md) for private disclosure. Changes to the signing
service, `internal/crypto`, the store's RLS policies, or the linter itself
require review from the owners listed in
[`.github/CODEOWNERS`](.github/CODEOWNERS).

## Code of conduct

This project adopts the [Contributor Covenant](CODE_OF_CONDUCT.md) 2.1 as-is. It
applies to issues, pull requests, and every other project space, and the
enforcement address is the maintainer address published in
[SECURITY.md](SECURITY.md).

## Bug reports and feature requests

Issues arrive on a form:
[`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/) carries a bug report and a
feature request, and blank issues are disabled. A vulnerability is not an issue —
follow [SECURITY.md](SECURITY.md).

## Getting started

The authoring guides for
[connectors](docs/guides/connector-authoring.md) and
[plugins](docs/guides/plugin-authoring.md) are the gentlest entry points:
both extend the platform without touching the invariants.
