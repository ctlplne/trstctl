<!--
Core (everything outside ee/) is MPL-2.0 and takes contributions under the
Developer Certificate of Origin: sign every commit with `git commit -s`.
The proprietary ee/ tree additionally requires a signed CLA — open an issue
first. See CONTRIBUTING.md.
-->

## What this changes

<!-- One or two sentences: what behaves differently after this merges, and why.
Link the issue it closes, if there is one. -->

## How to verify

<!-- The commands you ran, and the one test that fails without this change:
`go test ./<package>/ -run <TestName> -count=1`. -->

## Checklist

- [ ] Commits are signed off (`git commit -s`) — DCO for core
- [ ] `ee/` changes (if any) are covered by a signed CLA
- [ ] A test that fails without this change was written first
- [ ] `make lint test` is green, including the architecture linter
- [ ] Docs and a CHANGELOG entry under `[Unreleased]` are updated
- [ ] Scoped to one change; adjacent work is noted as a follow-up
