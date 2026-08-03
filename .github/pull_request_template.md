<!--
trstctl is not accepting contributions or contributors at this time, and
outside pull requests are closed unread. This is not a judgment of the code:
the repository is dual-licensed with a proprietary ee/ tree and is the subject
of pending patent applications, so reading outside code creates ownership
questions the project cannot carry. See CONTRIBUTING.md for the reasoning and
for what IS welcome — issues, reproductions, and security reports.

This template is for the maintainer's own changes.
-->

## What this changes

<!-- One or two sentences: what behaves differently after this merges, and why.
Link the issue it closes, if there is one. -->

## How to verify

<!-- The commands you ran, and the one test that fails without this change:
`go test ./<package>/ -run <TestName> -count=1`. -->

## Checklist

- [ ] A test that fails without this change was written first
- [ ] `make lint test` is green, including the architecture linter
- [ ] Docs and a CHANGELOG entry under `[Unreleased]` are updated
- [ ] Scoped to one change; adjacent work is noted as a follow-up
