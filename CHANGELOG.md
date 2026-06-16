# Changelog

All notable changes to trstctl are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches
1.0. trstctl is **pre-1.0 and under active hardening**: minor versions may carry
breaking changes, and the tagged versions below are development milestones, not
supported release lines (see [SECURITY.md](SECURITY.md) for the support policy and
[docs/limitations.md](docs/limitations.md) for what the running binary serves today).

This file is the human-readable companion to the git tags; the
[README roadmap](README.md#roadmap) describes what is planned.

## [Unreleased]

### Security & hardening
- Remediation pass (R0–R9) hardening the served, multi-tenant profile: served
  end-to-end **revocation** (a revoked credential stops validating in the product's
  inventory/records), an idempotent first-API-token bootstrap, served X.509 issuance
  with CDP/AIA/SKI and certificate-profile enforcement, quorum-gated cross-signing,
  versioned event envelopes with version-aware projections, bounded/tenant-scoped
  lifecycle history, and TTL'd idempotency keys.
- Supply chain: GitHub Actions and base/runtime images pinned by digest, the
  embedded-PostgreSQL binary pinned against a committed provenance manifest, a
  CycloneDX SBOM and `govulncheck` gate in CI, CODEOWNERS over the root-of-trust
  paths with required code-owner review, and checksum-verified CI tool installs.
- Docs/observability honesty: a reality-tested `docs/limitations.md` that states
  served-vs-library status for every advertised capability, so the binary cannot
  silently over-claim.

### Added
- `CHANGELOG.md` (this file), linked from the README and SECURITY.md (DOCS-005).

## [0.5.0] - 2026-06-13
- Hardening milestone toward an enterprise-GA bar for the self-hosted, multi-tenant
  profile: isolated signer custody (sealed CA key persisted across restarts), the
  assembled control-plane server (`cmd/trstctl` → `internal/server`) serving the
  event spine, projections, orchestrator, and REST API, and the architecture linter
  (`tools/trstctllint`) enforcing AN-1/AN-3/AN-5/AN-8 in CI.

## [0.4] - 2026-05-31
- Pre-release development milestone.

## [0.3] - 2026-05-31
- Pre-release development milestone.

## [0.2] - 2026-05-31
- Pre-release development milestone.

## [0.1] - 2026-05-31
- Initial tagged development milestone.

[Unreleased]: https://github.com/imfeelingtheagi/trstctl/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/imfeelingtheagi/trstctl/releases/tag/v0.5.0
[0.4]: https://github.com/imfeelingtheagi/trstctl/releases/tag/v0.4
[0.3]: https://github.com/imfeelingtheagi/trstctl/releases/tag/v0.3
[0.2]: https://github.com/imfeelingtheagi/trstctl/releases/tag/v0.2
[0.1]: https://github.com/imfeelingtheagi/trstctl/releases/tag/v0.1
