# Security policy

certctl is a control plane for credentials that are not human — a private CA among
them. We take security reports seriously and appreciate responsible disclosure.

## Reporting a vulnerability

**Please report security issues privately — do not open a public GitHub issue.**

- Use GitHub's **private vulnerability reporting** ("Report a vulnerability") on the
  repository's **Security** tab, or
- email the maintainer at **skreddy040@gmail.com** with the details below.

Please include, as far as you can:

- a description of the issue and its impact,
- the affected component or endpoint and version/commit,
- steps to reproduce (a proof of concept if you have one), and
- any suggested remediation.

We aim to acknowledge a report within a few business days, agree on a disclosure
timeline with you, and credit reporters who wish to be credited. Please give us a
reasonable opportunity to remediate before any public disclosure.

## Scope

In scope: the control plane and signing service (`cmd/`, `internal/`), the agent,
the deployment artifacts (`deploy/`), and the documented configuration. Especially
of interest: anything that could cross a tenant boundary (AN-1), extract or misuse
key material (AN-3/AN-4/AN-8), forge or break the audit chain, or bypass
authentication/authorization.

Out of scope: issues that require a pre-compromised host or operator credentials,
findings against the not-yet-served subsystems noted in
[docs/limitations.md](docs/limitations.md) (please still report anything you find —
we'll triage accordingly), and theoretical issues without a practical impact.

## Supported versions

certctl is pre-1.0 and under active development. Security fixes target the
**latest `main`**; there are no long-term support branches yet. Once releases are
tagged, this section will list the supported versions and their support windows.

## Our commitments

- We use the cryptography boundary (AN-3) and the out-of-process signer (AN-4) to
  contain key-material risk by design.
- We ship reproducible, cosign-signed images with an SBOM, and run `govulncheck` in
  CI so dependency vulnerabilities surface quickly.
- The product threat model is documented in
  [docs/security/threat-model.md](docs/security/threat-model.md), and the signing
  service has its own [design & threat model](docs/design/signing-service.md).
