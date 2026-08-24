# Report a security vulnerability

This page is for researchers, customers, and operators who may have found a trstctl
security problem. Send the report privately. Do not put exploit details, credentials,
tenant data, or unpatched reproduction steps in a public issue.

## Private reporting path

If your repository account has access, use **Security → Report a vulnerability**
in the trstctl repository. Otherwise email **skreddy040@gmail.com**.

Include the smallest useful evidence:

- what happened and the likely impact;
- affected component, endpoint, version, commit SHA, and image digest;
- safe reproduction steps using synthetic data;
- whether a tenant boundary, key, audit chain, authentication, or authorization is
  involved; and
- any repair you already tested.

Do not attach private keys, bearer tokens, session cookies, customer data, or an
unredacted support bundle. Agree on a protected transfer method first if the report
needs sensitive evidence.

We aim to acknowledge reports within a few business days, agree on a coordinated
disclosure timeline, and credit reporters who want credit. Give the project a
reasonable opportunity to repair and publish an advisory before public disclosure.

## Scope

In scope: the control plane, isolated signing service, agent, deployment artifacts,
and documented configuration. Tenant-boundary escape, private-key extraction or
misuse, audit forgery, and authentication/authorization bypass receive priority.

The host and operator credentials are assumed trusted. Findings that require an
already-compromised host or administrator are normally outside the primary threat
boundary, but report them when the practical impact is material. The running build's
[Current limitations](../limitations.md) remains the authority for what is served.

trstctl is pre-1.0. Security fixes target the latest `main`; no long-term-support
branches are promised yet. [Vulnerability management](vulnerability-management.md)
defines triage, patch targets, advisories, and retest evidence.
