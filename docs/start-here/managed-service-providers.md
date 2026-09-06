# Start here: managed service providers

You operate machine identity for several customers and need one control plane that
keeps them apart, proves what was done for whom, and lets your operators work across
customers without a customer ever seeing another's records. This page names what
exists today, what is edition-gated, and how to evaluate it honestly.

## What exists today

- **Tenant isolation is the datastore's job, not the operator's discipline.** Every
  table is row-level-secured by tenant; a token is minted for one tenant and carries
  its scopes. A customer-B token asking for a customer-A identity, owner, target or
  transition gets `404`/`403` with no A data in the body — the cold design-partner run
  of 2026-09-06 exercised exactly that.
- **Provider operations** (`/api/v1/managed-offering/tenants`, provider usage
  evidence, per-customer entitlement) are part of the Enterprise Provider plan; see
  [Plan and license](../editions.md) for what the Free and Enterprise editions include
  and how a license is applied.
- **Per-customer operating loop**: the same journeys apply inside each customer
  tenant — [Keep your existing CA](../journeys/preserve-existing-ca.md),
  [Onboard a team as a tenant](../journeys/onboard-a-team.md),
  [Respond to a compromise](../journeys/respond-to-compromise.md).

## Evaluating as a provider

1. Mint one API token per customer tenant through the documented path
   (`trstctl token create --tenant <customer uuid>` inside the Compose custody
   boundary) and keep them in mode-0600 files; the CLI reads `TRSTCTL_TOKEN` from the
   environment, never from the command line.
2. Run the web-server or fleet journey inside customer A.
3. With customer B's token, read A's objects by id and try a write: expect refusal
   without leakage. Record both.
4. Route each customer's alerts to that customer's channel with an owner-level routing
   policy, and review the exact route before saving.

## What is not there yet

A provider-wide console workspace that switches customers without re-authentication,
delegation with expiry, and cross-customer reporting are Enterprise Provider features;
their served state is listed in [Current limitations](../limitations.md). Do not
present a tenant switcher as a managed-service workflow until that page says it is
served.
