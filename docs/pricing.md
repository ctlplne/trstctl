# Pricing And Billing Posture

trstctl's public pricing posture is intentionally unit-first: buyers should know
what is counted before a sales conversation starts.

## Billable Units

| Packaging line | Primary unit | Never primary billable |
|---|---|---|
| Community self-host | None; MPL-2.0 open core. | Issued certificates, stored certificates, ephemeral identities, discovery findings, audit events. |
| Enterprise self-host | `control_plane_deployment` plus contracted capacity band. | Issued certificates, stored certificates, ephemeral identities. |
| Provider | `managed_tenant_band`. | Issued certificates, stored certificates, ephemeral identities. |
| Managed | `managed_tenant_band` plus support, data-residency, and operating-responsibility terms. | Issued certificates, stored certificates, ephemeral identities. |

Certificate counters are operational telemetry. `certificates_issued` helps spot
issuance bursts and abuse. `certificates_stored` helps capacity planning and
renewal posture. Neither counter is the primary billing axis.

## Managed Boundary

Managed is first-party operated. Provider is MSP or self-hosted provider-plane
operation. Both use the same event-sourced, tenant-isolated control-plane
lineage; the difference is who operates it, who owns the support boundary, and
which data-residency and operating-responsibility terms apply.

## Served Proof

The running product exposes the same posture through `GET /api/v1/editions`:
`packaging.billable_unit`, `packaging.provider_billing_unit`,
`packaging.no_per_certificate_billing`,
`packaging.no_ephemeral_identity_billing`, and the usage-meter classifications.
The web Platform page renders those fields in the first viewport.
