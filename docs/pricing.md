# Pricing and billing posture

trstctl's public pricing posture is intentionally unit-first: buyers should know
what is counted before a sales conversation starts.

## Billable Units

| Tier | Primary unit | Never billed by trstctl |
|---|---|---|
| Free | None; the self-hosted MPL core requires no signed license. | Certificates, SVIDs, secrets, API keys, tokens, rotations, nodes, discovery findings, and audit events. |
| Enterprise | `control_plane_deployment`. The signed Enterprise license unlocks the commercial `ee/` feature set for that deployment. | Certificates, SVIDs, secrets, API keys, tokens, and rotations. |
| Provider / MSP | `managed_customer_band`, negotiated in the Provider contract. The license includes all Enterprise features plus managed-service and resale rights for the commercial feature set. | Certificates, SVIDs, secrets, API keys, tokens, rotations, nodes, and control-plane deployments. |

Credential counters are operational telemetry. `certificates_issued` helps spot
issuance bursts and abuse. `certificates_stored` helps capacity planning and
renewal posture. Neither counter is the primary billing axis.

## Provider / MSP flexibility

The managed-customer band is the wholesale pricing anchor, not a rigid public
tariff. Standard starting bands are 1–10, 11–50, and 51–250 managed customers;
larger or unusual operating models use a negotiated band. Contract term, support
load, data residency, deployment isolation, and the MSP's hosting posture can
change the final wholesale price.

An MSP normally runs one shared control plane with one isolated tenant per
customer. It may instead use dedicated customer deployments when its security or
operating posture requires them. That choice does not turn certificates,
identities, nodes, or deployments into automatic wholesale billing units.

The MSP sets its own downstream prices. It may charge its customers for hosting,
support, dedicated infrastructure, managed operations, or any other service it
provides; trstctl does not prescribe that resale model.

## Served Proof

The running product exposes the same posture through `GET /api/v1/editions`:
`packaging.billable_unit`, `packaging.provider_billing_unit`,
`packaging.no_per_certificate_billing`,
`packaging.no_ephemeral_identity_billing`, and the usage-meter classifications.
The signed license tier also exposes effective feature grants, managed-customer
band, and use rights. The web Platform page renders the packaging fields.
