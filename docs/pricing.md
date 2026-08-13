# Pricing and billing posture

trstctl publishes reference prices because a buyer should know both the number
and what it counts before a sales call. These are annual USD list prices for the
self-hosted software; an executed order form controls a customer's final price,
taxes, support contacts, and any negotiated term.

## Annual reference bands

| Edition / band | Annual USD list | Licensed unit | Included environment bundle |
|---|---:|---|---|
| Free | $0 | None; the MPL-2.0 core needs no signed license. | Unlimited self-operated Community deployments. |
| Enterprise Standard | $15,000 | One production `control_plane_deployment`. | 1 production + 3 non-production control planes. |
| Enterprise Plus | $30,000 | One HA or multi-region production `control_plane_deployment`. | 1 production + 3 non-production control planes. |
| Provider / MSP, 1–10 managed customers | $12,000 | `managed_customer_band`. | Full Enterprise entitlement plus Provider rights. |
| Provider / MSP, 11–50 managed customers | $30,000 | `managed_customer_band`. | Full Enterprise entitlement plus Provider rights. |
| Provider / MSP, 51–250 managed customers | $72,000 | `managed_customer_band`. | Full Enterprise entitlement plus Provider rights. |
| Provider / MSP, 250+ managed customers | Negotiated | `managed_customer_band`. | Full Enterprise entitlement plus Provider rights. |

Standard and Plus are commercial packaging bands over the same signed Enterprise
feature tier. Plus is the supported-HA commitment; it does not hide a second
feature table inside sales paperwork. Provider is wholesale: the MSP controls
its own downstream hosting, support, and resale price.

Two- and three-year prepaid terms have reference discounts of 10% and 15%.
Connectors, protocols, CA integrations, tenants, certificates, SVIDs, secrets,
API keys, tokens, rotations, nodes, discovery findings, and audit events cost
$0 as add-ons: there is no per-connector fee, no per-protocol fee, and no
per-certificate or per-ephemeral-identity meter.

## Bundled non-production entitlement

Every version 2 Enterprise or Provider license names exactly one production
deployment and permits up to 3 explicitly named non-production deployments.
The runtime must supply its stable deployment ID and declare `production` or
`non_production`; startup fails when that pair does not match a signed slot.

A matched non-production control plane receives the complete licensed feature
set and reports `production_units_consumed: 0` through
`GET /api/v1/editions`. It is bundled, not discounted, so staging and test do
not need separate purchase orders. Non-production carries no production SLA and
must not serve production traffic. trstctl can enforce the signed ID/environment
binding; it cannot observe an operator's business meaning for the traffic.

Version 1 licenses remain loadable for upgrades but are production-only and
unbound. They never gain the new non-production right by implication.

## Support

| Edition | Channel and hours | First response | Production-down target |
|---|---|---|---|
| Free | Public issue tracker | No SLA | No SLA |
| Enterprise Standard | Email/portal, business hours Eastern Time | 1 business day | 4 business hours |
| Enterprise Plus | Email/portal, priority queue | 4 business hours | 2 business hours |
| Provider / MSP | Portal plus shared escalation channel | 4 business hours | 2 business hours; best effort after hours |

Non-production deployments have no production SLA. Contractual credits, named
contacts, local holidays, and an MSP's downstream customer SLA belong in the
executed support order, not in the software license claim.

## Renewal, grace, and expiry

The standard term is annual, renewing only on notice rather than silently
auto-renewing, with a 60-day cancellation notice. Renewal uplift is capped at
5% per annual renewal for the same band and scope unless the parties sign a
different scope. Multi-year prepaid discounts are stated above.

At expiry, the offline verifier provides a 30-day grace period. During grace,
licensed modes remain enabled. After grace, the license state and commercial
feature modes become `read_only`; core issuance, renewal, revocation, protocol,
audit/export, tenancy, and license-verification capabilities remain Community
software. The MPL core keeps running: a lapsed commercial order never bricks a
customer's PKI. Individual commercial mutation surfaces must honor the served
`read_only` mode; the editions page makes that state visible before an operator
acts.

## Served proof

`GET /api/v1/editions` and Platform → Editions expose the exact effective tier,
expiry/read-only horizon, signed deployment environment, production-unit
consumption, remaining non-production slots, reference price bands, and
packaging rules. `internal/license` owns the one feature-to-tier table and the
one bundled allowance constant; the API and docs are guarded against drift from
those values.
