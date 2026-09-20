// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package ee is the commercial-code fence for trstctl Enterprise and Provider
// capabilities. Core may not import this tree except through the tagged attach
// seams (cmd/trstctl/ee_attach.go and cmd/trstctl-signer/ee_attach.go); ee
// packages may import core. Enterprise remediation code lives under
// ee/incident; the cross-cluster DR/federation worker lives under
// ee/federation; BYOK/HSM managed keys live under ee/managedkeys; compliance
// evidence packs and governance policy live under ee/governance; the
// Provider/MSP console lives under ee/provider; provider metering and quota
// export live under ee/billing. White-label branding lives under
// ee/whitelabel; siloed isolation lives under ee/silo. The served API mounts
// human-triggered remediation routes, background HA federation, BYOK,
// governance, provider-plane routes, metering, white-label branding, and silo
// routing only through the licensed attach seam.
//
// The patent-pending families — PCAS (internal/succession, internal/rpverify,
// internal/translog), AGID (internal/agentid), XREC (internal/reconcile),
// VDEC (internal/decommission) — and PQC (internal/pqc, internal/pqcruntime,
// internal/pqcmigration, internal/kmip) moved out of this tree on 2026-09-20:
// they ship in the core under the Business Source License 1.1 and attach in
// every build through cmd/*/attach_families.go.
package ee
