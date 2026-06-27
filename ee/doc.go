// SPDX-License-Identifier: LicenseRef-trstctl-Commercial-TBD

// Package ee is the commercial-code fence for trstctl Enterprise and Provider
// capabilities. Core may not import this tree except through the tagged
// cmd/trstctl/ee_attach.go seam; ee packages may import core seams. Enterprise
// remediation code lives under ee/incident, ee/fleet, and ee/pqcmigration; the
// cross-cluster DR/federation worker lives under ee/federation; BYOK/HSM managed
// keys and KMIP live under ee/managedkeys and ee/kmip; compliance evidence packs
// and governance policy live under ee/governance; the Provider/MSP console lives
// under ee/provider; provider metering and quota export live under ee/billing.
// White-label branding lives under ee/whitelabel; siloed isolation lives under
// ee/silo. The served API mounts human-triggered remediation routes, background
// HA federation, BYOK/KMIP, governance, provider-plane routes, metering,
// white-label branding, and silo routing only through the licensed attach seam.
package ee
