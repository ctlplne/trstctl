// SPDX-License-Identifier: LicenseRef-trstctl-Commercial-TBD

// Package ee is the commercial-code fence for trstctl Enterprise and Provider
// capabilities. Core may not import this tree except through the tagged
// cmd/trstctl/ee_attach.go seam; ee packages may import core seams. Enterprise
// remediation code lives under ee/incident, ee/fleet, and ee/pqcmigration; the
// served API mounts those human-triggered execution routes only through the
// licensed attach seam.
package ee
