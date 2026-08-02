// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package reconcile assembles the proprietary XREC runtime behind the tagged
// attach seam. It keeps XREC product wiring in ee/ while core sees only generic
// server seams.
//
// The assembled runtime is the system embodiment of the XREC filing
// (XREC-claims-1, 16): read-only observation of two or more credential
// authorities, deterministic canonicalization, signed state digests, minimal
// divergence witnesses, quarantine, and signer-gated remediation, wired here as
// one whole so that no step of the claimed method exists only as a library.
package reconcile
