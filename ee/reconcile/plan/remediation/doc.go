// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package remediation records signer-approved XREC remediation authorizations
// and stages the corresponding corrective job on the core transactional outbox.
//
// It is deliberately a child package of ee/reconcile/plan: the parent package is
// signer-linked and stays free of SQL/outbox imports, while this package is
// control-plane-only and is mounted through the tagged FeatureReconcile attach
// seam.
package remediation
