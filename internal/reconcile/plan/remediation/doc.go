// SPDX-License-Identifier: BUSL-1.1

// Package remediation records signer-approved XREC remediation authorizations
// and stages the corresponding corrective job on the core transactional outbox.
//
// It is deliberately a child package of internal/reconcile/plan: the parent package is
// signer-linked and stays free of SQL/outbox imports, while this package is
// control-plane-only and is mounted through the tagged FeatureReconcile attach
// seam.
//
// The authorization row and its corrective job are written in one transaction and
// keyed by the witness digest, so a repeated authorization is a no-op
// (XREC-claim-14); the corrective write itself runs only through a
// capability-granted remediation connector (XREC-claim-18).
package remediation
