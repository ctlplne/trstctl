// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package plan implements XREC remediation plans and the signer-side public
// evidence gate that binds a corrective operation to a recorded divergence
// witness before any signer-held key operation may run.
//
// A plan that fails signer-side verification yields a signed refusal rather than
// a silent drop (XREC-claim-13).
package plan
