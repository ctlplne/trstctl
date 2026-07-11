// SPDX-License-Identifier: MPL-2.0

package server

// EnableRemediationEdition is the edition-neutral attach operation for the
// served remediation routes. The licensed cmd/trstctl attach seam calls this
// only after the offline license grants remediation; runtime wiring proofs call
// the same operation before Build so they exercise the exact production route
// set without importing ee/ into core.
func EnableRemediationEdition(deps *Deps) {
	if deps != nil {
		deps.EnableRemediation = true
	}
}
