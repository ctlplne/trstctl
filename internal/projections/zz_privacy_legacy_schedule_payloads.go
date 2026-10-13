// SPDX-License-Identifier: BUSL-1.1

package projections

// Legacy schedule payloads stay closed even when current event schemas gain
// command receipts. Privacy export and restore must not infer absent fields.
type privacyDiscoveryScheduleControlledV1 struct {
	ID         string `json:"id"`
	Action     string `json:"action"`
	ReasonCode string `json:"reason_code"`
}
