// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import "trstctl.com/trstctl/internal/eventprotect"

func (policy SourcePolicy) verifyDestructionReceipt(receipt string) (eventprotect.DestructionClaims, error) {
	if claims, err := eventprotect.VerifyDestructionReceipt(policy.Trust, receipt); err == nil {
		return claims, nil
	}
	return eventprotect.VerifyDestructionReceipt(policy.VerificationKeys, receipt)
}
