// SPDX-License-Identifier: BUSL-1.1
package eventprivacy

import (
	"context"

	"trstctl.com/trstctl/internal/eventprotect"
)

// receiptMatchesCurrentLifetime is called inside the existing custody fence.
// Receipt-only readers retain the finite-cut rule. A neighboring restored branch
// can reuse an old numeric offboard position, so crossing it additionally requires
// current independent lookup of the EXACT creation identity, completed signed
// removal and material absence. This is a current erasure floor, not proof that
// the restored source contains the original offboard or any authority to append,
// provision, sign or remove. No lifetime is chosen from a sequence number alone.
func (policy SourcePolicy) receiptMatchesCurrentLifetime(
	ctx context.Context, life Lifetime, claims eventprotect.DestructionClaims,
	head uint64, custody any, receipt string,
) (bool, error) {
	if receiptMatchesAvailableLifetime(life, claims, head) {
		return true, nil
	}
	if life.Offboard != nil || life.Activation == nil || claims.Request.OffboardSequence > head || !receiptMatchesAbsentLifetime(life, claims) {
		return false, nil
	}
	current, ok := custody.(registrationCustody)
	if !ok {
		return false, nil
	}
	creation := life.Activation.Body.Creation
	state, found, err := current.LookupKeyState(ctx, creation.Ref)
	if err != nil {
		return false, err
	}
	return found && state.Phase == eventprotect.CustodyKeyDestroyed &&
		state.Receipt == receipt && state.Creation.Ref == creation.Ref &&
		creation.Digest() != "" && state.Creation.Digest() == creation.Digest(), nil
}
