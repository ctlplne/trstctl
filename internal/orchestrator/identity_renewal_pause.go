// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// ErrRenewalPausedByOperator says an automatic renewal was held because an
// operator rolled this identity's target back and has not resumed it (B4-8).
var ErrRenewalPausedByOperator = errors.New("orchestrator: automatic renewal is paused on this target after an operator rollback; resume it to renew")

// PauseIdentityRenewal records that an operator's rollback of targetID holds
// automatic renewal of identityID there (B4-8). The identity's other targets
// are untouched. Idempotent in effect: pausing an already paused target
// re-records the reason and time.
func (o *Orchestrator) PauseIdentityRenewal(ctx context.Context, tenantID, identityID, targetID, reason string) error {
	identityID, targetID = strings.TrimSpace(identityID), strings.TrimSpace(targetID)
	if identityID == "" || targetID == "" {
		return errors.New("orchestrator: a renewal pause names an identity and a target")
	}
	if _, err := o.store.GetIdentity(ctx, tenantID, identityID); err != nil {
		return fmt.Errorf("orchestrator: pause renewal: %w", err)
	}
	payload, err := json.Marshal(projections.IdentityRenewalPaused{IdentityID: identityID, TargetID: targetID, Reason: strings.TrimSpace(reason)})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventIdentityRenewalPaused, tenantID, payload)
	return err
}

// ResumeIdentityRenewal lifts the pause for one target (B4-8). The event is
// the audit record of the operator's decision: the actor on its envelope is
// whoever called this. Resuming a target that is not paused is refused, so a
// stale console cannot record a decision nobody made.
func (o *Orchestrator) ResumeIdentityRenewal(ctx context.Context, tenantID, identityID, targetID string) error {
	identityID, targetID = strings.TrimSpace(identityID), strings.TrimSpace(targetID)
	if identityID == "" || targetID == "" {
		return errors.New("orchestrator: a renewal resume names an identity and a target")
	}
	ident, err := o.store.GetIdentity(ctx, tenantID, identityID)
	if err != nil {
		return fmt.Errorf("orchestrator: resume renewal: %w", err)
	}
	if _, paused := store.IdentityRenewalPauses(ident.Attributes)[targetID]; !paused {
		return fmt.Errorf("%w: automatic renewal is not paused on target %s", ErrInvalidTransition, targetID)
	}
	payload, err := json.Marshal(projections.IdentityRenewalResumed{IdentityID: identityID, TargetID: targetID})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventIdentityRenewalResumed, tenantID, payload)
	return err
}

// RenewalPausedTarget reports the target whose operator rollback holds this
// identity's automatic renewal: the identity's bound deployment target when
// a pause names it. An identity bound elsewhere, or not paused, renews.
func RenewalPausedTarget(ident store.Identity) (string, bool) {
	targetID := boundDeploymentTargetID(ident)
	if targetID == "" {
		return "", false
	}
	_, paused := store.IdentityRenewalPauses(ident.Attributes)[targetID]
	return targetID, paused
}
