// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"context"
	"encoding/json"
	"errors"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

var errDependentCanonicalEvidence = errors.New("api: native step projection differs from canonical signed sources; rebuild projections before continuing")

// canonicalDependentStep refuses a changed projection before its status, native
// process identity or completion can authorize another external effect. Delivery
// rows remain operational and may have a new ID after a rebuild; the signed
// source's historical job and attempt remain exact.
func (a *API) canonicalDependentStep(ctx context.Context, tenantID, rotationID, stepID string) (store.ServiceDependentStep, error) {
	saved, err := a.store.GetServiceDependentStep(ctx, tenantID, rotationID, stepID)
	if errors.Is(err, store.ErrServiceDependentStepNotFound) {
		for _, sourceID := range []string{servicedependents.StepSourceID(rotationID, stepID), servicedependents.StepObservedSourceID(rotationID, stepID)} {
			_, found, sourceErr := a.log.EventByID(ctx, sourceID)
			if sourceErr != nil {
				return saved, sourceErr
			}
			if found {
				return saved, errDependentCanonicalEvidence
			}
		}
	}
	if err != nil {
		return saved, err
	}
	refused := errDependentCanonicalEvidence
	queued, found, err := a.log.EventByID(ctx, servicedependents.StepSourceID(rotationID, stepID))
	if err != nil {
		return saved, err
	}
	var authority projections.ServiceDependentStepQueued
	if !found || queued.TenantID != tenantID || queued.Type != projections.EventServiceDependentStepQueued || json.Unmarshal(queued.Data, &authority) != nil || authority.Step.Validate() != nil || authority.Step.RotationID != rotationID || authority.Step.ID != stepID || !dependentCanonicalJSON(saved.Intent, authority.Step) || authority.At.IsZero() || saved.QueuedAt.UnixMicro() != authority.At.UnixMicro() {
		return saved, refused
	}
	observed, found, err := a.log.EventByID(ctx, servicedependents.StepObservedSourceID(rotationID, stepID))
	if err != nil {
		return saved, err
	}
	if saved.Status == "queued" {
		if found || saved.Report != nil || saved.ReceiptJobID != nil || saved.Attempt != nil || saved.ReceiptStatement != "" || saved.ReceiptSignature != "" || saved.SignerFingerprint != "" || saved.ReceivedAt != nil {
			return saved, refused
		}
		return saved, nil
	}
	var proof projections.ServiceDependentStepObserved
	if !found || observed.TenantID != tenantID || observed.Type != projections.EventServiceDependentStepObserved || json.Unmarshal(observed.Data, &proof) != nil || proof.Report.Validate(authority.Step) != nil || proof.JobID <= 0 || proof.Attempt <= 0 || proof.At.IsZero() || proof.ReceiptStatement == "" || proof.ReceiptSignature == "" || proof.SignerFingerprint == "" {
		return saved, refused
	}
	if saved.Report == nil || !dependentCanonicalJSON(saved.Report, proof.Report) || saved.Status != proof.Report.Status || saved.ReceiptJobID == nil || *saved.ReceiptJobID != proof.JobID || saved.Attempt == nil || *saved.Attempt != proof.Attempt || saved.ReceiptStatement != proof.ReceiptStatement || saved.ReceiptSignature != proof.ReceiptSignature || saved.SignerFingerprint != proof.SignerFingerprint || saved.ReceivedAt == nil || saved.ReceivedAt.UnixMicro() != proof.At.UnixMicro() {
		return saved, refused
	}
	return saved, nil
}

func dependentCanonicalJSON(left, right any) bool {
	a, err := json.Marshal(left)
	if err != nil {
		return false
	}
	b, err := json.Marshal(right)
	return err == nil && crypto.SHA256Hex(a) == crypto.SHA256Hex(b)
}

// The parent event is also the child's operation identity. Checking it before
// every phase prevents a changed read-model link from downgrading the command
// into the ordinary static-rotation path.
func (a *API) validateDependentCommandSource(ctx context.Context, cmd store.SecretStaticRotationCommand) error {
	if a.log == nil {
		return errors.New("api: canonical rotation source is unavailable")
	}
	source, found, err := a.log.EventByID(ctx, cmd.ID)
	if err != nil {
		return err
	}
	coordinated := found && source.Type == projections.EventServiceDependentRotationQueued
	if !coordinated && cmd.DependentChangeID == "" {
		return nil
	}
	if !coordinated || source.TenantID != cmd.TenantID || cmd.DependentChangeID != source.ID {
		return errors.New("api: dependent command parent differs from its canonical source")
	}
	_, err = a.dependentRotationParent(ctx, cmd)
	return err
}
