// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

const EventServiceDependentRotationQueued = "pam.service_dependents.rotation_queued"
const EventServiceDependentRotationInverse = "pam.service_dependents.rotation_inverse"
const EventServiceDependentDirectoryApplyStarted = "pam.service_dependents.directory_apply_started"
const EventServiceDependentDirectoryRestored = "pam.service_dependents.directory_restored"
const EventServiceDependentStepQueued = "pam.service_dependents.step_queued"
const EventServiceDependentStepObserved = "pam.service_dependents.step_observed"

type ServiceDependentRotationQueued struct {
	Approval *store.OperationApprovalUse      `json:"approval,omitempty"`
	Intent   servicedependents.RotationIntent `json:"intent"`
	Child    SecretStaticRotationQueued       `json:"child"`
	Actor    string                           `json:"actor"`
	At       time.Time                        `json:"at"`
}
type ServiceDependentRotationInverse struct {
	RotationID   string    `json:"rotation_id"`
	IntentDigest string    `json:"intent_digest"`
	Failure      string    `json:"failure"`
	At           time.Time `json:"at"`
}
type ServiceDependentDirectoryApplyStarted ServiceDependentDirectoryRestored

type ServiceDependentDirectoryRestored struct {
	RotationID   string    `json:"rotation_id"`
	IntentDigest string    `json:"intent_digest"`
	At           time.Time `json:"at"`
}
type ServiceDependentStepQueued struct {
	Step servicedependents.RotationStep `json:"step"`
	At   time.Time                      `json:"at"`
}
type ServiceDependentStepObserved struct {
	Report            servicedependents.StepReport `json:"report"`
	JobID             int64                        `json:"job_id"`
	Attempt           int                          `json:"attempt"`
	ReceiptStatement  string                       `json:"receipt_statement"`
	ReceiptSignature  string                       `json:"receipt_signature_base64"`
	SignerFingerprint string                       `json:"signer_fingerprint"`
	At                time.Time                    `json:"at"`
}

func (p *Projector) applyServiceDependentRotationTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	if handled, err := p.applyServiceDependentManifestTx(ctx, tx, e); handled {
		return true, err
	}
	switch e.Type {
	case EventServiceReconciliationReviewProposed:
		var v ServiceReconciliationReview
		if err := decode(e, &v); err != nil {
			return true, err
		}
		if e.ID != servicedependents.ReconciliationReviewSourceID(e.TenantID, v.Intent.Plan.ID) {
			return true, errors.New("dependent reconciliation: frozen review source identity differs")
		}
		return true, ValidateServiceReconciliationReview(v)

	case EventServiceDependentRotationQueued:
		var v ServiceDependentRotationQueued
		if err := decode(e, &v); err != nil {
			return true, err
		}
		digest, err := v.Intent.Digest()
		if err != nil {
			return true, err
		}
		if e.ID != v.Intent.Plan.ID || v.Child.ID != e.ID || v.Child.DependentChangeID != e.ID || v.Child.RequestBinding != digest || v.At.IsZero() {
			return true, errors.New("dependent rotation queued source binding differs")
		}
		if err := ValidateServiceDependentRotationSource(e, v); err != nil {
			return true, err
		}
		fenceSemantic := ""
		if v.Approval != nil {
			fenceSemantic, err = p.resolveServiceReconcileFenceUseTx(ctx, tx, e, &v)
			if err != nil {
				return true, err
			}
		}
		if v.Approval != nil {
			if err := validateApprovalActor(e, v.Approval.Requester); err != nil {
				return true, err
			}
			if err := p.store.ConsumeOperationApprovalTx(ctx, tx, e.TenantID, *v.Approval, e.ID, e.Time); err != nil {
				return true, err
			}
		}
		parent := store.ServiceDependentRotation{TenantID: e.TenantID, ID: e.ID, Intent: v.Intent, IntentDigest: digest, CommandID: v.Child.ID, TenantEpoch: v.Child.TenantEpoch, Direction: servicedependents.Forward, Actor: v.Actor, CreatedAt: v.At}
		if err = p.store.ApplyServiceDependentRotationQueuedTx(ctx, tx, parent); err != nil {
			return true, err
		}
		raw, err := json.Marshal(v.Child)
		if err != nil {
			return true, err
		}
		childEvent := e
		childEvent.ID = v.Child.ID
		childEvent.Type = EventSecretStaticRotationQueued
		childEvent.Data = raw
		if err := p.applySecretStaticRotationQueuedTx(ctx, tx, childEvent, v.Child); err != nil {
			return true, err
		}
		if v.Approval != nil {
			return true, p.store.CompleteApprovedTargetFenceTx(ctx, tx, e.TenantID, store.ApprovedTargetServiceReconciliation, servicedependents.ReconcileCommandKey(e.TenantID, v.Intent.Plan.SecretName), e.ID, e.Type, schemaVersionOf(e), e.Time, []byte(fenceSemantic))
		}
		return true, nil
	case EventServiceDependentRotationInverse:
		var v ServiceDependentRotationInverse
		if err := decode(e, &v); err != nil {
			return true, err
		}
		if v.At.IsZero() {
			return true, errors.New("dependent inverse source needs time")
		}
		return true, p.store.ApplyServiceDependentRotationInverseTx(ctx, tx, e.TenantID, v.RotationID, v.IntentDigest, v.Failure, v.At)
	case EventServiceDependentDirectoryApplyStarted:
		var v ServiceDependentDirectoryApplyStarted
		if err := decode(e, &v); err != nil {
			return true, err
		}
		if e.ID != servicedependents.DirectoryApplyStartedSourceID(v.RotationID) {
			return true, errors.New("native apply intent source identity differs")
		}
		return true, p.store.ApplyServiceDependentDirectoryApplyStartedTx(ctx, tx, e.TenantID, v.RotationID, v.IntentDigest, v.At)
	case EventServiceDependentDirectoryRestored:
		var v ServiceDependentDirectoryRestored
		if err := decode(e, &v); err != nil {
			return true, err
		}
		return true, p.store.ApplyServiceDependentDirectoryRestoredTx(ctx, tx, e.TenantID, v.RotationID, v.IntentDigest, v.At)
	case EventServiceDependentStepRecoveryQueued:
		var v ServiceDependentStepRecoveryQueued
		if err := decode(e, &v); err != nil {
			return true, err
		}
		if err := ValidateServiceDependentStepRecovery(e, v); err != nil {
			return true, err
		}
		return true, p.store.ApplyServiceDependentStepRecoveryQueuedTx(ctx, tx, e.TenantID, v.Previous, v.Step, v.PreviousStatus, v.PreviousReportDigest, v.At)
	case EventServiceDependentStepQueued:
		var v ServiceDependentStepQueued
		if err := decode(e, &v); err != nil {
			return true, err
		}
		if _, _, _, err := DecodeServiceDependentStepSource(e); err != nil {
			return true, err
		}
		if e.ID != servicedependents.StepSourceID(v.Step.RotationID, v.Step.ID) {
			return true, errors.New("native step source identity differs")
		}
		return true, p.store.ApplyServiceDependentStepQueuedTx(ctx, tx, e.TenantID, v.Step, v.At)
	case EventServiceDependentStepObserved:
		var v ServiceDependentStepObserved
		if err := decode(e, &v); err != nil {
			return true, err
		}
		if e.ID != servicedependents.StepObservedSourceID(v.Report.RotationID, v.Report.StepID) {
			return true, errors.New("native step observation source identity differs")
		}
		if err := validateServiceDependentReceipt(v.JobID, v.Attempt, v.ReceiptStatement, v.ReceiptSignature, v.SignerFingerprint, v.At); err != nil {
			return true, err
		}
		return true, p.store.ApplyServiceDependentStepObservedTx(ctx, tx, e.TenantID, v.JobID, v.Attempt, v.Report, v.ReceiptStatement, v.ReceiptSignature, v.SignerFingerprint, v.At)
	}
	return false, nil
}
func (p *Projector) applySecretStaticRotationQueuedTx(ctx context.Context, tx pgx.Tx, e events.Event, pl SecretStaticRotationQueued) error {
	if pl.ID == "" || pl.TenantEpoch == "" || pl.Provider == "" || pl.Key == "" || pl.OldRef == "" {
		return errors.New("projections: static rotation requires id, tenant_epoch, provider, key and old_ref")
	}
	return p.store.ApplySecretStaticRotationQueuedTx(ctx, tx, store.SecretStaticRotationCommand{
		DependentChangeID: pl.DependentChangeID, CloudChangeID: pl.CloudChangeID, ProviderBinding: pl.ProviderBinding,
		TenantID: e.TenantID, ID: pl.ID, TenantEpoch: pl.TenantEpoch, Provider: pl.Provider, Key: pl.Key, OldRef: pl.OldRef,
		ExpectedVersion: pl.ExpectedVersion, IdempotencyKeyDigest: pl.IdempotencyKeyDigest, RequestBinding: pl.RequestBinding, ScheduleID: pl.ScheduleID, TTLSeconds: pl.TTLSeconds, CreatedAt: e.Time,
		Consumers: pl.Consumers, RetireAfterSeconds: pl.RetireAfterSeconds, RetireApprovedBy: pl.RetireApprovedBy, SinglePhaseAcknowledged: pl.SinglePhaseAcknowledged,
	}, e.Data)
}
