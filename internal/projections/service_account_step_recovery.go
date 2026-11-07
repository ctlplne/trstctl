// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/servicedependents"
)

const EventServiceDependentStepRecoveryQueued = "pam.service_dependents.step_recovery_queued"
const MaxServiceDependentRecoveryDepth = servicedependents.MaxInverseRecoveryDepth

type ServiceDependentStepRecoveryQueued struct {
	Previous             servicedependents.RotationStep `json:"previous_step"`
	Step                 servicedependents.RotationStep `json:"step"`
	PreviousStatus       string                         `json:"previous_status"`
	PreviousReportDigest string                         `json:"previous_report_digest,omitempty"`
	CurrentVersion       int                            `json:"current_vault_version"`
	ReviewDigest         string                         `json:"recovery_digest"`
	Actor                string                         `json:"actor"`
	Reason               string                         `json:"reason"`
	At                   time.Time                      `json:"at"`
}

func ServiceDependentReportDigest(report *servicedependents.StepReport) string {
	if report == nil {
		return ""
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return ""
	}
	return crypto.SHA256Hex(raw)
}
func ServiceDependentRecoveryReviewDigest(previous servicedependents.RotationStep, status, reportDigest string, currentVersion int) (string, error) {
	if previous.Validate() != nil || previous.Direction != servicedependents.Inverse || previous.Challenge == "" || currentVersion < 1 {
		return "", errors.New("dependent recovery: exact inverse and current vault version required")
	}
	if status != "queued" && status != "failed" && status != "uncertain" {
		return "", errors.New("dependent recovery: successful work cannot be replaced")
	}
	decoded, err := hex.DecodeString(reportDigest)
	if status == "queued" && reportDigest != "" || status != "queued" && (err != nil || len(decoded) != 32 || reportDigest != strings.ToLower(reportDigest)) {
		return "", errors.New("dependent recovery: canonical predecessor observation required")
	}
	raw, err := json.Marshal(struct {
		Version        int                            `json:"version"`
		Previous       servicedependents.RotationStep `json:"previous_step"`
		Status         string                         `json:"previous_status"`
		ReportDigest   string                         `json:"previous_report_digest,omitempty"`
		CurrentVersion int                            `json:"current_vault_version"`
		Material       string                         `json:"material"`
	}{1, previous, status, reportDigest, currentVersion, "retained_predecessor"})
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(append([]byte("trstctl.service-dependent.inverse-recovery-review.v1\x00"), raw...)), nil
}
func ValidateServiceDependentStepRecovery(e events.Event, v ServiceDependentStepRecoveryQueued) error {
	digest, err := ServiceDependentRecoveryReviewDigest(v.Previous, v.PreviousStatus, v.PreviousReportDigest, v.CurrentVersion)
	if err != nil {
		return err
	}
	next, err := servicedependents.NewInverseRecoveryStep(v.Previous, v.Step.Challenge, v.At)
	if err != nil {
		return err
	}
	a, _ := json.Marshal(next)
	b, _ := json.Marshal(v.Step)
	if crypto.SHA256Hex(a) != crypto.SHA256Hex(b) || digest != v.ReviewDigest || v.Actor == "" || len(v.Actor) > 512 || len(v.Reason) > 4096 || !e.Time.Equal(v.At) || v.At.IsZero() || e.Type != EventServiceDependentStepRecoveryQueued || schemaVersionOf(e) != 1 || e.ID != servicedependents.RecoverySourceID(v.Previous.RotationID, v.Previous.ID) {
		return errors.New("dependent recovery: exact first replacement source differs")
	}
	if err := validateApprovalActor(e, v.Actor); err != nil {
		return err
	}
	if v.PreviousStatus == "queued" && !v.At.After(v.Previous.Deadline.Add(time.Minute)) {
		return errors.New("dependent recovery: predecessor execution lease is still active")
	}
	return nil
}

// DecodeServiceDependentStepSource keeps ordinary schema1 closed. Recovery has
// its own source type and must bind an unchanged inverse effect to a predecessor.
func DecodeServiceDependentStepSource(e events.Event) (servicedependents.RotationStep, time.Time, *ServiceDependentStepRecoveryQueued, error) {
	if schemaVersionOf(e) != 1 {
		return servicedependents.RotationStep{}, time.Time{}, nil, errors.New("dependent step: unsupported source version")
	}
	var step servicedependents.RotationStep
	var at time.Time
	switch e.Type {
	case EventServiceDependentStepQueued:
		var v ServiceDependentStepQueued
		if json.Unmarshal(e.Data, &v) != nil || v.Step.Recovery != nil {
			return step, at, nil, errors.New("dependent step: ordinary source cannot carry recovery authority")
		}
		step, at = v.Step, v.At
	case EventServiceDependentStepRecoveryQueued:
		var v ServiceDependentStepRecoveryQueued
		if json.Unmarshal(e.Data, &v) != nil {
			return step, at, nil, errors.New("dependent recovery: invalid source")
		}
		if err := ValidateServiceDependentStepRecovery(e, v); err != nil {
			return step, at, nil, err
		}
		return v.Step, v.At, &v, nil
	default:
		return step, at, nil, errors.New("dependent step: unknown source type")
	}
	if step.Validate() != nil || step.Challenge == "" || at.IsZero() || e.ID != servicedependents.StepSourceID(step.RotationID, step.ID) {
		return step, at, nil, errors.New("dependent step: canonical source identity differs")
	}
	return step, at, nil, nil
}

// ResolveServiceDependentStepHead follows only immutable deterministic sources.
// A missing or rewritten SQL lineage cannot revive a superseded host grant.
func ResolveServiceDependentStepHead(ctx context.Context, log *events.Log, tenantID, rotationID, rootStepID string) (servicedependents.RotationStep, error) {
	event, found, err := log.EventByID(ctx, servicedependents.StepSourceID(rotationID, rootStepID))
	if err != nil {
		return servicedependents.RotationStep{}, err
	}
	if !found || event.TenantID != tenantID {
		return servicedependents.RotationStep{}, errors.New("dependent recovery: root step source unavailable")
	}
	head, _, recovery, err := DecodeServiceDependentStepSource(event)
	if err != nil || recovery != nil || head.ID != rootStepID || head.RotationID != rotationID {
		return servicedependents.RotationStep{}, errors.New("dependent recovery: original step authority differs")
	}
	for depth := 0; depth < MaxServiceDependentRecoveryDepth; depth++ {
		next, found, err := log.EventByID(ctx, servicedependents.RecoverySourceID(rotationID, head.ID))
		if err != nil {
			return head, err
		}
		if !found {
			return head, nil
		}
		replacement, _, authority, err := DecodeServiceDependentStepSource(next)
		if err != nil || next.TenantID != tenantID || authority == nil || replacement.Recovery.RootStepID != rootStepID || replacement.Recovery.PreviousStepID != head.ID {
			return head, errors.New("dependent recovery: retained replacement lineage differs")
		}
		a, _ := json.Marshal(head)
		b, _ := json.Marshal(authority.Previous)
		if crypto.SHA256Hex(a) != crypto.SHA256Hex(b) {
			return head, errors.New("dependent recovery: predecessor native authority changed")
		}
		observation, observed, err := log.EventByID(ctx, servicedependents.StepObservedSourceID(rotationID, head.ID))
		if err != nil {
			return head, err
		}
		if err := validateRecoveryPredecessorObservation(event, next, *authority, observation, observed); err != nil {
			return head, err
		}
		event = next
		head = replacement
	}
	return head, errors.New("dependent recovery: retained replacement history reached its bounded capacity")
}

// A replacement freezes the predecessor as it existed before this command.
// Later audit receipts cannot retroactively grant a different replacement.
func validateRecoveryPredecessorObservation(previousSource, recoverySource events.Event, recovery ServiceDependentStepRecoveryQueued, observed events.Event, found bool) error {
	refused := errors.New("dependent recovery: predecessor observation differs from retained first command")
	if previousSource.Sequence == 0 || recoverySource.Sequence <= previousSource.Sequence {
		return refused
	}
	before := found && observed.Sequence < recoverySource.Sequence
	if recovery.PreviousStatus == "queued" {
		if before {
			return refused
		}
		return nil
	}
	var value ServiceDependentStepObserved
	if !before || observed.Sequence <= previousSource.Sequence || observed.TenantID != recoverySource.TenantID || observed.Type != EventServiceDependentStepObserved || schemaVersionOf(observed) != 1 || json.Unmarshal(observed.Data, &value) != nil || value.Report.Validate(recovery.Previous) != nil || value.Report.Status != recovery.PreviousStatus || ServiceDependentReportDigest(&value.Report) != recovery.PreviousReportDigest || value.JobID <= 0 || value.Attempt <= 0 || value.At.IsZero() || value.ReceiptStatement == "" || value.ReceiptSignature == "" || value.SignerFingerprint == "" {
		return refused
	}
	return nil
}
