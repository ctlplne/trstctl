// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reprotect

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

type ReprotectPhase string

const (
	ReprotectPhaseStage   ReprotectPhase = "stage"
	ReprotectPhaseCutover ReprotectPhase = "cutover"
	ReprotectPhaseVerify  ReprotectPhase = "verify"
	ReprotectPhaseRetire  ReprotectPhase = "retire"
)

var ErrUnhealthySuccessor = errors.New("vdec reprotect: successor health verification failed")

// StagedPhases performs the external effects for a staged re-protection job.
// Implementations own the backing transaction/outbox details; this executor owns
// the order and the rule that completion is recorded only after health succeeds.
type StagedPhases interface {
	StageSuccessor(context.Context, StageRequest) (StagedForm, error)
	Cutover(context.Context, CutoverRequest) (CutoverResult, error)
	VerifyHealth(context.Context, HealthRequest) (HealthResult, error)
	RetireOriginal(context.Context, RetireRequest) error
	Rollback(context.Context, RollbackRequest) error
}

type StagedExecutor struct {
	phases   StagedPhases
	recorder *CompletionRecorder
}

type StagedRequest struct {
	Job            Job
	SuccessorKeyID string
}

type StageRequest struct {
	Job            Job
	SuccessorKeyID string
}

type StagedForm struct {
	ID                    string
	SuccessorKeyID        string
	CompletionSuccessorID string
}

type CutoverRequest struct {
	Job            Job
	SuccessorKeyID string
	Staged         StagedForm
}

type CutoverResult struct {
	Ref string
}

type HealthRequest struct {
	Job            Job
	SuccessorKeyID string
	Staged         StagedForm
	Cutover        CutoverResult
}

type HealthResult struct {
	Healthy bool
	Detail  string
}

type RetireRequest struct {
	Job            Job
	SuccessorKeyID string
	Staged         StagedForm
	Cutover        CutoverResult
	Health         HealthResult
}

type RollbackRequest struct {
	Job            Job
	SuccessorKeyID string
	Staged         StagedForm
	Cutover        CutoverResult
	FailedPhase    ReprotectPhase
}

type StagedResult struct {
	Staged     StagedForm
	Cutover    CutoverResult
	Health     HealthResult
	Completion CompletionResult
}

func NewStagedExecutor(phases StagedPhases, recorder *CompletionRecorder) (*StagedExecutor, error) {
	if phases == nil {
		return nil, errors.New("reprotect: staged phases are required")
	}
	if recorder == nil {
		return nil, ErrNilCompletionSink
	}
	return &StagedExecutor{phases: phases, recorder: recorder}, nil
}

func (e *StagedExecutor) Execute(ctx context.Context, req StagedRequest) (StagedResult, error) {
	if e == nil || e.phases == nil || e.recorder == nil {
		return StagedResult{}, errors.New("reprotect: staged executor is not configured")
	}
	if err := validateStagedRequest(req); err != nil {
		return StagedResult{}, err
	}
	staged, err := e.phases.StageSuccessor(ctx, StageRequest(req))
	if err != nil {
		return StagedResult{}, err
	}
	cutover, err := e.phases.Cutover(ctx, CutoverRequest{
		Job:            req.Job,
		SuccessorKeyID: req.SuccessorKeyID,
		Staged:         staged,
	})
	if err != nil {
		return StagedResult{Staged: staged}, e.rollback(ctx, req, staged, CutoverResult{}, ReprotectPhaseCutover, err)
	}
	health, err := e.phases.VerifyHealth(ctx, HealthRequest{
		Job:            req.Job,
		SuccessorKeyID: req.SuccessorKeyID,
		Staged:         staged,
		Cutover:        cutover,
	})
	if err != nil {
		return StagedResult{Staged: staged, Cutover: cutover}, e.rollback(ctx, req, staged, cutover, ReprotectPhaseVerify, err)
	}
	if !health.Healthy {
		err = fmt.Errorf("%w: %s", ErrUnhealthySuccessor, strings.TrimSpace(health.Detail))
		return StagedResult{Staged: staged, Cutover: cutover, Health: health}, e.rollback(ctx, req, staged, cutover, ReprotectPhaseVerify, err)
	}
	if err := e.phases.RetireOriginal(ctx, RetireRequest{
		Job:            req.Job,
		SuccessorKeyID: req.SuccessorKeyID,
		Staged:         staged,
		Cutover:        cutover,
		Health:         health,
	}); err != nil {
		return StagedResult{Staged: staged, Cutover: cutover, Health: health}, err
	}
	completion, err := e.recorder.RecordCompletion(ctx, req.Job, completionSuccessorID(req.SuccessorKeyID, staged))
	if err != nil {
		return StagedResult{Staged: staged, Cutover: cutover, Health: health}, err
	}
	return StagedResult{Staged: staged, Cutover: cutover, Health: health, Completion: completion}, nil
}

func (e *StagedExecutor) rollback(ctx context.Context, req StagedRequest, staged StagedForm, cutover CutoverResult, failed ReprotectPhase, cause error) error {
	err := e.phases.Rollback(ctx, RollbackRequest{
		Job:            req.Job,
		SuccessorKeyID: req.SuccessorKeyID,
		Staged:         staged,
		Cutover:        cutover,
		FailedPhase:    failed,
	})
	if err != nil {
		return errors.Join(cause, fmt.Errorf("reprotect: rollback after %s failure: %w", failed, err))
	}
	return cause
}

func validateStagedRequest(req StagedRequest) error {
	if err := validateJob(req.Job); err != nil {
		return err
	}
	if strings.TrimSpace(req.SuccessorKeyID) == "" {
		return fmt.Errorf("%w: successor_key_id is required", ErrInvalidState)
	}
	return nil
}

func completionSuccessorID(successorKeyID string, staged StagedForm) string {
	if strings.TrimSpace(staged.CompletionSuccessorID) != "" {
		return staged.CompletionSuccessorID
	}
	if strings.TrimSpace(staged.SuccessorKeyID) != "" {
		return staged.SuccessorKeyID
	}
	return successorKeyID
}
