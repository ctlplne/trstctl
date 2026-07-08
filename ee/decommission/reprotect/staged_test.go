// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reprotect

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"trstctl.com/trstctl/ee/decommission/depstate"
)

func TestReprotect_StagedCutoverHealthRollback(t *testing.T) {
	ctx := context.Background()
	job := stagedJob()

	successPhases := &scriptedStagedPhases{
		staged:  StagedForm{ID: "stage-1", SuccessorKeyID: "key://tenant-a/successor", CompletionSuccessorID: "dataset:successor"},
		cutover: CutoverResult{Ref: "cutover:dataset:successor"},
		health:  HealthResult{Healthy: true, Detail: "probe-ok"},
	}
	successSink := &recordingCompletionSink{}
	successExec, err := NewStagedExecutor(successPhases, NewCompletionRecorder(successSink))
	if err != nil {
		t.Fatalf("NewStagedExecutor success: %v", err)
	}
	res, err := successExec.Execute(ctx, StagedRequest{Job: job, SuccessorKeyID: "key://tenant-a/successor"})
	if err != nil {
		t.Fatalf("Execute success: %v", err)
	}
	assertCalls(t, successPhases.calls, []string{"stage", "cutover", "verify", "retire"})
	if len(successPhases.rollbacks) != 0 {
		t.Fatalf("success path rolled back: %#v", successPhases.rollbacks)
	}
	if !res.Completion.Recorded || len(successSink.events) != 1 {
		t.Fatalf("success completion mismatch: result=%#v events=%#v", res.Completion, successSink.events)
	}
	if got := successSink.events[0].SuccessorKeyID; got != "dataset:successor" {
		t.Fatalf("completion successor id = %q, want dataset:successor", got)
	}

	replayed, err := successExec.Execute(ctx, StagedRequest{Job: job, SuccessorKeyID: "key://tenant-a/successor"})
	if err != nil {
		t.Fatalf("Execute replay: %v", err)
	}
	if replayed.Completion.Recorded {
		t.Fatal("idempotent replay recorded a second completion")
	}
	if len(successSink.events) != 1 {
		t.Fatalf("completion event count after replay = %d, want 1", len(successSink.events))
	}

	verifyFailure := &scriptedStagedPhases{
		staged:  StagedForm{ID: "stage-verify-fail", SuccessorKeyID: "key://tenant-a/successor"},
		cutover: CutoverResult{Ref: "cutover:verify-fail"},
		health:  HealthResult{Healthy: false, Detail: "probe failed"},
	}
	verifySink := &recordingCompletionSink{}
	verifyExec, err := NewStagedExecutor(verifyFailure, NewCompletionRecorder(verifySink))
	if err != nil {
		t.Fatalf("NewStagedExecutor verify failure: %v", err)
	}
	if _, err := verifyExec.Execute(ctx, StagedRequest{Job: job, SuccessorKeyID: "key://tenant-a/successor"}); !errors.Is(err, ErrUnhealthySuccessor) {
		t.Fatalf("verify failure error = %v, want ErrUnhealthySuccessor", err)
	}
	assertCalls(t, verifyFailure.calls, []string{"stage", "cutover", "verify", "rollback"})
	if len(verifyFailure.rollbacks) != 1 || verifyFailure.rollbacks[0].FailedPhase != ReprotectPhaseVerify {
		t.Fatalf("verify failure rollback mismatch: %#v", verifyFailure.rollbacks)
	}
	if len(verifySink.events) != 0 {
		t.Fatalf("verify failure recorded completion events: %#v", verifySink.events)
	}

	cutoverErr := errors.New("cutover failed")
	cutoverFailure := &scriptedStagedPhases{
		staged:     StagedForm{ID: "stage-cutover-fail", SuccessorKeyID: "key://tenant-a/successor"},
		cutoverErr: cutoverErr,
		health:     HealthResult{Healthy: true},
	}
	cutoverSink := &recordingCompletionSink{}
	cutoverExec, err := NewStagedExecutor(cutoverFailure, NewCompletionRecorder(cutoverSink))
	if err != nil {
		t.Fatalf("NewStagedExecutor cutover failure: %v", err)
	}
	if _, err := cutoverExec.Execute(ctx, StagedRequest{Job: job, SuccessorKeyID: "key://tenant-a/successor"}); !errors.Is(err, cutoverErr) {
		t.Fatalf("cutover failure error = %v, want %v", err, cutoverErr)
	}
	assertCalls(t, cutoverFailure.calls, []string{"stage", "cutover", "rollback"})
	if len(cutoverFailure.rollbacks) != 1 || cutoverFailure.rollbacks[0].FailedPhase != ReprotectPhaseCutover {
		t.Fatalf("cutover failure rollback mismatch: %#v", cutoverFailure.rollbacks)
	}
	if len(cutoverSink.events) != 0 {
		t.Fatalf("cutover failure recorded completion events: %#v", cutoverSink.events)
	}
}

type scriptedStagedPhases struct {
	staged     StagedForm
	cutover    CutoverResult
	health     HealthResult
	stageErr   error
	cutoverErr error
	verifyErr  error
	retireErr  error

	calls     []string
	rollbacks []RollbackRequest
}

func (p *scriptedStagedPhases) StageSuccessor(context.Context, StageRequest) (StagedForm, error) {
	p.calls = append(p.calls, "stage")
	return p.staged, p.stageErr
}

func (p *scriptedStagedPhases) Cutover(context.Context, CutoverRequest) (CutoverResult, error) {
	p.calls = append(p.calls, "cutover")
	return p.cutover, p.cutoverErr
}

func (p *scriptedStagedPhases) VerifyHealth(context.Context, HealthRequest) (HealthResult, error) {
	p.calls = append(p.calls, "verify")
	return p.health, p.verifyErr
}

func (p *scriptedStagedPhases) RetireOriginal(context.Context, RetireRequest) error {
	p.calls = append(p.calls, "retire")
	return p.retireErr
}

func (p *scriptedStagedPhases) Rollback(_ context.Context, req RollbackRequest) error {
	p.calls = append(p.calls, "rollback")
	p.rollbacks = append(p.rollbacks, req)
	return nil
}

func stagedJob() Job {
	return Job{
		ID:             "job-staged",
		TenantID:       "tenant-a",
		KeyID:          "key://tenant-a/root",
		LedgerPosition: 9,
		Kind:           JobKindReDerive,
		Dependent:      depstate.Dependent{Class: depstate.DependentDataSet, ID: "dataset:customer-archive"},
		IdempotencyKey: "idem-staged",
	}
}

func assertCalls(t *testing.T, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("phase calls mismatch:\n got %#v\nwant %#v", got, want)
	}
}
