// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reprotect

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/ee/decommission/depstate"
)

type CredentialIssuer interface {
	IssueReplacementCredential(context.Context, CredentialIssueRequest) (CredentialReplacement, error)
}

type CredentialSupersessionRecorder interface {
	RecordCredentialSupersession(context.Context, CredentialSupersession) error
}

// CredentialReissueExecutor practices VDEC-claim-6: a credential dependent is
// reissued under the successor key, a supersession link is recorded, the original
// is marked superseded, and the completion event binds the credential and
// replacement identifiers.
type CredentialReissueExecutor struct {
	issuer       CredentialIssuer
	supersession CredentialSupersessionRecorder
	recorder     *CompletionRecorder
}

type CredentialIssueRequest struct {
	Job            Job
	SuccessorKeyID string
}

type CredentialReplacement struct {
	OldCredentialID string
	NewCredentialID string
	SuccessorKeyID  string
}

type CredentialSupersession struct {
	TenantID        string
	JobID           string
	IdempotencyKey  string
	OldCredentialID string
	NewCredentialID string
	SuccessorKeyID  string
}

type CredentialReissueRequest struct {
	Job            Job
	SuccessorKeyID string
}

type CredentialReissueResult struct {
	Replacement  CredentialReplacement
	Supersession CredentialSupersession
	Completion   CompletionResult
}

func NewCredentialReissueExecutor(issuer CredentialIssuer, supersession CredentialSupersessionRecorder, recorder *CompletionRecorder) (*CredentialReissueExecutor, error) {
	if issuer == nil {
		return nil, errors.New("reprotect: credential issuer is required")
	}
	if supersession == nil {
		return nil, errors.New("reprotect: credential supersession recorder is required")
	}
	if recorder == nil {
		return nil, ErrNilCompletionSink
	}
	return &CredentialReissueExecutor{issuer: issuer, supersession: supersession, recorder: recorder}, nil
}

func (e *CredentialReissueExecutor) Execute(ctx context.Context, req CredentialReissueRequest) (CredentialReissueResult, error) {
	if e == nil || e.issuer == nil || e.supersession == nil || e.recorder == nil {
		return CredentialReissueResult{}, errors.New("reprotect: credential reissue executor is not configured")
	}
	if err := validateCredentialReissueRequest(req); err != nil {
		return CredentialReissueResult{}, err
	}
	replacement, err := e.issuer.IssueReplacementCredential(ctx, CredentialIssueRequest(req))
	if err != nil {
		return CredentialReissueResult{}, err
	}
	replacement = normalizeCredentialReplacement(req, replacement)
	if err := validateCredentialReplacement(req, replacement); err != nil {
		return CredentialReissueResult{}, err
	}
	link := CredentialSupersession{
		TenantID:        req.Job.TenantID,
		JobID:           req.Job.ID,
		IdempotencyKey:  req.Job.IdempotencyKey,
		OldCredentialID: replacement.OldCredentialID,
		NewCredentialID: replacement.NewCredentialID,
		SuccessorKeyID:  replacement.SuccessorKeyID,
	}
	if err := e.supersession.RecordCredentialSupersession(ctx, link); err != nil {
		return CredentialReissueResult{}, err
	}

	completion, err := e.recorder.RecordCompletionEvidence(ctx, req.Job, CompletionEvidence{
		SuccessorKeyID: replacement.SuccessorKeyID,
		CredentialSupersession: &depstate.CredentialSupersessionV1{
			OldCredentialID: replacement.OldCredentialID,
			NewCredentialID: replacement.NewCredentialID,
		},
	})
	if err != nil {
		return CredentialReissueResult{}, err
	}
	return CredentialReissueResult{Replacement: replacement, Supersession: link, Completion: completion}, nil
}

func validateCredentialReissueRequest(req CredentialReissueRequest) error {
	if err := validateJob(req.Job); err != nil {
		return err
	}
	if req.Job.Kind != JobKindReIssue || req.Job.Dependent.Class != depstate.DependentCredential {
		return fmt.Errorf("%w: credential executor cannot handle job kind %s", ErrInvalidState, req.Job.Kind)
	}
	if strings.TrimSpace(req.SuccessorKeyID) == "" {
		return fmt.Errorf("%w: successor_key_id is required", ErrInvalidState)
	}
	return nil
}

func normalizeCredentialReplacement(req CredentialReissueRequest, replacement CredentialReplacement) CredentialReplacement {
	if strings.TrimSpace(replacement.OldCredentialID) == "" {
		replacement.OldCredentialID = req.Job.Dependent.ID
	}
	if strings.TrimSpace(replacement.SuccessorKeyID) == "" {
		replacement.SuccessorKeyID = req.SuccessorKeyID
	}
	return replacement
}

func validateCredentialReplacement(req CredentialReissueRequest, replacement CredentialReplacement) error {
	if strings.TrimSpace(replacement.NewCredentialID) == "" {
		return fmt.Errorf("%w: replacement credential id is required", ErrInvalidState)
	}
	if replacement.OldCredentialID != req.Job.Dependent.ID {
		return fmt.Errorf("%w: replacement old credential %s does not match dependent %s", ErrInvalidState, replacement.OldCredentialID, req.Job.Dependent.ID)
	}
	if replacement.NewCredentialID == replacement.OldCredentialID {
		return fmt.Errorf("%w: replacement credential must differ from original", ErrInvalidState)
	}
	if replacement.SuccessorKeyID != req.SuccessorKeyID {
		return fmt.Errorf("%w: replacement successor key %s does not match request %s", ErrInvalidState, replacement.SuccessorKeyID, req.SuccessorKeyID)
	}
	return nil
}
