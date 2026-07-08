// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reprotect

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"trstctl.com/trstctl/ee/decommission/depstate"
)

var ErrNilCompletionSink = errors.New("vdec reprotect: nil completion sink")

// CompletionEventSink appends completion evidence to the caller-owned event
// substrate. The recorder supplies idempotency; the sink supplies durability.
type CompletionEventSink interface {
	AppendReprotectionCompleted(context.Context, depstate.ReprotectionCompletedV1) error
}

// CompletionResult reports whether this delivery appended a new completion event.
type CompletionResult struct {
	Recorded bool
	Event    depstate.ReprotectionCompletedV1
}

// CompletionRecorder records at most one completion event for a job idempotency
// key and dependent identity pair.
type CompletionRecorder struct {
	mu   sync.Mutex
	sink CompletionEventSink
	seen map[string]struct{}
}

func NewCompletionRecorder(sink CompletionEventSink) *CompletionRecorder {
	return &CompletionRecorder{sink: sink, seen: make(map[string]struct{})}
}

func (r *CompletionRecorder) RecordCompletion(ctx context.Context, job Job, successorKeyID string) (CompletionResult, error) {
	if r == nil || r.sink == nil {
		return CompletionResult{}, ErrNilCompletionSink
	}
	if err := validateJob(job); err != nil {
		return CompletionResult{}, err
	}
	if strings.TrimSpace(successorKeyID) == "" {
		return CompletionResult{}, fmt.Errorf("%w: successor_key_id is required", ErrInvalidState)
	}
	event := depstate.ReprotectionCompletedV1{
		TenantID:       job.TenantID,
		KeyID:          job.KeyID,
		JobID:          job.ID,
		Dependent:      job.Dependent,
		SuccessorKeyID: successorKeyID,
	}
	key := completionKey(job)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.seen[key]; ok {
		return CompletionResult{Recorded: false, Event: event}, nil
	}
	if err := r.sink.AppendReprotectionCompleted(ctx, event); err != nil {
		return CompletionResult{}, err
	}
	r.seen[key] = struct{}{}
	return CompletionResult{Recorded: true, Event: event}, nil
}

func completionKey(job Job) string {
	return job.TenantID + "\x00" + job.KeyID + "\x00" + job.IdempotencyKey + "\x00" + dependentKey(job.Dependent)
}
