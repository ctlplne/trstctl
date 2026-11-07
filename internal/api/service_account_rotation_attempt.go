// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"context"
	"sync"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

type dependentManifestAttemptKey struct{}
type dependentManifestAuthorityKey struct {
	TenantID, RotationID, Digest, Direction, SourceID string
	Sequence                                          uint64
	HasCursor                                         bool
	Cursor                                            servicedependents.ManifestCursor
}
type dependentManifestAttempt struct {
	mu         sync.Mutex
	key        dependentManifestAuthorityKey
	valid      bool
	resolver   servicedependents.RotationManifestResolver
	pending    *events.Event
	hasStep    bool
	step       servicedependents.RotationStep
	applicable bool
}

func withDependentManifestAttempt(ctx context.Context) context.Context {
	return context.WithValue(ctx, dependentManifestAttemptKey{}, &dependentManifestAttempt{})
}
func manifestAuthorityKey(parent store.ServiceDependentRotation) dependentManifestAuthorityKey {
	key := dependentManifestAuthorityKey{TenantID: parent.TenantID, RotationID: parent.ID, Digest: parent.IntentDigest, Direction: parent.Direction, SourceID: parent.ManifestCursorSourceID, Sequence: parent.ManifestCursorSequence, HasCursor: parent.ManifestCursor != nil}
	if parent.ManifestCursor != nil {
		key.Cursor = *parent.ManifestCursor
	}
	return key
}

// Only public immutable authority is reused, for the lifetime of one worker
// call. Every new call, changed position/source/sequence or changed tenant reads
// canonical sources again. Native receipts and credential custody stay separate.
func resolveDependentManifestAttempt(ctx context.Context, parent store.ServiceDependentRotation, read func() (servicedependents.RotationManifestResolver, *events.Event, error)) (servicedependents.RotationManifestResolver, *events.Event, error) {
	attempt, _ := ctx.Value(dependentManifestAttemptKey{}).(*dependentManifestAttempt)
	if attempt == nil {
		return read()
	}
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	key := manifestAuthorityKey(parent)
	if attempt.valid && attempt.key == key {
		return attempt.resolver, attempt.pending, nil
	}
	attempt.valid = false
	attempt.hasStep = false
	attempt.step = servicedependents.RotationStep{}
	r, pending, err := read()
	if err != nil {
		return r, pending, err
	}
	// Four bounded pages is a memory budget, never a limit on account size. A
	// long run of host-only pages evicts old entries and continues normally.
	load := r.Page
	if load != nil {
		var mu sync.Mutex
		pages := map[int64]servicedependents.RotationManifestPage{}
		r.Page = func(number int64) (servicedependents.RotationManifestPage, error) {
			mu.Lock()
			defer mu.Unlock()
			if page, ok := pages[number]; ok {
				return page, nil
			}
			page, err := load(number)
			if err != nil {
				return page, err
			}
			if len(pages) >= 4 {
				clear(pages)
			}
			pages[number] = page
			return page, nil
		}
	}
	attempt.key = key
	attempt.valid = true
	attempt.resolver = r
	attempt.pending = pending
	attempt.hasStep = false
	attempt.step = servicedependents.RotationStep{}
	return r, pending, nil
}
func (a *API) dependentManifestCursor(ctx context.Context, parent store.ServiceDependentRotation) (servicedependents.RotationManifestResolver, *events.Event, error) {
	return resolveDependentManifestAttempt(ctx, parent, func() (servicedependents.RotationManifestResolver, *events.Event, error) {
		return projections.ResolveServiceDependentManifestCursor(ctx, a.log, parent)
	})
}
func cachedDependentManifestStep(ctx context.Context, parent store.ServiceDependentRotation) (servicedependents.RotationStep, bool, bool) {
	attempt, _ := ctx.Value(dependentManifestAttemptKey{}).(*dependentManifestAttempt)
	if attempt == nil {
		return servicedependents.RotationStep{}, false, false
	}
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	if !attempt.valid || attempt.key != manifestAuthorityKey(parent) || !attempt.hasStep {
		return servicedependents.RotationStep{}, false, false
	}
	return attempt.step, attempt.applicable, true
}
func retainDependentManifestStep(ctx context.Context, parent store.ServiceDependentRotation, step servicedependents.RotationStep, applicable bool) {
	attempt, _ := ctx.Value(dependentManifestAttemptKey{}).(*dependentManifestAttempt)
	if attempt == nil {
		return
	}
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	if attempt.valid && attempt.key == manifestAuthorityKey(parent) {
		attempt.step = step
		attempt.applicable = applicable
		attempt.hasStep = true
	}
}
