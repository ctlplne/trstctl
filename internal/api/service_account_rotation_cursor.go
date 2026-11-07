// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

func (a *API) validateDependentIntentCurrent(ctx context.Context, tenantID string, intent servicedependents.RotationIntent) error {
	if intent.Plan.Manifest == nil {
		inputs, err := a.dependentRotationInputs(ctx, tenantID, intent.Plan.Account.AccountID)
		if err != nil {
			return err
		}
		return intent.Validate(inputs)
	}
	state, err := a.canonicalManifestHeader(ctx, tenantID, intent.Plan.ID)
	if err != nil {
		return err
	}
	if state.Seal == nil {
		return manifestConflict()
	}
	exact, err := servicedependents.NewRotationIntentFromManifest(state.Header, *state.Seal)
	if err != nil {
		return err
	}
	digest, err := exact.Digest()
	if err != nil {
		return err
	}
	given, err := intent.Digest()
	if err != nil || given != digest {
		return manifestConflict()
	}
	if _, err := a.validateCanonicalManifest(ctx, tenantID, state, true); err != nil {
		return err
	}
	return a.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return a.store.ValidateServiceDependentRotationSourcesTx(ctx, tx, tenantID, intent, true)
	})
}
func (a *API) manifestStepAt(ctx context.Context, parent store.ServiceDependentRotation) (servicedependents.RotationManifestResolver, servicedependents.RotationStep, bool, error) {
	r, pending, err := a.dependentManifestCursor(ctx, parent)
	if err != nil {
		return r, servicedependents.RotationStep{}, false, err
	}
	if pending != nil {
		return r, servicedependents.RotationStep{}, false, store.ErrServiceDependentCursorAdvanceRequired
	}
	if step, applicable, ok := cachedDependentManifestStep(ctx, parent); ok {
		return r, step, applicable, nil
	}
	entry, err := r.Entry(*parent.ManifestCursor)
	if err != nil {
		return r, servicedependents.RotationStep{}, false, err
	}
	// Use the exact public inventory just validated against its immutable scan
	// source. A second SQL decode here adds no authority and scales with scan size.
	input, err := a.currentManifestHostInput(ctx, parent.TenantID, r.Header, entry.Host)
	if err != nil {
		return r, servicedependents.RotationStep{}, false, err
	}
	step, applicable, err := r.Step(parent.Intent, *parent.ManifestCursor, input)
	if err == nil {
		retainDependentManifestStep(ctx, parent, step, applicable)
	}
	return r, step, applicable, err
}
func (a *API) nextDependentManifestStep(ctx context.Context, parent store.ServiceDependentRotation, preflight bool) (*servicedependents.RotationStep, error) {
	_, pending, err := a.dependentManifestCursor(ctx, parent)
	if err != nil {
		return nil, err
	}
	if pending != nil {
		return nil, store.ErrServiceDependentCursorAdvanceRequired
	}
	if parent.ManifestCursor.Position.Stage == servicedependents.ManifestComplete || preflight && parent.ManifestCursor.Position.Stage != servicedependents.Preflight {
		return nil, nil
	}
	_, step, applicable, err := a.manifestStepAt(ctx, parent)
	if err != nil {
		return nil, err
	}
	if !applicable {
		return nil, store.ErrServiceDependentCursorAdvanceRequired
	}
	source, found, err := a.log.EventByID(ctx, servicedependents.StepSourceID(parent.ID, step.ID))
	if err != nil {
		return nil, err
	}
	if !found {
		if _, err := a.canonicalDependentStep(ctx, parent.TenantID, parent.ID, step.ID); !errors.Is(err, store.ErrServiceDependentStepNotFound) {
			if err == nil {
				return nil, errDependentCanonicalEvidence
			}
			return nil, err
		}
		return &step, nil
	}
	if source.TenantID != parent.TenantID {
		return nil, errDependentCanonicalEvidence
	}
	head, err := projections.ResolveServiceDependentStepHead(ctx, a.log, parent.TenantID, parent.ID, step.ID)
	if err != nil {
		return nil, err
	}
	saved, err := a.canonicalDependentStep(ctx, parent.TenantID, parent.ID, head.ID)
	if err != nil {
		return nil, err
	}
	if saved.Intent.ManifestPosition == nil || *saved.Intent.ManifestPosition != *step.ManifestPosition {
		return nil, errDependentCanonicalEvidence
	}
	switch saved.Status {
	case "succeeded":
		return &saved.Intent, store.ErrServiceDependentCursorAdvanceRequired
	case "failed", "uncertain":
		return &saved.Intent, store.ErrServiceDependentStepFailed
	}
	return &saved.Intent, nil
}
func (a *API) advanceDependentManifestCursor(ctx context.Context, parent store.ServiceDependentRotation) error {
	r, pending, err := a.dependentManifestCursor(ctx, parent)
	if err != nil {
		return err
	}
	if pending != nil {
		if err := projections.New(a.store).Apply(ctx, *pending); err != nil {
			return err
		}
		return errDependentManifestProgress
	}
	_, step, applicable, err := a.manifestStepAt(ctx, parent)
	if err != nil {
		return err
	}
	to, err := r.Advance(*parent.ManifestCursor)
	if err != nil {
		return err
	}
	v := projections.ServiceDependentCursorAdvanced{RotationID: parent.ID, IntentDigest: parent.IntentDigest, PreviousSourceID: parent.ManifestCursorSourceID, From: *parent.ManifestCursor, To: to, Cause: servicedependents.ManifestNotApplicable, At: time.Now().UTC()}
	if applicable {
		head, err := projections.ResolveServiceDependentStepHead(ctx, a.log, parent.TenantID, parent.ID, step.ID)
		if err != nil {
			return err
		}
		saved, err := a.canonicalDependentStep(ctx, parent.TenantID, parent.ID, head.ID)
		if err != nil {
			return err
		}
		if saved.Status != "succeeded" || saved.Report == nil || saved.Intent.ManifestPosition == nil || *saved.Intent.ManifestPosition != parent.ManifestCursor.Position {
			return errDependentCanonicalEvidence
		}
		v.Cause = servicedependents.ManifestNativeSucceeded
		v.StepID = saved.Intent.ID
		v.ReportDigest = projections.ServiceDependentReportDigest(saved.Report)
	}
	event := servicedependents.ManifestCursorAdvanceSourceID(parent.TenantID, parent.ID, parent.ManifestCursorSourceID)
	if err := a.appendDependentRuntimeSource(ctx, parent.TenantID, event, projections.EventServiceDependentCursorAdvanced, 1, v.At, v); err != nil {
		return err
	}

	return errDependentManifestProgress
}
func (a *API) setManifestPreviousPIDs(ctx context.Context, parent store.ServiceDependentRotation, next *servicedependents.RotationStep) error {
	if next.Action != servicedependents.Start && next.Action != servicedependents.Probe {
		return nil
	}
	if next.Task != nil || !next.Active() {
		return nil
	}
	if next.Service != nil {
		seen := map[uint32]bool{}
		for _, action := range []string{servicedependents.Preflight, servicedependents.Probe} {
			id := servicedependents.RotationStepID(parent.ID, parent.IntentDigest, servicedependents.Forward, action, next.Ref)
			saved, err := a.canonicalDependentStep(ctx, parent.TenantID, parent.ID, id)
			if errors.Is(err, store.ErrServiceDependentStepNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if saved.Status == "succeeded" && saved.Report != nil && saved.Report.Runtime != nil && saved.Report.Runtime.ProcessID != 0 && !seen[saved.Report.Runtime.ProcessID] {
				pid := saved.Report.Runtime.ProcessID
				next.PreviousPIDs = append(next.PreviousPIDs, pid)
				seen[pid] = true
			}
		}
	}
	id := servicedependents.RotationStepID(parent.ID, parent.IntentDigest, parent.Direction, servicedependents.Stop, next.Ref)
	head, err := projections.ResolveServiceDependentStepHead(ctx, a.log, parent.TenantID, parent.ID, id)
	if err != nil {
		return err
	}
	saved, err := a.canonicalDependentStep(ctx, parent.TenantID, parent.ID, head.ID)
	if err != nil {
		return err
	}
	if saved.Status != "succeeded" || saved.Report == nil {
		return errors.New("api: native start has no exact stopped predecessor")
	}
	if saved.Report.PoolProof != nil {
		next.PreviousPIDs = append([]uint32(nil), saved.Report.PoolProof.PreviousPIDs...)
	}
	return nil
}

func (a *API) appendDependentRuntimeSource(ctx context.Context, tenantID, id, kind string, version int, at time.Time, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	event := events.Event{ID: id, TenantID: tenantID, Type: kind, SchemaVersion: version, Time: at, Data: raw}
	if actor, ok := events.ActorFromContext(ctx); ok {
		event.Actor = &actor
	}
	canonical, err := a.log.Append(ctx, event)
	if err != nil {
		return err
	}
	if canonical.ID != id || canonical.TenantID != tenantID || canonical.Type != kind || canonical.SchemaVersion != version {
		return store.ErrIdempotencyConflict
	}
	return projections.New(a.store).Apply(ctx, canonical)
}
