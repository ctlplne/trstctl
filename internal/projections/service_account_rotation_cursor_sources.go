// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"context"
	"encoding/json"
	"errors"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

var ErrServiceDependentCursorSource = errors.New("dependent cursor: projection differs from canonical source")

// ResolveServiceDependentManifest reads each named immutable page directly.
// The caller validates the whole chain at admission; normal native work never
// selects its object through a mutable SQL ordinal-to-page index.
func ResolveServiceDependentManifest(ctx context.Context, log *events.Log, tenantID string, intent servicedependents.RotationIntent) (servicedependents.RotationManifestResolver, error) {
	var none servicedependents.RotationManifestResolver
	opened, found, err := log.EventByID(ctx, servicedependents.RotationManifestHeaderSourceID(tenantID, intent.Plan.ID))
	if err != nil {
		return none, err
	}
	var header ServiceDependentManifestOpened
	if !found || opened.TenantID != tenantID || decodePublishedDependentSource(opened.Data, &header) != nil || ValidateServiceDependentManifestOpened(opened, header) != nil {
		return none, ErrServiceDependentCursorSource
	}
	sealed, found, err := log.EventByID(ctx, servicedependents.RotationManifestSealSourceID(tenantID, intent.Plan.ID))
	if err != nil {
		return none, err
	}
	var seal ServiceDependentManifestSealed
	if !found || sealed.TenantID != tenantID || sealed.Sequence <= opened.Sequence || decodePublishedDependentSource(sealed.Data, &seal) != nil || ValidateServiceDependentManifestSealed(sealed, seal, header.Header) != nil || seal.Actor != header.Actor {
		return none, ErrServiceDependentCursorSource
	}
	exact, err := servicedependents.NewRotationIntentFromManifest(header.Header, seal.Seal)
	if err != nil {
		return none, err
	}
	want, err := exact.Digest()
	if err != nil {
		return none, err
	}
	got, err := intent.Digest()
	if err != nil || got != want {
		return none, ErrServiceDependentCursorSource
	}
	return servicedependents.RotationManifestResolver{Header: header.Header, Seal: seal.Seal, Page: func(number int64) (servicedependents.RotationManifestPage, error) {
		var value ServiceDependentManifestPageRecorded
		source, found, err := log.EventByID(ctx, servicedependents.RotationManifestPageSourceID(tenantID, intent.Plan.ID, number))
		if err != nil {
			return value.Page, err
		}
		if !found || source.TenantID != tenantID || source.Sequence <= opened.Sequence || source.Sequence >= sealed.Sequence || decodePublishedDependentSource(source.Data, &value) != nil || ValidateServiceDependentManifestPage(source, value, header.Header) != nil || value.Actor != header.Actor || value.Page.Number != number {
			return value.Page, ErrServiceDependentCursorSource
		}
		return value.Page, nil
	}}, nil
}

// ResolveServiceDependentManifestCursor verifies the named cursor source and
// one immediate predecessor. Sources are append-only and each transition is
// checked before append and during projection. A deterministic pending successor
// fences an old SQL position even when append outpaced projection. Readers may
// refuse it; the worker may project this exact metadata before trying again.
func ResolveServiceDependentManifestCursor(ctx context.Context, log *events.Log, parent store.ServiceDependentRotation) (servicedependents.RotationManifestResolver, *events.Event, error) {
	r, err := ResolveServiceDependentManifest(ctx, log, parent.TenantID, parent.Intent)
	if err != nil {
		return r, nil, err
	}
	root, found, err := log.EventByID(ctx, parent.ID)
	if err != nil {
		return r, nil, err
	}
	var queued ServiceDependentRotationQueued
	if !found || root.TenantID != parent.TenantID || json.Unmarshal(root.Data, &queued) != nil || ValidateServiceDependentRotationSource(root, queued) != nil {
		return r, nil, ErrServiceDependentCursorSource
	}
	rootDigest, err := queued.Intent.Digest()
	if err != nil || rootDigest != parent.IntentDigest {
		return r, nil, ErrServiceDependentCursorSource
	}
	sealed, found, err := log.EventByID(ctx, servicedependents.RotationManifestSealSourceID(parent.TenantID, parent.ID))
	if err != nil {
		return r, nil, err
	}
	if !found || sealed.Sequence >= root.Sequence {
		return r, nil, ErrServiceDependentCursorSource
	}
	inverse, hasInverse, err := log.EventByID(ctx, servicedependents.InverseSourceID(parent.ID))
	if err != nil {
		return r, nil, err
	}
	direction := servicedependents.Forward
	if hasInverse {
		var value ServiceDependentRotationInverse
		if inverse.TenantID != parent.TenantID || inverse.Type != EventServiceDependentRotationInverse || schemaVersionOf(inverse) != 1 || inverse.Sequence <= root.Sequence || json.Unmarshal(inverse.Data, &value) != nil || value.RotationID != parent.ID || value.IntentDigest != parent.IntentDigest {
			return r, nil, ErrServiceDependentCursorSource
		}
		direction = servicedependents.Inverse
	}
	if parent.Direction != direction {
		return r, nil, ErrServiceDependentCursorSource
	}
	if parent.ManifestCursor == nil || parent.ManifestCursor.Validate(r.Seal) != nil {
		return r, nil, ErrServiceDependentCursorSource
	}
	resolve := func(source events.Event) (servicedependents.ManifestCursor, error) {
		var none servicedependents.ManifestCursor
		if source.TenantID != parent.TenantID || source.Sequence == 0 {
			return none, ErrServiceDependentCursorSource
		}
		switch source.Type {
		case EventServiceDependentRotationQueued:
			var v ServiceDependentRotationQueued
			if json.Unmarshal(source.Data, &v) != nil || source.ID != parent.ID || ValidateServiceDependentRotationSource(source, v) != nil {
				return none, ErrServiceDependentCursorSource
			}
			digest, e := v.Intent.Digest()
			if e != nil || digest != parent.IntentDigest {
				return none, ErrServiceDependentCursorSource
			}
			return r.Initial(servicedependents.Forward)
		case EventServiceDependentRotationInverse:
			var v ServiceDependentRotationInverse
			if schemaVersionOf(source) != 1 || source.ID != servicedependents.InverseSourceID(parent.ID) || decodePublishedDependentSource(source.Data, &v) != nil || v.RotationID != parent.ID || v.IntentDigest != parent.IntentDigest {
				return none, ErrServiceDependentCursorSource
			}
			return r.Initial(servicedependents.Inverse)
		case EventServiceDependentCursorAdvanced:
			var v ServiceDependentCursorAdvanced
			if decodePublishedDependentSource(source.Data, &v) != nil || ValidateServiceDependentCursorAdvanceSource(source, v, parent.Intent) != nil {
				return none, ErrServiceDependentCursorSource
			}
			// This immutable source attests the fully checked transition. Its
			// producer and projection resolve page links, eligibility and signed
			// native evidence. Native readers verify coordinates, exact lineage,
			// current direction and pending successors without replaying those pages.
			return v.To, nil
		}
		return none, ErrServiceDependentCursorSource
	}
	source, found, err := log.EventByID(ctx, parent.ManifestCursorSourceID)
	if err != nil {
		return r, nil, err
	}
	if !found || source.Sequence < root.Sequence || source.Sequence != parent.ManifestCursorSequence || hasInverse && source.Sequence < inverse.Sequence {
		return r, nil, ErrServiceDependentCursorSource
	}
	current, err := resolve(source)
	if err != nil || current != *parent.ManifestCursor || current.Direction != parent.Direction {
		return r, nil, ErrServiceDependentCursorSource
	}
	if source.Type == EventServiceDependentCursorAdvanced {
		var v ServiceDependentCursorAdvanced
		if json.Unmarshal(source.Data, &v) != nil {
			return r, nil, ErrServiceDependentCursorSource
		}
		previous, found, e := log.EventByID(ctx, v.PreviousSourceID)
		if e != nil {
			return r, nil, e
		}
		if !found || previous.Sequence >= source.Sequence {
			return r, nil, ErrServiceDependentCursorSource
		}
		from, e := resolve(previous)
		if e != nil || from != v.From {
			return r, nil, ErrServiceDependentCursorSource
		}
	}
	pending, found, err := log.EventByID(ctx, servicedependents.ManifestCursorAdvanceSourceID(parent.TenantID, parent.ID, source.ID))
	if err != nil {
		return r, nil, err
	}
	if found {
		var v ServiceDependentCursorAdvanced
		if pending.Sequence <= source.Sequence || decodePublishedDependentSource(pending.Data, &v) != nil || ValidateServiceDependentCursorAdvanceSource(pending, v, parent.Intent) != nil || v.PreviousSourceID != source.ID || v.From != current {
			return r, nil, ErrServiceDependentCursorSource
		}
		if _, err := resolve(pending); err != nil {
			return r, nil, err
		}
		return r, &pending, nil
	}
	return r, nil, nil
}
