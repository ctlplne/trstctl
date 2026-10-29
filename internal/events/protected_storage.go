// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/schedulerhistory"
)

var ErrEventProtectionUnavailable = errors.New("events: protected source requires its independent key custodian")

const protectedWireSchemaVersion = -1

var protectedWireMarker = []byte("trstctl.protected-source.v1")

// EventProtectionAdmission must hold the same tenant admission fence through
// activation, append and destruction. An absent key means a never-activated
// tenant, not permission to fall back after key loss or offboarding. Production
// selection must verify retained source authority rather than trust SQL alone.
type EventProtectionAdmission interface {
	WithTenantEventProtection(context.Context, string, func(context.Context) error) error
	EventProtectionFor(context.Context, Event) (EventProtectionDecision, error)
}

type EventProtectionMode uint8

const (
	EventProtectionLegacy EventProtectionMode = iota
	EventProtectionSensitive
	EventProtectionPublicControl
)

type EventProtectionDecision struct {
	Mode EventProtectionMode
	Ref  eventprotect.KeyRef
}

type EventProtectionKeys interface {
	WithKey(context.Context, eventprotect.KeyRef, func(seal.KeyWrapper) error) error
}

type EventProtection struct {
	Keys      EventProtectionKeys
	Admission EventProtectionAdmission
}

func WithEventProtection(protection EventProtection) OpenOption {
	return func(log *Log) { copy := protection; log.eventProtection = &copy }
}

func protectionContext(e Event) eventprotect.Context {
	return eventprotect.Context{Scope: eventprotect.ScopeEvent, ID: e.ID, Type: e.Type,
		TenantID: e.TenantID, SchemaVersion: e.SchemaVersion, Time: e.Time}
}

func storedForEvent(e Event) (storedEvent, error) {
	stored := storedEvent{ID: e.ID, Type: e.Type, TenantID: e.TenantID, Time: e.Time,
		SchemaVersion: e.SchemaVersion, Data: e.Data, Actor: e.Actor}
	if e.Protection != nil {
		stored.SchemaVersion, stored.PayloadSchemaVersion = protectedWireSchemaVersion, e.SchemaVersion
		stored.Data, stored.Actor, stored.Protection = protectedWireMarker, nil, e.Protection
	}
	return stored, validateStoredProtection(stored)
}

func validateStoredProtection(stored storedEvent) error {
	if stored.Protection == nil {
		if stored.SchemaVersion < 0 || stored.PayloadSchemaVersion != 0 {
			return eventprotect.ErrEnvelope
		}
		return nil
	}
	if stored.SchemaVersion != protectedWireSchemaVersion || stored.PayloadSchemaVersion <= 0 ||
		stored.Actor != nil || !bytes.Equal(stored.Data, protectedWireMarker) {
		return eventprotect.ErrEnvelope
	}
	event := Event{ID: stored.ID, Type: stored.Type, TenantID: stored.TenantID, Time: stored.Time, SchemaVersion: stored.PayloadSchemaVersion}
	return eventprotect.ValidateEnvelope(protectionContext(event), stored.Protection.PolicyDigest, *stored.Protection)
}

func (l *Log) appendWithEventProtection(ctx context.Context, e Event, explicitTime bool) (Event, error) {
	if l.eventProtection == nil {
		return l.publishPreparedEvent(ctx, e)
	}
	var result Event
	err := l.withHistoryRead(ctx, func(readCtx context.Context) error {
		return l.eventProtection.Admission.WithTenantEventProtection(readCtx, e.TenantID, func(guardCtx context.Context) error {
			decision, err := l.eventProtection.Admission.EventProtectionFor(guardCtx, e)
			if err != nil {
				return err
			}
			if decision.Mode > EventProtectionPublicControl {
				return eventprotect.ErrContext
			}
			ref := decision.Ref
			canonical, found, err := l.rawEventByID(guardCtx, e.ID)
			if err != nil {
				return err
			}
			if found && (decision.Mode != EventProtectionLegacy || canonical.Protection != nil) {
				if normalizedTenantScope(canonical.TenantID) != normalizedTenantScope(e.TenantID) || canonical.Type != e.Type || canonical.SchemaVersion != e.SchemaVersion {
					return ErrConflictingEventIdentity
				}
				canonical, err = l.openProtectedEvent(guardCtx, canonical)
				if err != nil {
					return err
				}
				if canonical.SensitiveErased || !bytes.Equal(canonical.Data, e.Data) || !sameProtectedActorEncoding(canonical.Actor, e.Actor) ||
					(explicitTime && !canonical.Time.Equal(e.Time)) {
					return ErrConflictingEventIdentity
				}
				result = canonical
				return nil
			}
			if decision.Mode != EventProtectionSensitive {
				result, err = l.publishPreparedEvent(guardCtx, e)
				return err
			}
			tenant, err := uuid.Parse(e.TenantID)
			if err != nil || tenant == uuid.Nil || ref.TenantID != tenant.String() {
				return eventprotect.ErrContext
			}
			// The retained safety floor must remain inspectable without opening
			// keys. New production writes already use the closed v2 schema.
			if e.Type == schedulerhistory.EventType && e.SchemaVersion <= schedulerhistory.LegacySchemaVersion {
				return schedulerhistory.ErrSanitationRequired
			}
			digest, err := PrivacyEventPolicyDigest(e.Type, e.SchemaVersion)
			if err != nil {
				return err
			}
			var envelope eventprotect.Envelope
			if err := l.eventProtection.Keys.WithKey(guardCtx, ref, func(key seal.KeyWrapper) error {
				var err error
				envelope, err = eventprotect.Protect(key, protectionContext(e), ref.ID, digest, eventprotect.Payload{Data: e.Data, Actor: e.Actor})
				return err
			}); err != nil {
				return err
			}
			e.Protection = &envelope
			result, err = l.publishPreparedEvent(guardCtx, e)
			return err
		})
	})
	return result, err
}

func sameProtectedActorEncoding(left, right *Actor) bool {
	// Roles has omitempty: nil and an empty slice have the same stored meaning.
	// Compare the wire representation, not Go's allocation shape.
	leftWire, leftErr := json.Marshal(left)
	defer secret.Wipe(leftWire)
	rightWire, rightErr := json.Marshal(right)
	defer secret.Wipe(rightWire)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftWire, rightWire)
}

func (l *Log) openProtectedEvent(ctx context.Context, e Event) (Event, error) {
	if e.Protection == nil {
		return e, nil
	}
	if l.eventProtection == nil || l.eventProtection.Keys == nil {
		return Event{}, ErrEventProtectionUnavailable
	}
	digest, err := PrivacyEventPolicyDigest(e.Type, e.SchemaVersion)
	if err != nil {
		return Event{}, err
	}
	if err := eventprotect.ValidateEnvelope(protectionContext(e), digest, *e.Protection); err != nil {
		return Event{}, err
	}
	var opened eventprotect.Payload
	err = l.eventProtection.Keys.WithKey(ctx, eventprotect.KeyRef{TenantID: e.TenantID, ID: e.Protection.KeyID}, func(key seal.KeyWrapper) error {
		var err error
		opened, err = eventprotect.Open(key, protectionContext(e), digest, *e.Protection)
		return err
	})
	if err != nil {
		secret.Wipe(opened.Data)
	}
	if errors.Is(err, eventprotect.ErrDestroyed) {
		e.Data, e.Actor, e.SensitiveErased = nil, nil, true
		return e, nil
	}
	if err != nil {
		return Event{}, err
	}
	e.Data, e.Actor = opened.Data, opened.Actor
	return e, nil
}
