// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
)

const (
	eventRegistered = "tenant.registered"
	eventOffboarded = "tenant.offboarded"
)

type RequestSource struct {
	Meta events.EnvelopeMetadata
	Body Requested
}
type ActivationSource struct {
	Meta events.EnvelopeMetadata
	Body Activated
}
type CompletionSource struct {
	Meta   events.EnvelopeMetadata
	JWS    string
	Claims eventprotect.DestructionClaims
}

// Lifetime contains public source authority only. Ordinary name changes may use
// tenant.registered again; the FIRST registration after offboarding is the key
// lifetime. No SQL row or readable registration/offboard body chooses that key.
type Lifetime struct {
	Registration events.EnvelopeMetadata
	Request      *RequestSource
	Activation   *ActivationSource
	Offboard     *events.EnvelopeMetadata
	Completion   *CompletionSource
}

type SourcePolicy struct {
	Log   *events.Log
	Trust *jose.JWKSet
}

// LatestLifetime returns authority only after the complete finite source fold
// and its final history-generation check succeed. It never caches SQL state.
func (policy SourcePolicy) LatestLifetime(ctx context.Context, tenantID string) (Lifetime, error) {
	var result Lifetime
	err := policy.replayLifetimes(ctx, tenantID, func(lifetime Lifetime) error { result = lifetime; return nil })
	if err != nil {
		return Lifetime{}, err
	}
	return result, nil
}

func (policy SourcePolicy) replayLifetimes(ctx context.Context, tenantID string, visit func(Lifetime) error) error {
	if policy.Log == nil || tenantID == "" || visit == nil {
		return ErrSource
	}
	if parsed, err := uuid.Parse(tenantID); err == nil && parsed != uuid.Nil {
		tenantID = parsed.String()
	}
	return policy.Log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		head, err := policy.Log.LastSequence(readCtx)
		if err != nil {
			return err
		}
		var current Lifetime
		seen := make(map[string]events.EnvelopeMetadata)
		err = policy.Log.ReplayTenantMetadataTypesThrough(readCtx, tenantID, 1, head, []string{eventRegistered, eventOffboarded, EventRequested, EventActivated, EventDestroyed}, func(meta events.EnvelopeMetadata) error {
			if meta.SchemaVersion != 1 {
				return ErrSource
			}
			if first, duplicate := seen[meta.ID]; duplicate {
				// The durable identity index compares complete stored envelopes,
				// including ciphertext, without opening custody. ID/header equality
				// alone would accept a changed historical payload or actor.
				canonical, found, err := policy.Log.TenantMetadataByID(readCtx, tenantID, meta.ID)
				if err != nil {
					return errors.Join(ErrSource, err)
				}
				if !found || canonical.Sequence != first.Sequence || canonical.Type != first.Type ||
					canonical.SchemaVersion != first.SchemaVersion || !canonical.Time.Equal(first.Time) ||
					canonical.DeclaredKeyID != first.DeclaredKeyID {
					return ErrSource
				}
				return nil
			}
			seen[meta.ID] = meta
			switch meta.Type {
			case eventRegistered:
				if current.Registration.ID == "" || current.Offboard != nil {
					if current.Registration.ID != "" {
						if err := visit(current); err != nil {
							return err
						}
					}
					current = Lifetime{Registration: meta}
				}
				return nil
			case eventOffboarded:
				if current.Registration.ID == "" || current.Offboard != nil {
					return ErrSource
				}
				copy := meta
				current.Offboard = &copy
				return nil
			}
			if current.Registration.ID == "" {
				return ErrSource
			}
			// Check public metadata BEFORE a logical read. An encrypted control
			// must not recursively ask the controller to resolve its own key.
			if meta.DeclaredKeyID != "" {
				return ErrSource
			}
			event, found, err := policy.Log.EventAtSequence(readCtx, meta.Sequence)
			if err != nil {
				return err
			}
			eventTenant, tenantErr := uuid.Parse(event.TenantID)
			if !found || event.ID != meta.ID || event.Type != meta.Type || tenantErr != nil || eventTenant.String() != tenantID || !event.Time.Equal(meta.Time) {
				return ErrSource
			}
			switch meta.Type {
			case EventRequested:
				request, err := ParseRequested(tenantID, event.Data)
				if err != nil || request.RegistrationIdentity != current.Registration.ID || event.ID != RequestedEventID(request) {
					return ErrSource
				}
				if current.Request != nil {
					if current.Request.Body != request || current.Request.Meta.ID != meta.ID || !current.Request.Meta.Time.Equal(meta.Time) {
						return ErrSource
					}
					return nil
				}
				if current.Offboard != nil {
					return ErrSource
				}
				current.Request = &RequestSource{Meta: meta, Body: request}
			case EventActivated:
				activation, err := ParseActivated(event)
				if err != nil || current.Request == nil || activation.Requested() != current.Request.Body || activation.RequestedEventID != current.Request.Meta.ID || activation.RequestedSequence != current.Request.Meta.Sequence || !activation.RequestedAt.Equal(current.Request.Meta.Time) {
					return ErrSource
				}
				if current.Activation != nil {
					if current.Activation.Meta.ID != meta.ID || !current.Activation.Meta.Time.Equal(meta.Time) || current.Activation.Body.Creation.Digest() != activation.Creation.Digest() {
						return ErrSource
					}
					return nil
				}
				if current.Offboard != nil {
					return ErrSource
				}
				current.Activation = &ActivationSource{Meta: meta, Body: activation}
			case EventDestroyed:
				completion, err := ParseDestroyed(event)
				if err != nil || current.Activation == nil || current.Offboard == nil {
					return ErrSource
				}
				claims, err := eventprotect.VerifyDestructionReceipt(policy.Trust, completion.JWS)
				if err != nil || !matchesLifetimeDestruction(current, claims.Request) || event.Time.Before(claims.RemovedAt) {
					return ErrSource
				}
				if current.Completion != nil && (current.Completion.Meta.ID != meta.ID || current.Completion.JWS != completion.JWS) {
					return ErrSource
				}
				if current.Completion == nil {
					current.Completion = &CompletionSource{Meta: meta, JWS: completion.JWS, Claims: claims}
				}
			default:
				return ErrSource
			}
			return nil
		})
		if err != nil {
			return err
		}
		if current.Registration.ID != "" {
			return visit(current)
		}
		return nil
	})
}

func matchesLifetimeDestruction(lifetime Lifetime, request eventprotect.DestructionRequest) bool {
	expected, err := NewDestructionRequest(lifetime)
	if err != nil || !request.OffboardedAt.Equal(expected.OffboardedAt) || !request.NotBefore.Equal(expected.NotBefore) {
		return false
	}
	request.OffboardedAt, request.NotBefore = expected.OffboardedAt, expected.NotBefore
	return request == expected
}
