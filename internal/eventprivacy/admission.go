// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

var (
	ErrPreparing  = errors.New("event privacy: key preparation is pending")
	ErrOffboarded = errors.New("event privacy: this tenant lifetime is offboarded")
)

type TenantGuard interface {
	WithTenantEventProtection(context.Context, string, func(context.Context) error) error
}

type ActivationCustody interface {
	CreationEvidence(context.Context, eventprotect.KeyRef) (eventprotect.KeyCreationEvidence, error)
	DestructionReceipt(context.Context, eventprotect.KeyRef) (string, bool, error)
}

// SourceAdmission holds the same tenant fence as custody through append. Policy
// comes from retained events; deleting or changing a SQL view cannot disable it.
type SourceAdmission struct {
	Policy  SourcePolicy
	Guard   TenantGuard
	Custody ActivationCustody
	Holds   HoldClearancePolicy
}

func (admission SourceAdmission) WithTenantEventProtection(ctx context.Context, tenantID string, visit func(context.Context) error) error {
	if admission.Guard == nil || visit == nil {
		return ErrSource
	}
	guardTenant := tenantID
	if tenantID == events.LegacyProviderGlobalAuditScope {
		var err error
		guardTenant, err = store.AuditCheckpointRLSID(tenantID)
		if err != nil {
			return err
		}
	}
	return admission.Guard.WithTenantEventProtection(ctx, guardTenant, visit)
}

func (admission SourceAdmission) EventProtectionFor(ctx context.Context, event events.Event) (events.EventProtectionDecision, error) {
	if event.Protection == nil && !event.SensitiveErased && event.SchemaVersion == 1 && events.IsLegacyProviderGlobalAudit(event) {
		return events.EventProtectionDecision{Mode: events.EventProtectionLegacy}, nil
	}
	tenant, err := uuid.Parse(event.TenantID)
	if err != nil || tenant == uuid.Nil || event.Protection != nil || event.SensitiveErased {
		return events.EventProtectionDecision{}, ErrSource
	}
	lifetime, err := admission.Policy.LatestLifetime(ctx, tenant.String())
	if err != nil {
		return events.EventProtectionDecision{}, err
	}
	switch event.Type {
	case EventRequested:
		request, err := ParseRequested(tenant.String(), event.Data)
		if err != nil || event.SchemaVersion != 1 || event.ID != RequestedEventID(request) || request.RegistrationIdentity != lifetime.Registration.ID ||
			(lifetime.Request != nil && lifetime.Request.Body != request) || (lifetime.Request == nil && lifetime.Offboard != nil) {
			return events.EventProtectionDecision{}, ErrSource
		}
		return events.EventProtectionDecision{Mode: events.EventProtectionPublicControl}, nil
	case EventActivated:
		return admission.activationDecision(ctx, event, lifetime)
	case EventDestroyed:
		return admission.completionDecision(ctx, event)
	case EventHoldClearance:
		return admission.holdClearanceDecision(ctx, event)
	}
	if event.Type == EventAuthorizationDecision && event.SchemaVersion == MinimalAuthzSchemaVersion {
		return admission.minimalAuthzDecision(event, lifetime)
	}
	if lifetime.Offboard != nil {
		// Feature-disabled audit-only decisions keep their prior representation.
		// Protected lifetimes use only the closed source-bound alternate above.
		if lifetime.Request == nil && event.Type == EventAuthorizationDecision && event.SchemaVersion == 1 {
			return events.EventProtectionDecision{Mode: events.EventProtectionLegacy}, nil
		}
		if event.Type == eventRegistered {
			return events.EventProtectionDecision{Mode: events.EventProtectionLegacy}, nil
		}
		return events.EventProtectionDecision{}, ErrOffboarded
	}
	if lifetime.Request == nil {
		return events.EventProtectionDecision{Mode: events.EventProtectionLegacy}, nil
	}
	if lifetime.Activation == nil {
		return events.EventProtectionDecision{}, ErrPreparing
	}
	if event.Type == eventOffboarded {
		if admission.Holds == nil {
			return events.EventProtectionDecision{}, ErrSource
		}
		if err := admission.Holds.RequireOffboardClear(ctx, lifetime); err != nil {
			return events.EventProtectionDecision{}, err
		}
	}
	return events.EventProtectionDecision{Mode: events.EventProtectionSensitive, Ref: lifetime.Activation.Body.Creation.Ref}, nil
}

func (admission SourceAdmission) activationDecision(ctx context.Context, event events.Event, lifetime Lifetime) (events.EventProtectionDecision, error) {
	activation, err := parseActivated(event, false)
	if err != nil || admission.Custody == nil || lifetime.Request == nil || activation.Requested() != lifetime.Request.Body ||
		activation.RequestedEventID != lifetime.Request.Meta.ID || activation.RequestedSequence != lifetime.Request.Meta.Sequence ||
		!activation.RequestedAt.Equal(lifetime.Request.Meta.Time) || (lifetime.Activation == nil && lifetime.Offboard != nil) {
		return events.EventProtectionDecision{}, ErrSource
	}
	if lifetime.Activation != nil && lifetime.Activation.Body.Creation.Digest() != activation.Creation.Digest() {
		return events.EventProtectionDecision{}, ErrSource
	}
	creation, err := admission.Custody.CreationEvidence(ctx, activation.Creation.Ref)
	if err != nil {
		return events.EventProtectionDecision{}, err
	}
	if creation.Digest() != activation.Creation.Digest() {
		return events.EventProtectionDecision{}, eventprotect.ErrKey
	}
	return events.EventProtectionDecision{Mode: events.EventProtectionPublicControl}, nil
}

func (admission SourceAdmission) completionDecision(ctx context.Context, event events.Event) (events.EventProtectionDecision, error) {
	completion, err := ParseDestroyed(event)
	if err != nil || admission.Custody == nil {
		return events.EventProtectionDecision{}, ErrSource
	}
	claims, err := admission.Policy.verifyDestructionReceipt(completion.JWS)
	if err != nil || event.Time.Before(claims.RemovedAt) {
		return events.EventProtectionDecision{}, ErrSource
	}
	tenant, err := uuid.Parse(event.TenantID)
	if err != nil || tenant.String() != claims.Request.Ref.TenantID {
		return events.EventProtectionDecision{}, ErrSource
	}
	lifetime, found, err := admission.Policy.LifetimeForKey(ctx, claims.Request.Ref)
	if err != nil {
		return events.EventProtectionDecision{}, err
	}
	if !found || !matchesLifetimeDestruction(lifetime, claims.Request) ||
		(lifetime.Completion != nil && (lifetime.Completion.Meta.ID != event.ID || lifetime.Completion.JWS != completion.JWS)) {
		return events.EventProtectionDecision{}, ErrSource
	}
	receipt, erased, err := admission.Custody.DestructionReceipt(ctx, claims.Request.Ref)
	if err != nil {
		return events.EventProtectionDecision{}, err
	}
	if !erased || receipt != completion.JWS {
		return events.EventProtectionDecision{}, eventprotect.ErrKey
	}
	return events.EventProtectionDecision{Mode: events.EventProtectionPublicControl}, nil
}
