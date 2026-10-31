// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// eventProtectionStatusBudget bounds the one-key readback the status route
// performs; the route answers unavailable rather than waiting on custody.
const eventProtectionStatusBudget = 2 * time.Second

// eventProtectionControls serves the tenant opt-in (A233) over the opened
// source's runtime. Every answer comes from the retained source and an
// independent key readback, never from a SQL flag.
type eventProtectionControls struct {
	runtime *eventProtectionRuntime
	orch    *orchestrator.Orchestrator
}

// eventProtectionAPIOption serves the controls when the source was opened with
// a protection runtime; without one the routes answer "not served".
func eventProtectionAPIOption(d Deps, orch *orchestrator.Orchestrator) api.Option {
	if d.eventProtection == nil || orch == nil {
		return api.WithEventProtection(nil)
	}
	return api.WithEventProtection(&eventProtectionControls{runtime: d.eventProtection, orch: orch})
}

func (c *eventProtectionControls) lifetime(ctx context.Context, tenantID string) (eventprivacy.Lifetime, error) {
	life, err := c.runtime.policy.LatestLifetime(ctx, tenantID)
	if err != nil {
		slog.WarnContext(ctx, "event protection: tenant source authority could not be read", "error", err)
		return eventprivacy.Lifetime{}, api.ErrEventProtectionUnavailable
	}
	return life, nil
}

func (c *eventProtectionControls) Status(ctx context.Context, tenantID string) (api.EventProtectionStatus, error) {
	life, err := c.lifetime(ctx, tenantID)
	if err != nil {
		return api.EventProtectionStatus{}, err
	}
	status := api.EventProtectionStatus{
		State: api.EventProtectionNotEnabled, RegistrationIdentity: life.Registration.ID,
		CustodyConfigured: c.runtime.custody != nil, LegacyEventsReadable: true,
		NextStep: "Preview, then enable, with the retention window your policy requires.",
	}
	if !status.CustodyConfigured {
		status.NextStep = "An operator sets privacy.event_protection.key_directory before a tenant can enable protection."
	}
	if life.Request == nil {
		return status, nil
	}
	request := life.Request.Body
	requestedAt := life.Request.Meta.Time.UTC()
	status.OperationID, status.Retention, status.RequestedAt = request.OperationID, time.Duration(request.RetentionNanos).String(), &requestedAt
	if life.Activation == nil {
		status.State = api.EventProtectionPreparing
		status.NextStep = "A bounded worker is preparing the tenant key; writes are refused until it is active."
		return status, nil
	}
	activatedAt := life.Activation.Meta.Time.UTC()
	status.ActivatedAt = &activatedAt
	// Active only when the exact activated key opens now. Missing material is
	// not erasure; it is unavailable, and the route never regenerates it.
	probe, cancel := context.WithTimeout(ctx, eventProtectionStatusBudget)
	defer cancel()
	if err := c.runtime.reader.WithKey(probe, life.Activation.Body.Creation.Ref, func(seal.KeyWrapper) error { return nil }); err != nil {
		slog.WarnContext(ctx, "event protection: active tenant key did not read back", "error", err)
		return api.EventProtectionStatus{}, api.ErrEventProtectionUnavailable
	}
	status.State = api.EventProtectionActive
	status.NextStep = "New sensitive event fields are sealed under the tenant key. Offboarding destroys it after the retention window."
	return status, nil
}

// plan computes the exact request and every reason it cannot apply now. It
// reads only; the same inputs give the same fingerprint.
func (c *eventProtectionControls) plan(ctx context.Context, tenantID string, req api.EventProtectionRequest) (api.EventProtectionPlan, eventprivacy.Requested, error) {
	req, retention, err := api.NormalizeEventProtectionRequest(req)
	if err != nil {
		return api.EventProtectionPlan{}, eventprivacy.Requested{}, err
	}
	request, err := eventprivacy.NewRequested(tenantID, req.RegistrationIdentity, retention)
	if err != nil {
		return api.EventProtectionPlan{}, eventprivacy.Requested{}, fmt.Errorf("%w: registration_identity is not a valid source identity", api.ErrEventProtectionInvalid)
	}
	life, err := c.lifetime(ctx, tenantID)
	if err != nil {
		return api.EventProtectionPlan{}, eventprivacy.Requested{}, err
	}
	wire, err := json.Marshal(struct {
		Domain  string                 `json:"domain"`
		Tenant  string                 `json:"tenant"`
		Request eventprivacy.Requested `json:"request"`
	}{"trstctl.event-protection-plan.v1", tenantID, request})
	if err != nil {
		return api.EventProtectionPlan{}, eventprivacy.Requested{}, err
	}
	plan := api.EventProtectionPlan{
		Capability: "event_protection", Operation: "enable", EffectFree: true,
		RequestFingerprint: crypto.SHA256Hex(wire), RequiredPermission: string(authz.PrivacyWrite),
		NormalizedRequest: req, OperationID: request.OperationID, CustodyConfigured: c.runtime.custody != nil,
		Blockers: []string{}, Warnings: []string{
			"Events recorded before the key is active stay readable; protection never rewrites them.",
			"Writes for this tenant are refused while the key is prepared.",
			"Offboarding destroys the key after the retention window with a signed destruction record; that cannot be undone.",
		},
		PreviewWrites: []string{}, PreviewExternalEffects: []string{},
		ExecuteWrites: []string{
			"Appends one tenant.event_protection.requested control event naming the registration and retention.",
			"A bounded worker creates one tenant key in the configured key directory and appends its activation.",
		},
		ExecuteExternalEffects: []string{},
		RecoverySteps: []string{
			"Repeating the same request with the same Idempotency-Key returns the original result and creates no second key.",
			"A request for a stale registration or a different retention is refused before anything is written.",
		},
		VerificationSteps: []string{
			"GET /api/v1/privacy/event-protection reports active only after the activated key reads back.",
		},
	}
	switch {
	case !plan.CustodyConfigured:
		plan.Blockers = append(plan.Blockers, "custody_not_configured: an operator sets privacy.event_protection.key_directory")
	case req.RegistrationIdentity != life.Registration.ID:
		plan.Blockers = append(plan.Blockers, "registration_not_current: read registration_identity from the status route")
	case life.Request != nil && life.Request.Body != request:
		plan.Blockers = append(plan.Blockers, "requested_with_different_policy: this registration already has a protection request")
	case life.Request != nil:
		plan.Blockers = append(plan.Blockers, "already_requested: this registration already has this protection request")
	}
	plan.Ready = len(plan.Blockers) == 0
	return plan, request, nil
}

func (c *eventProtectionControls) Preview(ctx context.Context, tenantID string, req api.EventProtectionRequest) (api.EventProtectionPlan, error) {
	plan, _, err := c.plan(ctx, tenantID, req)
	return plan, err
}

func (c *eventProtectionControls) Request(ctx context.Context, tenantID string, req api.EventProtectionRequest) (api.EventProtectionAccepted, error) {
	plan, request, err := c.plan(ctx, tenantID, req)
	if err != nil {
		return api.EventProtectionAccepted{}, err
	}
	// The same request for the same lifetime is a retry: the orchestrator finds
	// the retained event. Any other blocker refuses before a write.
	for _, blocker := range plan.Blockers {
		if !strings.HasPrefix(blocker, "already_requested") {
			return api.EventProtectionAccepted{}, fmt.Errorf("%w: %s", api.ErrEventProtectionConflict, blocker)
		}
	}
	if err := c.orch.RequestEventProtection(ctx, tenantID, request); err != nil {
		if errors.Is(err, eventprivacy.ErrSource) || errors.Is(err, store.ErrIdempotencyConflict) {
			return api.EventProtectionAccepted{}, fmt.Errorf("%w: the tenant's retained source refused the request", api.ErrEventProtectionConflict)
		}
		return api.EventProtectionAccepted{}, err
	}
	return api.EventProtectionAccepted{
		OperationID: request.OperationID, RegistrationIdentity: request.RegistrationIdentity,
		Retention: time.Duration(request.RetentionNanos).String(), State: api.EventProtectionPreparing,
	}, nil
}
