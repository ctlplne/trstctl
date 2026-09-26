// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
)

// TenantErasureRequest retains the original authorization's tenant generation
// and audit actor outside the SQL rows that the erase will remove. It contains
// no credential material. RequestBinding separately binds the HTTP principal,
// method, path and body to the source event.
type TenantErasureRequest struct {
	RegistrationIdentity string       `json:"registration_identity"`
	RegistrationSequence uint64       `json:"registration_sequence"`
	RegistrationAbsent   bool         `json:"registration_absent,omitempty"`
	Actor                events.Actor `json:"actor"`
}

// TenantOffboarder uses the production-assembled core projector and the same
// immutable Provider event source as other authority mutations.
type TenantOffboarder struct {
	store     *corestore.Store
	log       *events.Log
	orch      *orchestrator.Orchestrator
	mutations *EventMutationSink
	// Test-only crash seam after erasure and before the HTTP result is saved.
	afterErase func() error
	// Test-only crash seam after core preparation and before Provider append.
	beforeRequestAppend func() error
}

func NewTenantOffboarder(st *corestore.Store, log *events.Log, orch *orchestrator.Orchestrator, mutations *EventMutationSink) *TenantOffboarder {
	return &TenantOffboarder{store: st, log: log, orch: orch, mutations: mutations}
}

func (o *TenantOffboarder) execute(ctx context.Context, service *Service, actor Operator, tenantID string) error {
	return o.executeRequest(ctx, service, actor, tenantID, "")
}

// continueRequest recovers one already-authorized operation. Its public event
// reference is not a credential: current authentication, MFA, admin role and
// entitlement still apply, and only the original actor can continue it. A new
// HTTP key binds the continuation request, not a second erase authorization.
func (o *TenantOffboarder) continueRequest(ctx context.Context, service *Service, actor Operator, tenantID, requestID string) error {
	if _, err := uuid.Parse(requestID); err != nil {
		return ErrMutationConflict
	}
	return o.executeRequest(ctx, service, actor, tenantID, requestID)
}

func (o *TenantOffboarder) executeRequest(ctx context.Context, service *Service, actor Operator, tenantID, requestID string) error {
	if o == nil || o.store == nil || o.log == nil || o.orch == nil || o.mutations == nil {
		return fmt.Errorf("%w: core tenant erasure is not configured", ErrMutationPersistence)
	}
	if err := o.authorizeBeforeServiceBarrier(ctx, service, actor, tenantID, requestID); err != nil {
		return err
	}
	return o.store.WithTenantServiceBarrier(ctx, tenantID, func(fenced context.Context) error {
		return o.executeQuiesced(fenced, service, actor, tenantID, requestID)
	})
}

// Check authority before revealing contention. Recheck it under the exclusive
// fence below, since this preliminary read is not an authorization to mutate.
func (o *TenantOffboarder) authorizeBeforeServiceBarrier(ctx context.Context, service *Service, actor Operator, tenantID, requestID string) error {
	if err := service.requireMutation(actor, true); err != nil {
		return err
	}
	key, binding := mutationKeyFromContext(ctx), mutationBindingFromContext(ctx)
	if key == "" || binding == "" {
		return errors.New("provider: tenant erasure requires a bound idempotency key")
	}
	id := uuid.NewSHA1(providerMutationNamespace, []byte(tenantID+"\x00"+key)).String()
	if requestID != "" {
		id = requestID
	}
	retained, found, err := o.log.EventByID(ctx, id)
	if err != nil {
		return fmt.Errorf("%w: load tenant erasure request: %v", ErrMutationPersistence, err)
	}
	if !found {
		if requestID != "" {
			return ErrMutationConflict
		}
		return service.authorize(ctx, actor, tenantID, OpOffboard)
	}
	var request AuthorityEvent
	if retained.Type != AuditTenantErasureRequested || retained.TenantID != tenantID || retained.SchemaVersion != events.DefaultSchemaVersion ||
		json.Unmarshal(retained.Data, &request) != nil || (requestID == "" && request.RequestBinding != binding) ||
		request.Audit.OperatorID != actor.ID || validateAuthorityEvent(retained, request) != nil {
		return ErrMutationConflict
	}
	return nil
}

func (o *TenantOffboarder) executeQuiesced(ctx context.Context, service *Service, actor Operator, tenantID, requestID string) error {
	return withAuthorityFence(ctx, o.store, func(ctx context.Context) error {
		if err := service.requireMutation(actor, true); err != nil {
			return err
		}
		key, binding := mutationKeyFromContext(ctx), mutationBindingFromContext(ctx)
		if key == "" || binding == "" {
			return errors.New("provider: tenant erasure requires a bound idempotency key")
		}
		id := uuid.NewSHA1(providerMutationNamespace, []byte(tenantID+"\x00"+key)).String()
		if requestID != "" {
			id = requestID
		}
		retained, found, err := o.log.EventByID(ctx, id)
		if err != nil {
			return fmt.Errorf("%w: load tenant erasure request: %v", ErrMutationPersistence, err)
		}
		var request AuthorityEvent
		if found {
			if retained.Type != AuditTenantErasureRequested || retained.TenantID != tenantID || retained.SchemaVersion != events.DefaultSchemaVersion ||
				json.Unmarshal(retained.Data, &request) != nil || (requestID == "" && request.RequestBinding != binding) ||
				request.Audit.OperatorID != actor.ID || validateAuthorityEvent(retained, request) != nil {
				return ErrMutationConflict
			}
			if err := o.mutations.projection.Apply(ctx, retained); err != nil {
				return fmt.Errorf("%w: recover tenant erasure request: %v", ErrMutationPersistence, err)
			}
		} else {
			if requestID != "" {
				return ErrMutationConflict
			}
			if err := service.authorize(ctx, actor, tenantID, OpOffboard); err != nil {
				return err
			}
			tenant, err := service.store.Tenant(ctx, tenantID)
			if err != nil {
				return err
			}
			if tenant.Status == TenantOffboarding {
				return ErrTenantStateConflict
			}
			var registration orchestrator.TenantRegistrationAuthority
			_, lookupErr := o.store.GetTenant(ctx, tenantID)
			absent := corestore.IsNotFound(lookupErr)
			if absent {
				if err := o.withUnregisteredCustomer(ctx, tenantID, nil); err != nil {
					return err
				}
			} else {
				if lookupErr != nil {
					return fmt.Errorf("%w: inspect customer registration: %v", ErrMutationPersistence, lookupErr)
				}
				registration, err = orchestrator.ResolveLiveTenantRegistrationAuthority(ctx, o.log, o.store, tenantID)
				if err != nil {
					if errors.Is(err, orchestrator.ErrIdempotencyConflict) {
						return fmt.Errorf("%w: customer retained registration history is incomplete; restore and verify it before offboarding", ErrTenantStateConflict)
					}
					return fmt.Errorf("%w: resolve authorized tenant registration: %v", ErrMutationPersistence, err)
				}
			}
			now := service.clock()
			tenant.Status, tenant.UpdatedAt = TenantOffboarding, now
			request = AuthorityEvent{Tenant: &tenant, RequestBinding: binding,
				Erasure: &TenantErasureRequest{RegistrationIdentity: registration.EventID, RegistrationSequence: registration.EventSequence, RegistrationAbsent: absent,
					Actor: events.Actor{Subject: actor.ID, Roles: []string{string(actor.Role)}}},
				Audit: AuditEvent{Type: AuditTenantErasureRequested, TenantID: tenantID, OperatorID: actor.ID, OperatorEmail: actor.Email, At: now}}
			if !absent {
				// Persist core's registration/actor-bound command receiver before
				// the Provider event can survive a crash. A failed append or
				// projection must not depend on a licensed callback to deny service.
				if err := o.orch.PrepareTenantOffboard(events.ContextWithActor(ctx, request.Erasure.Actor),
					orchestrator.TenantOffboardCommand{TenantID: tenantID, RegistrationIdentity: registration.EventID}); err != nil {
					return fmt.Errorf("%w: prepare core tenant erasure: %w", ErrMutationPersistence, err)
				}
			}
			if o.beforeRequestAppend != nil {
				if err := o.beforeRequestAppend(); err != nil {
					return fmt.Errorf("%w: %v", ErrMutationPersistence, err)
				}
			}
			retained, err = o.mutations.Append(ctx, key, AuditTenantErasureRequested, tenantID, request)
			if err != nil {
				return err
			}
			if err := json.Unmarshal(retained.Data, &request); err != nil {
				return fmt.Errorf("%w: decode retained tenant erasure: %v", ErrMutationPersistence, err)
			}
		}
		if request.Erasure.RegistrationAbsent {
			if err := o.completeUnregistered(ctx, retained, request, service.clock()); err != nil {
				if errors.Is(err, ErrTenantStateConflict) || errors.Is(err, ErrMutationConflict) {
					if recordErr := o.recordErasureConflict(ctx, retained, request, service.clock()); recordErr != nil {
						return recordErr
					}
				}
				return err
			}
			if o.afterErase != nil {
				if err := o.afterErase(); err != nil {
					return fmt.Errorf("%w: %v", ErrMutationPersistence, err)
				}
			}
			return o.recordErasureCompletion(ctx, retained, request, service.clock())
		}
		// The retained request is authority for its own completion after deletion
		// revokes the original grant. It never authorizes a different key, caller
		// or tenant generation, and current authentication/MFA/licensing still run.
		command := orchestrator.TenantOffboardCommand{
			TenantID: tenantID, RegistrationIdentity: request.Erasure.RegistrationIdentity,
		}
		eraseCtx := events.ContextWithActor(ctx, request.Erasure.Actor)
		_, err = o.orch.OffboardTenant(eraseCtx, command)
		if errors.Is(err, ErrAuthorityRebuildRequired) {
			// The core transaction has rolled back. Recover Provider's ordered
			// prefix outside that transaction, then retry the exact core command.
			// Its pending receiver denies service throughout the gap. Never drop
			// the receipt/order guard or retry with a fresh tenant registration.
			if recoveryErr := o.mutations.projection.recoverOrdered(ctx, o.log); recoveryErr != nil {
				return fmt.Errorf("%w: recover authority before tenant erasure: %v", ErrMutationPersistence, recoveryErr)
			}
			_, err = o.orch.OffboardTenant(eraseCtx, command)
		}
		if errors.Is(err, orchestrator.ErrIdempotencyConflict) {
			if recordErr := o.recordErasureConflict(ctx, retained, request, service.clock()); recordErr != nil {
				return recordErr
			}
			return ErrMutationConflict
		}
		if err != nil {
			return fmt.Errorf("%w: complete tenant erasure: %v", ErrMutationPersistence, err)
		}
		if o.afterErase != nil {
			if err := o.afterErase(); err != nil {
				return fmt.Errorf("%w: %v", ErrMutationPersistence, err)
			}
		}
		return o.recordErasureCompletion(ctx, retained, request, service.clock())
	})
}
