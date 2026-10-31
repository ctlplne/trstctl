// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/tenancy"
)

// The normal and post-delete boxes never share a service-admission callback.
// Family selection is shared by live ticks and the causal shutdown drain.
type eventKeyDelivery struct {
	preparationOutbox *orchestrator.Outbox
	preparation       orchestrator.Handler
	destruction       orchestrator.Handler
	destructionOutbox *orchestrator.Outbox
}

func (s *Server) configureEventKeyDelivery(d Deps, orch *orchestrator.Orchestrator) error {
	runtime := d.eventProtection
	if runtime == nil || runtime.custody == nil {
		return nil
	}
	if runtime.authority == nil || s.bulk == nil || s.bulk.Pool(bulkhead.SubsystemOutboxEventKeyPreparation) == nil || s.bulk.Pool(bulkhead.SubsystemOutboxEventKeyDestruction) == nil {
		return errors.New("server: configured event keys require independent preparation and destruction worker pools")
	}
	prepare := eventprivacy.PreparationReceiver{Policy: runtime.policy, Claims: d.Store, Guard: d.Store, Custody: runtime.custody, Record: orch.RecordEventProtectionControl}
	destroy := eventprivacy.DestructionReceiver{Policy: runtime.policy, Claims: d.Store, Guard: d.Store, Custody: runtime.custody, Authority: runtime.authority, Record: orch.RecordEventProtectionControl}
	prepBox := s.newEventKeyOutbox(d, d.TenantServiceCheck)
	box := s.newEventKeyOutbox(d, d.Store.RequireEventKeyDestructionService)

	s.eventKeyDelivery = &eventKeyDelivery{
		preparationOutbox: prepBox,
		preparation: orchestrator.HandlerFunc(func(ctx context.Context, message orchestrator.Message) error {
			claim, err := parseEventKeyPreparationMessage(message)
			if err != nil {
				return orchestrator.DefiniteNoEffect(err)
			}
			return prepare.Prepare(ctx, claim)
		}),
		destruction: orchestrator.HandlerFunc(func(ctx context.Context, message orchestrator.Message) error {
			claim, err := parseEventKeyDestructionMessage(message)
			if err != nil {
				return orchestrator.DefiniteNoEffect(err)
			}
			return destroy.Destroy(ctx, claim)
		}),
		destructionOutbox: box,
	}
	return nil
}

func (s *Server) dispatchOutboxFamily(ctx context.Context, family outboxDispatchFamily) (int, error) {
	switch family.eventKeyKind {
	case 0:
		return s.outbox.DispatchScoped(ctx, s.obHandler, family.scope)
	case 1:
		if s.eventKeyDelivery == nil {
			return 0, nil
		}
		return s.eventKeyDelivery.preparationOutbox.DispatchScoped(ctx, s.eventKeyDelivery.preparation, family.scope)
	case 2:
		if s.eventKeyDelivery == nil {
			return 0, nil
		}
		return s.eventKeyDelivery.destructionOutbox.DispatchScoped(ctx, s.eventKeyDelivery.destruction, family.scope)
	default:
		return 0, errors.New("server: unknown event-key delivery family")
	}
}

func eventKeyDeliveryMessage(message orchestrator.Message) eventprivacy.DeliveryMessage {
	return eventprivacy.DeliveryMessage{ID: message.ID, TenantID: message.TenantID, Destination: message.Destination, IdempotencyKey: message.IdempotencyKey, Payload: message.Payload, Attempts: message.Attempts, EffectLane: message.EffectLane, RequiredAgentRole: message.RequiredAgentRole, ReceiverAttemptID: message.ReceiverAttemptID}
}

func parseEventKeyPreparationMessage(message orchestrator.Message) (eventprivacy.PreparationClaim, error) {
	return eventprivacy.ParsePreparationDelivery(eventKeyDeliveryMessage(message))
}
func parseEventKeyDestructionMessage(message orchestrator.Message) (eventprivacy.DestructionClaim, error) {
	return eventprivacy.ParseDestructionDelivery(eventKeyDeliveryMessage(message))
}

func (s *Server) newEventKeyOutbox(d Deps, check tenancy.ServiceCheck) *orchestrator.Outbox {
	return orchestrator.NewOutbox(d.Store,
		orchestrator.WithTenantServiceCheck(check),
		orchestrator.WithDeliveryTimeout(d.OutboxDeliveryTimeout),
		orchestrator.WithDeliveryTimeoutObserver(func(message orchestrator.Message) {
			s.mOutboxDeliveryTimeouts.WithLabelValues(message.Destination).Inc()
		}),
		orchestrator.WithCircuitObserver(func(transition orchestrator.CircuitTransition) {
			s.mOutboxCircuitTransitions.WithLabelValues(transition.Destination, string(transition.From), string(transition.To)).Inc()
		}),
	)
}
