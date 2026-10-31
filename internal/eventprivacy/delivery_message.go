// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"io"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/store"
)

// DeliveryMessage is routing/claim identity read from a durable outbox row.
// Parsing it grants no source, tenant service or custody effect authority.
type DeliveryMessage struct {
	ID                int64
	TenantID          string
	Destination       string
	IdempotencyKey    string
	Payload           []byte
	Attempts          int
	EffectLane        string
	RequiredAgentRole string
	ReceiverAttemptID string
}

func decodeEventKeyCommand(wire []byte, target any) error {
	if len(wire) == 0 || len(wire) > 16<<10 {
		return errors.New("server: invalid event-key command frame")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("server: invalid event-key command body")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("server: event-key command has trailing data")
	}
	return nil
}

func validEventKeyInvocation(message DeliveryMessage, destination string) bool {
	invocation, err := uuid.Parse(message.ReceiverAttemptID)
	tenant, tenantErr := uuid.Parse(message.TenantID)
	return err == nil && invocation.Version() == 4 && invocation.String() == message.ReceiverAttemptID && tenantErr == nil && tenant != uuid.Nil && tenant.String() == message.TenantID &&
		message.ID > 0 && message.Attempts > 0 && message.Destination == destination && message.EffectLane == destination && message.RequiredAgentRole == "control_plane"
}

// Parsing checks routing only. The receivers independently verify the exact
// committed lease/token, retained source and current custody before any effect.
func ParsePreparationDelivery(message DeliveryMessage) (PreparationClaim, error) {
	var command store.EventKeyPreparationCommand
	if !validEventKeyInvocation(message, store.EventKeyPreparationDestination) || decodeEventKeyCommand(message.Payload, &command) != nil || command.Validate() != nil || command.Ref.TenantID != message.TenantID || message.IdempotencyKey != store.EventKeyPreparationOutboxKey(command.Ref.ID) {
		return PreparationClaim{}, errors.New("server: invalid event-key preparation delivery")
	}
	return PreparationClaim{ID: message.ID, AttemptID: message.ReceiverAttemptID, Attempts: message.Attempts, Command: command}, nil
}

func ParseDestructionDelivery(message DeliveryMessage) (DestructionClaim, error) {
	var command eventprotect.DestructionRequest
	if !validEventKeyInvocation(message, store.EventKeyDestructionDestination) || decodeEventKeyCommand(message.Payload, &command) != nil || command.Validate() != nil || command.Ref.TenantID != message.TenantID || message.IdempotencyKey != store.EventKeyDestructionOutboxKey(command.OperationID) {
		return DestructionClaim{}, errors.New("server: invalid event-key destruction delivery")
	}
	return DestructionClaim{ID: message.ID, AttemptID: message.ReceiverAttemptID, Attempts: message.Attempts, Command: command}, nil
}
