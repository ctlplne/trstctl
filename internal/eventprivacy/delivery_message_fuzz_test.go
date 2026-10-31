// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/store"
)

func eventKeyMessageFixture(destruction bool) DeliveryMessage {
	const tenant = "174048ba-fc30-4558-a79a-1cde6428b014"
	const key = "686c234a-4582-42c0-8a36-19e126f11eb0"
	at := time.Unix(1, 0).UTC()
	message := DeliveryMessage{ID: 1, TenantID: tenant, Attempts: 1, RequiredAgentRole: "control_plane", ReceiverAttemptID: "cae534ec-c301-44d3-90f0-03abdd23c55e"}
	if destruction {
		command := eventprotect.DestructionRequest{Ref: eventprotect.KeyRef{TenantID: tenant, ID: key}, OperationID: "2a54ea2a-904e-40e9-bcc8-468fd23f17df", RegistrationIdentity: "fixture-registration", ActivationEventID: key, ActivationSequence: 2, CreationDigest: strings.Repeat("a", 64), OffboardEventID: "fixture-offboard", OffboardSequence: 3, OffboardedAt: at, NotBefore: at.Add(time.Hour)}
		message.Payload, _ = json.Marshal(command)
		message.Destination = store.EventKeyDestructionDestination
		message.IdempotencyKey = store.EventKeyDestructionOutboxKey(command.OperationID)
	} else {
		command := store.EventKeyPreparationCommand{Ref: eventprotect.KeyRef{TenantID: tenant, ID: key}, RegistrationIdentity: "fixture-registration", RequestedEventID: key + ":requested", RequestedSequence: 1, RequestedAt: at, RetentionNanos: int64(time.Hour)}
		message.Payload, _ = json.Marshal(command)
		message.Destination = store.EventKeyPreparationDestination
		message.IdempotencyKey = store.EventKeyPreparationOutboxKey(key)
	}
	message.EffectLane = message.Destination
	return message
}

func FuzzEventKeyDeliveryCommand(f *testing.F) {
	for _, destruction := range []bool{false, true} {
		f.Add(destruction, eventKeyMessageFixture(destruction).Payload)
	}
	f.Add(false, []byte(`{}`))
	f.Add(true, []byte(`null`))
	f.Fuzz(func(t *testing.T, destruction bool, wire []byte) {
		message := eventKeyMessageFixture(destruction)
		message.Payload = wire
		if destruction {
			claim, err := ParseDestructionDelivery(message)
			if err != nil {
				return
			}
			if claim.Command.Validate() != nil || claim.Command.Ref.TenantID != message.TenantID || claim.ID != message.ID || claim.AttemptID != message.ReceiverAttemptID {
				t.Fatal("parser changed a command's routing identity")
			}
		} else {
			claim, err := ParsePreparationDelivery(message)
			if err != nil {
				return
			}
			if claim.Command.Validate() != nil || claim.Command.Ref.TenantID != message.TenantID || claim.ID != message.ID || claim.AttemptID != message.ReceiverAttemptID {
				t.Fatal("parser changed a command's routing identity")
			}
		}
	})
}
