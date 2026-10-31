// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func eventKeyMessageFixture(destruction bool) orchestrator.Message {
	const tenant = "174048ba-fc30-4558-a79a-1cde6428b014"
	const key = "686c234a-4582-42c0-8a36-19e126f11eb0"
	at := time.Unix(1, 0).UTC()
	message := orchestrator.Message{ID: 1, TenantID: tenant, Attempts: 1, RequiredAgentRole: "control_plane", ReceiverAttemptID: "cae534ec-c301-44d3-90f0-03abdd23c55e"}
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

func TestEventKeyMessageParsersKeepRoutingAndBodyClosed(t *testing.T) {
	for _, destruction := range []bool{false, true} {
		good := eventKeyMessageFixture(destruction)
		parse := func(message orchestrator.Message) error {
			if destruction {
				_, err := parseEventKeyDestructionMessage(message)
				return err
			}
			_, err := parseEventKeyPreparationMessage(message)
			return err
		}
		if err := parse(good); err != nil {
			t.Fatal(err)
		}
		// jsonb can reorder keys and add whitespace. No byte-level command signature
		// is inferred from that transport; retained source and SQL claims grant effects.
		var object any
		if err := json.Unmarshal(good.Payload, &object); err != nil {
			t.Fatal(err)
		}
		spaced, err := json.MarshalIndent(object, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		changed := good
		changed.Payload = spaced
		if err := parse(changed); err != nil {
			t.Fatal("valid jsonb presentation was rejected")
		}
		for label, mutate := range map[string]func(*orchestrator.Message){
			"role":        func(m *orchestrator.Message) { m.RequiredAgentRole = "host" },
			"lane":        func(m *orchestrator.Message) { m.EffectLane += ".extra" },
			"destination": func(m *orchestrator.Message) { m.Destination += ".extra" },
			"tenant":      func(m *orchestrator.Message) { m.TenantID = "d59b4292-1adc-4d43-a405-781f95b1779c" },
			"invocation":  func(m *orchestrator.Message) { m.ReceiverAttemptID = "" },
			"id":          func(m *orchestrator.Message) { m.ID = 0 },
			"attempts":    func(m *orchestrator.Message) { m.Attempts = 0 },
			"idempotency": func(m *orchestrator.Message) { m.IdempotencyKey = "another-command" },
			"trailing":    func(m *orchestrator.Message) { m.Payload = append(append([]byte(nil), m.Payload...), []byte(` {}`)...) },
			"unknown":     func(m *orchestrator.Message) { m.Payload = append([]byte(`{"unknown":true,`), m.Payload[1:]...) },
			"oversize":    func(m *orchestrator.Message) { m.Payload = []byte(strings.Repeat(" ", 17<<10)) },
			"empty":       func(m *orchestrator.Message) { m.Payload = nil },
		} {
			t.Run(label, func(t *testing.T) {
				candidate := good
				mutate(&candidate)
				if err := parse(candidate); err == nil {
					t.Fatal("invalid command acquired a parsed delivery claim")
				}
			})
		}
	}
}

func TestEventKeyConfiguredCustodyRequiresIndependentDeliveryPools(t *testing.T) {
	st := newServerTestStore(t)
	cfg := eventProtectionRuntimeConfigFixture(t)
	key := testAuditSigningKey(t)
	log, custody, err := openConfiguredEventSource(t.Context(), cfg, st, key, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = custody.Close() })
	t.Cleanup(func() { _ = log.Close() })
	pools := bulkhead.NewSet(bulkhead.Config{Name: bulkhead.SubsystemOutbox, Workers: 1, Queue: 1})
	defer pools.Close()
	server, err := Build(t.Context(), Deps{Store: st, Log: log, AuditSigningKey: key, eventProtection: custody, Bulkhead: pools})
	if err == nil {
		_ = server.Shutdown(t.Context())
		t.Fatal("configured custody silently borrowed an ordinary delivery pool")
	}
	if !strings.Contains(err.Error(), "independent preparation and destruction worker pools") {
		t.Fatalf("missing pool failed for an unrelated reason: %v", err)
	}
}
