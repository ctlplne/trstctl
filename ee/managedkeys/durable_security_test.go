// SPDX-License-Identifier: LicenseRef-trstctl-EE

package managedkeys

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

type managedKeyCustodySpy struct {
	calls  int
	result signing.ManagedKeyResult
}

type managedKeyApprovalSpy struct{ calls int }

func (s *managedKeyApprovalSpy) IsApproved(context.Context, string, string, string, string) (bool, string) {
	s.calls++
	return false, "approval deliberately unavailable after original completion"
}

func (s *managedKeyCustodySpy) ManageKey(context.Context, signing.ManagedKeyCommand) (signing.ManagedKeyResult, error) {
	s.calls++
	return s.result, nil
}

func testDurableManagedKeyCommand() (projections.ManagedKeyCommand, store.ManagedKeyOperation, orchestrator.Message) {
	command := projections.ManagedKeyCommand{
		OperationID: "managedkey:operation-1", Provider: "aws-kms", Action: "revoke",
		KeyID: "kms-key-1", Algorithm: string(crypto.RSA2048),
		RequestBinding: "7de7890fd3d4a5d98398c6c3c5af8c08e07fc174e7e1f071f9f5496c097e47d0",
	}
	stored := store.ManagedKeyOperation{
		TenantID: "11111111-1111-1111-1111-111111111111", OperationID: command.OperationID,
		Provider: command.Provider, Action: command.Action, KeyID: command.KeyID,
		Algorithm: command.Algorithm, RequestBinding: command.RequestBinding, Status: "queued", OutboxID: 42,
	}
	payload, _ := json.Marshal(command)
	message := orchestrator.Message{
		ID: 42, TenantID: stored.TenantID, Destination: managedKeyCommandDestination,
		EffectLane:     store.ManagedKeyEffectLane(command.Provider, command.KeyID, command.OperationID),
		IdempotencyKey: command.OperationID, Payload: payload,
	}
	return command, stored, message
}

func TestManagedKeyOutboxRejectsEveryDurableIdentityMismatchBeforeSigner(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*projections.ManagedKeyCommand, *store.ManagedKeyOperation, *orchestrator.Message)
	}{
		{name: "operation", mutate: func(c *projections.ManagedKeyCommand, _ *store.ManagedKeyOperation, _ *orchestrator.Message) {
			c.OperationID = "managedkey:other"
		}},
		{name: "stored-operation", mutate: func(_ *projections.ManagedKeyCommand, s *store.ManagedKeyOperation, _ *orchestrator.Message) {
			s.OperationID = "managedkey:other"
		}},
		{name: "provider", mutate: func(c *projections.ManagedKeyCommand, _ *store.ManagedKeyOperation, _ *orchestrator.Message) {
			c.Provider = "gcp-kms"
		}},
		{name: "action", mutate: func(c *projections.ManagedKeyCommand, _ *store.ManagedKeyOperation, _ *orchestrator.Message) {
			c.Action = "zeroize"
		}},
		{name: "key", mutate: func(c *projections.ManagedKeyCommand, _ *store.ManagedKeyOperation, _ *orchestrator.Message) {
			c.KeyID = "kms-key-2"
		}},
		{name: "algorithm", mutate: func(c *projections.ManagedKeyCommand, _ *store.ManagedKeyOperation, _ *orchestrator.Message) {
			c.Algorithm = string(crypto.ECDSAP256)
		}},
		{name: "request-binding", mutate: func(c *projections.ManagedKeyCommand, _ *store.ManagedKeyOperation, _ *orchestrator.Message) {
			c.RequestBinding = "4f54e11d8ed110e6f4e92510a5194ce2bb03b90b94d1f81ae958de7e0b99b773"
		}},
		{name: "empty-binding", mutate: func(c *projections.ManagedKeyCommand, _ *store.ManagedKeyOperation, _ *orchestrator.Message) {
			c.RequestBinding = ""
		}},
		{name: "outbox-row", mutate: func(_ *projections.ManagedKeyCommand, s *store.ManagedKeyOperation, _ *orchestrator.Message) {
			s.OutboxID++
		}},
		{name: "effect-lane", mutate: func(_ *projections.ManagedKeyCommand, _ *store.ManagedKeyOperation, m *orchestrator.Message) {
			m.EffectLane = "managedkey.command:aws-kms:kms-key-attacker-selected"
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command, stored, message := testDurableManagedKeyCommand()
			test.mutate(&command, &stored, &message)
			message.Payload, _ = json.Marshal(command)
			spy := &managedKeyCustodySpy{}
			handler := &durableOutboxHandler{
				signer: spy,
				loadOperation: func(context.Context, string, string) (store.ManagedKeyOperation, error) {
					return stored, nil
				},
			}
			handled, err := handler.DeliverLicensed(context.Background(), message)
			if !handled || err == nil {
				t.Fatalf("identity mismatch handled=%v err=%v, want handled failure", handled, err)
			}
			if spy.calls != 0 {
				t.Fatalf("identity mismatch reached isolated signer %d times, want zero", spy.calls)
			}
		})
	}
}

func TestManagedKeyOutboxCallsSignerOnlyForQueuedOperation(t *testing.T) {
	for _, test := range []struct {
		status  string
		wantErr bool
	}{
		{status: "completed"},
		{status: "failed", wantErr: true},
	} {
		t.Run(test.status, func(t *testing.T) {
			_, stored, message := testDurableManagedKeyCommand()
			stored.Status = test.status
			spy := &managedKeyCustodySpy{}
			handler := &durableOutboxHandler{
				signer: spy,
				loadOperation: func(context.Context, string, string) (store.ManagedKeyOperation, error) {
					return stored, nil
				},
			}
			if test.status == "completed" {
				// Completion is already projected. Even if the signer was removed
				// before an ACK-crash retry, the outbox can safely acknowledge it.
				handler.signer = nil
			}
			handled, err := handler.DeliverLicensed(context.Background(), message)
			if !handled || (err != nil) != test.wantErr {
				t.Fatalf("status=%s handled=%v err=%v wantErr=%v", test.status, handled, err, test.wantErr)
			}
			if spy.calls != 0 {
				t.Fatalf("status=%s reached signer %d times, want zero", test.status, spy.calls)
			}
		})
	}
}

func TestManagedKeyDestructiveResultCannotSubstituteAnotherKey(t *testing.T) {
	for _, action := range []string{"revoke", "zeroize"} {
		t.Run(action, func(t *testing.T) {
			command, stored, message := testDurableManagedKeyCommand()
			command.Action, stored.Action = action, action
			message.Payload, _ = json.Marshal(command)
			spy := &managedKeyCustodySpy{result: signing.ManagedKeyResult{
				Provider: command.Provider, KeyID: "kms-key-attacker-selected",
				Algorithm: crypto.Algorithm(command.Algorithm), PublicDER: []byte("public"), State: action + "d",
			}}
			handler := &durableOutboxHandler{
				signer: spy,
				loadOperation: func(context.Context, string, string) (store.ManagedKeyOperation, error) {
					return stored, nil
				},
			}
			handled, err := handler.DeliverLicensed(context.Background(), message)
			if !handled || err == nil {
				t.Fatalf("mismatched destructive result handled=%v err=%v, want failure", handled, err)
			}
			if spy.calls != 1 {
				t.Fatalf("signer calls=%d, want one call followed by result rejection", spy.calls)
			}
		})
	}
}

func TestManagedKeyTerminalFailureCarriesRequestBinding(t *testing.T) {
	command, _, _ := testDurableManagedKeyCommand()
	payload, err := managedKeyTerminalFailurePayload(command)
	if err != nil {
		t.Fatal(err)
	}
	var failure projections.ManagedKeyCommandFailed
	if err := json.Unmarshal(payload, &failure); err != nil {
		t.Fatal(err)
	}
	if failure.OperationID != command.OperationID || failure.RequestBinding != command.RequestBinding || failure.Error == "" {
		t.Fatalf("terminal failure lost durable identity: %+v", failure)
	}
}

func TestManagedKeyDurableBindingSurvivesHTTPRecorderGC(t *testing.T) {
	const (
		tenantID       = "11111111-1111-1111-1111-111111111111"
		rawKey         = "raw-key-whose-http-cache-was-collected"
		keyID          = "kms-key-1"
		originalDigest = "7de7890fd3d4a5d98398c6c3c5af8c08e07fc174e7e1f071f9f5496c097e47d0"
		changedCaller  = "4f54e11d8ed110e6f4e92510a5194ce2bb03b90b94d1f81ae958de7e0b99b773"
	)
	operationID, err := durableOperationID(tenantID, rawKey)
	if err != nil {
		t.Fatal(err)
	}
	operation := store.ManagedKeyOperation{
		TenantID: tenantID, OperationID: operationID, Provider: "aws-kms", Action: "revoke",
		KeyID: keyID, Algorithm: string(crypto.RSA2048), RequestBinding: originalDigest,
		Status: "completed", ResultKeyID: keyID, ResultState: "revoked",
	}
	approval := &managedKeyApprovalSpy{}
	keyLoads := 0
	service := &durableService{
		provider: "aws-kms", gate: approval,
		loadOperation: func(context.Context, string, string) (store.ManagedKeyOperation, error) {
			return operation, nil
		},
		loadKey: func(_ context.Context, _, _, requestedKey string) (store.ManagedKey, error) {
			keyLoads++
			if requestedKey != keyID {
				return store.ManagedKey{}, errors.New("unexpected key lookup")
			}
			return store.ManagedKey{
				TenantID: tenantID, Provider: "aws-kms", KeyID: keyID,
				Algorithm: string(crypto.RSA2048), Version: 1, State: "revoked", PublicDER: []byte("public"),
			}, nil
		},
	}

	if _, err := service.Revoke(context.Background(), tenantID, keyID, "different-caller", rawKey, changedCaller); !errors.Is(err, orchestrator.ErrIdempotencyConflict) {
		t.Fatalf("new-recorder changed caller error=%v, want ErrIdempotencyConflict", err)
	}
	if approval.calls != 0 || keyLoads != 0 {
		t.Fatalf("changed caller touched approval/key state: approvals=%d key-loads=%d", approval.calls, keyLoads)
	}

	replay, err := service.Revoke(context.Background(), tenantID, keyID, "original-caller", rawKey, originalDigest)
	if err != nil {
		t.Fatalf("new-recorder exact replay: %v", err)
	}
	if replay.KeyID != keyID || replay.State != "revoked" || approval.calls != 0 || keyLoads != 1 {
		t.Fatalf("exact durable replay result=%+v approvals=%d key-loads=%d", replay, approval.calls, keyLoads)
	}
}
