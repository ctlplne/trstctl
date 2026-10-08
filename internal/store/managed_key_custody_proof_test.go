// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestManagedKeyCustodyProofProjectionKeepsLifecycleAndTenantBoundary(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for _, tenant := range []string{tenantA, tenantB} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: tenant}); err != nil {
			t.Fatal(err)
		}
	}
	public := []byte("saved-public-key")
	if _, err := s.SystemPool().Exec(ctx,
		`INSERT INTO managed_keys (tenant_id,provider,key_id,algorithm,version,state,public_der,created_at,updated_at)
		 VALUES ($1,'aws-kms','owned-key','RSA-2048',1,'active',$2,now(),now())`, tenantA, public); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-time.Minute)
	project := func(id, kind string, at time.Time, payload any) {
		t.Helper()
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if err := projections.New(s).Apply(ctx, events.Event{ID: id, TenantID: tenantA, Type: kind, Time: at, Data: body}); err != nil {
			t.Fatal(err)
		}
	}
	read := func(want string) {
		t.Helper()
		key, err := s.GetManagedKey(ctx, tenantA, "aws-kms", "owned-key")
		if err != nil || key.CustodyStatus != want || key.State != "active" {
			t.Fatalf("custody=%q lifecycle=%q err=%v, want %q/active", key.CustodyStatus, key.State, err, want)
		}
	}
	command := func(n string) projections.ManagedKeyCommand {
		return projections.ManagedKeyCommand{OperationID: "proof-" + n, Provider: "aws-kms", Action: "verify_custody",
			KeyID: "owned-key", Algorithm: "RSA-2048", RequestBinding: "bound-" + n}
	}
	first := command("first")
	project("proof-first-request", projections.EventManagedKeyCommandRequested, base, first)
	read("pending")
	project("proof-first-complete", projections.EventManagedKeyCommandCompleted, base.Add(time.Second),
		projections.ManagedKeyCommandCompleted{ManagedKeyCommand: first, ResultKeyID: first.KeyID, PublicDER: public, State: "verified"})
	read("verified")
	second := command("missing")
	project("proof-missing-request", projections.EventManagedKeyCommandRequested, base.Add(2*time.Second), second)
	read("pending")
	project("proof-missing-failed", projections.EventManagedKeyCommandFailed, base.Add(3*time.Second),
		projections.ManagedKeyCommandFailed{OperationID: second.OperationID, RequestBinding: second.RequestBinding, Error: "retry budget exhausted"})
	read("unavailable")
	third := command("recovered")
	project("proof-recovered-request", projections.EventManagedKeyCommandRequested, base.Add(4*time.Second), third)
	project("proof-recovered-complete", projections.EventManagedKeyCommandCompleted, base.Add(5*time.Second),
		projections.ManagedKeyCommandCompleted{ManagedKeyCommand: third, ResultKeyID: third.KeyID, PublicDER: public, State: "verified"})
	read("verified")
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE managed_keys SET state = 'revoked' WHERE tenant_id = $1 AND provider = 'aws-kms' AND key_id = 'owned-key'`, tenantA); err != nil {
		t.Fatal(err)
	}
	project("proof-recovered-redelivery", projections.EventManagedKeyCommandCompleted, base.Add(6*time.Second),
		projections.ManagedKeyCommandCompleted{ManagedKeyCommand: third, ResultKeyID: third.KeyID, PublicDER: public, State: "verified"})
	afterReplay, err := s.GetManagedKey(ctx, tenantA, "aws-kms", "owned-key")
	if err != nil || afterReplay.State != "revoked" || afterReplay.CustodyStatus != "verified" {
		t.Fatalf("completion redelivery changed later lifecycle: key=%+v err=%v", afterReplay, err)
	}
	if _, err := s.GetManagedKey(ctx, tenantB, "aws-kms", "owned-key"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("other tenant custody read = %v, want no row", err)
	}

	generated := projections.ManagedKeyCommand{OperationID: "generated-proof-key", Provider: "aws-kms", Action: "generate",
		Algorithm: "RSA-2048", RequestBinding: "generated-bound"}
	generatedResult := projections.ManagedKeyCommandCompleted{ManagedKeyCommand: generated,
		ResultKeyID: "new-key", PublicDER: public, State: "active"}
	project("generated-request", projections.EventManagedKeyCommandRequested, base.Add(7*time.Second), generated)
	project("generated-complete", projections.EventManagedKeyCommandCompleted, base.Add(8*time.Second), generatedResult)
	newKey, err := s.GetManagedKey(ctx, tenantA, "aws-kms", "new-key")
	if err != nil || newKey.CustodyStatus != "not_checked" || newKey.CustodyCheckedAt != nil {
		t.Fatalf("generation without challenge claimed a proof: key=%+v err=%v", newKey, err)
	}
	proof := projections.ManagedKeyCommand{OperationID: "proof-new-key", Provider: "aws-kms", Action: "verify_custody",
		KeyID: "new-key", Algorithm: "RSA-2048", RequestBinding: "proof-new-bound"}
	project("new-key-proof-request", projections.EventManagedKeyCommandRequested, base.Add(9*time.Second), proof)
	project("new-key-proof-complete", projections.EventManagedKeyCommandCompleted, base.Add(10*time.Second),
		projections.ManagedKeyCommandCompleted{ManagedKeyCommand: proof, ResultKeyID: "new-key", PublicDER: public, State: "verified"})
	project("generated-complete-redelivery", projections.EventManagedKeyCommandCompleted, base.Add(11*time.Second), generatedResult)
	newKey, err = s.GetManagedKey(ctx, tenantA, "aws-kms", "new-key")
	if err != nil || newKey.CustodyStatus != "verified" {
		t.Fatalf("generation redelivery erased the later signature proof: key=%+v err=%v", newKey, err)
	}
}

func TestManagedKeyFailureV2BindsAuditKeyToDurableOperation(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: tenantA}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`INSERT INTO managed_keys (tenant_id,provider,key_id,algorithm,version,state,public_der,created_at,updated_at)
		 VALUES ($1,'aws-kms','owned-key','RSA-2048',1,'active',$2,now(),now())`, tenantA, []byte("saved-public-key")); err != nil {
		t.Fatal(err)
	}
	command := projections.ManagedKeyCommand{OperationID: "proof-v2", Provider: "aws-kms", Action: "verify_custody",
		KeyID: "owned-key", Algorithm: "RSA-2048", RequestBinding: "bound-v2"}
	apply := func(id, kind string, version int, payload any) error {
		t.Helper()
		body, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		return projections.New(s).Apply(ctx, events.Event{
			ID: id, TenantID: tenantA, Type: kind, SchemaVersion: version,
			Time: time.Now().UTC(), Data: body,
		})
	}
	if err := apply("proof-v2-request", projections.EventManagedKeyCommandRequested, 1, command); err != nil {
		t.Fatal(err)
	}
	failure := projections.ManagedKeyCommandFailed{
		OperationID: command.OperationID, RequestBinding: command.RequestBinding,
		Provider: command.Provider, Action: command.Action, KeyID: "another-key", Error: "retry budget exhausted",
	}
	if err := apply("proof-v2-wrong-key", projections.EventManagedKeyCommandFailed,
		projections.ManagedKeyFailureEventSchemaVersion, failure); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("failure event with foreign key identity = %v, want no matching durable operation", err)
	}
	key, err := s.GetManagedKey(ctx, tenantA, "aws-kms", command.KeyID)
	if err != nil || key.CustodyStatus != "pending" {
		t.Fatalf("foreign failure altered owned key: key=%+v err=%v", key, err)
	}
	failure.KeyID = command.KeyID
	if err := apply("proof-v2-failed", projections.EventManagedKeyCommandFailed,
		projections.ManagedKeyFailureEventSchemaVersion, failure); err != nil {
		t.Fatal(err)
	}
	key, err = s.GetManagedKey(ctx, tenantA, "aws-kms", command.KeyID)
	if err != nil || key.CustodyStatus != "unavailable" || key.State != "active" {
		t.Fatalf("bound failure did not mark point-in-time custody: key=%+v err=%v", key, err)
	}
	generate := projections.ManagedKeyCommand{OperationID: "generate-v2", Provider: "aws-kms", Action: "generate",
		Algorithm: "RSA-2048", RequestBinding: "generate-bound-v2"}
	if err := apply("generate-v2-request", projections.EventManagedKeyCommandRequested, 1, generate); err != nil {
		t.Fatal(err)
	}
	generateFailure := projections.ManagedKeyCommandFailed{OperationID: generate.OperationID,
		RequestBinding: generate.RequestBinding, Provider: generate.Provider, Action: generate.Action,
		Error: "retry budget exhausted"}
	if err := apply("generate-v2-failed", projections.EventManagedKeyCommandFailed,
		projections.ManagedKeyFailureEventSchemaVersion, generateFailure); err != nil {
		t.Fatalf("generation failure without an unminted key ID must project: %v", err)
	}
	op, err := s.GetManagedKeyOperation(ctx, tenantA, generate.OperationID)
	if err != nil || op.Status != "failed" || op.KeyID != "" {
		t.Fatalf("failed generation operation = %+v, err %v", op, err)
	}
}
