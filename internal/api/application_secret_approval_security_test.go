// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	configpkg "trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type recordedApplicationSecretMACInput struct {
	domain   []byte
	material []byte
}

func applicationSecretMACAPI(t *testing.T) (*API, *[]recordedApplicationSecretMACInput) {
	t.Helper()
	serverKey := bytes.Repeat([]byte{0x7d}, 32)
	inputs := []recordedApplicationSecretMACInput{}
	return &API{secrets: &secretsService{be: SecretsBackend{
		CommandMAC: func(domain, material []byte) ([]byte, error) {
			inputs = append(inputs, recordedApplicationSecretMACInput{
				domain: append([]byte(nil), domain...), material: append([]byte(nil), material...),
			})
			input := make([]byte, 0, len(domain)+1+len(material))
			input = append(input, domain...)
			input = append(input, 0)
			input = append(input, material...)
			return crypto.HMACSHA256(serverKey, input), nil
		},
	}}}, &inputs
}

func TestApplicationSecretServerMACIsTenantBoundAndNotCallerKeyed(t *testing.T) {
	a, macInputs := applicationSecretMACAPI(t)
	const (
		tenantA = "11111111-1111-1111-1111-111111111111"
		tenantB = "22222222-2222-2222-2222-222222222222"
		idem    = "7"
	)
	req := secretWriteRequest{Name: "db/password", Value: secretJSONBytes("x")}
	defer req.Value.wipe()

	keyDigestA, bindingA, err := a.applicationSecretRequestBinding(
		tenantA, idem, "alice", "PUT", "/api/v1/secrets/store/db/password",
		"rotate", "native", "db/password", req)
	if err != nil {
		t.Fatal(err)
	}
	keyDigestReplay, bindingReplay, err := a.applicationSecretRequestBinding(
		tenantA, idem, "alice", "PUT", "/api/v1/secrets/store/db/password",
		"rotate", "native", "db/password", req)
	if err != nil {
		t.Fatal(err)
	}
	_, bindingB, err := a.applicationSecretRequestBinding(
		tenantB, idem, "alice", "PUT", "/api/v1/secrets/store/db/password",
		"rotate", "native", "db/password", req)
	if err != nil {
		t.Fatal(err)
	}
	if keyDigestA != keyDigestReplay || bindingA != bindingReplay {
		t.Fatal("exact request retry did not reproduce its stable server-keyed binding")
	}
	if bindingA == bindingB {
		t.Fatal("identical low-entropy input produced the same request binding across tenants")
	}

	command := canonicalApplicationSecretCommand{
		Domain: "trstctl.api.application-secret-command.v2", Action: "rotate",
		Name: "db/password", Surface: "native", ExpectedVersion: 1,
		ResultVersion: 2, Value: []byte("x"),
	}
	_, evidenceA, err := a.applicationSecretCommandEvidence(tenantA, idem, command)
	if err != nil {
		t.Fatal(err)
	}
	_, evidenceReplay, err := a.applicationSecretCommandEvidence(tenantA, idem, command)
	if err != nil {
		t.Fatal(err)
	}
	_, evidenceB, err := a.applicationSecretCommandEvidence(tenantB, idem, command)
	if err != nil {
		t.Fatal(err)
	}
	if evidenceA != evidenceReplay {
		t.Fatal("exact command retry did not reproduce its stable server-keyed evidence")
	}
	if evidenceA == evidenceB {
		t.Fatal("identical low-entropy command produced the same evidence across tenants")
	}

	// The pre-remediation construction used the caller-controlled raw key as the
	// HMAC key. Even with every low-entropy input known, that offline oracle must
	// not reproduce either persisted server-keyed value.
	for i, input := range *macInputs {
		combined := append(append(append([]byte(nil), input.domain...), 0), input.material...)
		for _, legacyInput := range [][]byte{input.material, combined} {
			legacyHex := hex.EncodeToString(crypto.HMACSHA256([]byte(idem), legacyInput))
			if bindingA == legacyHex || evidenceA == legacyHex {
				t.Fatalf("persisted application-secret evidence is reproducible from the caller key (MAC input %d)", i)
			}
		}
	}
}

func TestApplicationSecretMutationEventIDBindsTenantLifecycleEpoch(t *testing.T) {
	const (
		tenant    = "11111111-1111-1111-1111-111111111111"
		name      = "db/password"
		action    = "rotate"
		keyDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	)
	first := applicationSecretMutationEventID(tenant, "11111111-aaaa-4aaa-8aaa-111111111111", name, action, keyDigest)
	replay := applicationSecretMutationEventID(tenant, "11111111-aaaa-4aaa-8aaa-111111111111", name, action, keyDigest)
	reregistered := applicationSecretMutationEventID(tenant, "22222222-bbbb-4bbb-8bbb-222222222222", name, action, keyDigest)
	if first != replay {
		t.Fatal("same tenant lifecycle epoch did not reproduce its deterministic event id")
	}
	if first == reregistered {
		t.Fatal("offboard/re-registration lifecycle reused an old application-secret event id")
	}
}

func applicationSecretRecoveryEvent(
	t *testing.T,
	payload projections.ApplicationSecretMutation,
) events.Event {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return events.Event{
		ID: "77900000-0000-4000-8000-000000000001", Type: projections.EventApplicationSecretRotated,
		TenantID:      "11111111-1111-1111-1111-111111111111",
		Time:          time.Date(2026, 8, 10, 18, 0, 0, 0, time.UTC),
		SchemaVersion: projections.ApplicationSecretMutationSchemaVersion, Data: raw,
	}
}

func applicationSecretRecoveryPayload(requester string) projections.ApplicationSecretMutation {
	return projections.ApplicationSecretMutation{
		TenantEpoch: "11111111-aaaa-4aaa-8aaa-111111111111",
		Action:      "rotate", Name: "durable/window", ExpectedVersion: 1, ResultVersion: 2,
		Sealed: []byte("sealed-canonical-v2"), IdempotencyKeyDigest: string(bytes.Repeat([]byte{'1'}, 64)),
		RequestBinding: string(bytes.Repeat([]byte{'2'}, 64)), CommandEvidence: string(bytes.Repeat([]byte{'3'}, 64)),
		Surface: "native", Approval: &store.OperationApprovalUse{
			RequestID: "77900000-0000-4000-8000-000000000011", IntentDigest: "sha256:durable-window",
			Requester: requester, ResourceKind: "secret", ResourceID: "secret:durable/window",
			Action: "rotate", FromState: "version:1",
			ToState:       "version:2:command-hmac-sha256:" + string(bytes.Repeat([]byte{'3'}, 64)),
			TargetVersion: 1, RequiredApprovals: 1,
		},
	}
}

func openApplicationSecretRecoveryLog(t *testing.T) *events.Log {
	t.Helper()
	log, err := events.Open(context.Background(), configpkg.NATS{
		Mode: configpkg.NATSEmbedded, StoreDir: t.TempDir(),
	}, events.WithDuplicateWindowForTesting(100*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log
}

func applicationSecretRecoveryEventCount(t *testing.T, log *events.Log) int {
	t.Helper()
	count := 0
	if err := log.Replay(context.Background(), 0, func(events.Event) error {
		count++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestApplicationSecretFreshCommandAppendsCanonicalEventWithoutRecoveryReplay(t *testing.T) {
	ctx := context.Background()
	log := openApplicationSecretRecoveryLog(t)
	payload := applicationSecretRecoveryPayload("alice")
	candidate := applicationSecretRecoveryEvent(t, payload)
	candidate.Actor = &events.Actor{Subject: "alice", Roles: []string{"operator"}}

	canonical, gotPayload, err := recoverOrAppendApplicationSecretMutationEvent(
		ctx, log, candidate, payload, false)
	if err != nil {
		t.Fatalf("append fresh application-secret command: %v", err)
	}
	if canonical.ID != candidate.ID || canonical.Sequence == 0 || gotPayload.Name != payload.Name {
		t.Fatalf("fresh canonical event = %+v payload=%+v", canonical, gotPayload)
	}
	if count := applicationSecretRecoveryEventCount(t, log); count != 1 {
		t.Fatalf("fresh command published %d physical events, want one", count)
	}
}

func TestApplicationSecretAppendRecoveryUsesRetainedEnvelopeBeyondBrokerDuplicateWindow(t *testing.T) {
	ctx := context.Background()
	log := openApplicationSecretRecoveryLog(t)
	originalPayload := applicationSecretRecoveryPayload("alice")
	original := applicationSecretRecoveryEvent(t, originalPayload)
	first, err := log.Append(ctx, original)
	if err != nil {
		t.Fatal(err)
	}

	// Cross the real finite JetStream message-ID memory. A blind Append here would
	// publish a second physical event even though the durable command ID is equal.
	time.Sleep(400 * time.Millisecond)
	retryPayload := applicationSecretRecoveryPayload("erased:0123456789abcdef")
	retry := applicationSecretRecoveryEvent(t, retryPayload)
	canonical, gotPayload, err := recoverOrAppendApplicationSecretMutationEvent(ctx, log, retry, retryPayload, true)
	if err != nil {
		t.Fatalf("recover retained application-secret event: %v", err)
	}
	if canonical.Sequence != first.Sequence || gotPayload.Approval == nil || gotPayload.Approval.Requester != "alice" {
		t.Fatalf("retained canonical event was not reused: event=%+v payload=%+v", canonical, gotPayload)
	}
	if count := applicationSecretRecoveryEventCount(t, log); count != 1 {
		t.Fatalf("post-window recovery published %d physical events, want exactly one", count)
	}
}

func TestApplicationSecretBackgroundRecoveryReusesRetainedRequestActor(t *testing.T) {
	ctx := context.Background()
	log := openApplicationSecretRecoveryLog(t)
	payload := applicationSecretRecoveryPayload("alice")
	original := applicationSecretRecoveryEvent(t, payload)
	original.Actor = &events.Actor{Subject: "alice", Roles: []string{"operator"}}
	first, err := log.Append(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	backgroundCandidate := applicationSecretRecoveryEvent(t, payload)
	canonical, _, err := recoverOrAppendApplicationSecretMutationEvent(
		ctx, log, backgroundCandidate, payload, true)
	if err != nil {
		t.Fatalf("background retained recovery rejected request actor: %v", err)
	}
	if canonical.Sequence != first.Sequence || canonical.Actor == nil || canonical.Actor.Subject != "alice" {
		t.Fatalf("background recovery did not reuse retained actor: %+v", canonical)
	}
	if count := applicationSecretRecoveryEventCount(t, log); count != 1 {
		t.Fatalf("background recovery published %d physical events, want one", count)
	}
}

func TestApplicationSecretRetainedPrivacyActorOrderRecoversWithoutWeakeningRoleBinding(t *testing.T) {
	ctx := context.Background()
	log := openApplicationSecretRecoveryLog(t)
	placeholder := privacy.Placeholder(privacy.SubjectRef(
		"11111111-1111-1111-1111-111111111111", "alice",
	))
	payload := applicationSecretRecoveryPayload(placeholder)
	retained := applicationSecretRecoveryEvent(t, payload)
	retained.Actor = &events.Actor{
		Subject: "release-controller",
		Roles:   []string{placeholder, "bob", placeholder},
	}
	first, err := log.Append(ctx, retained)
	if err != nil {
		t.Fatal(err)
	}

	candidate := applicationSecretRecoveryEvent(t, payload)
	candidate.Actor = &events.Actor{
		Subject: retained.Actor.Subject,
		Roles:   []string{"bob", placeholder, placeholder},
	}
	canonical, _, err := recoverOrAppendApplicationSecretMutationEvent(ctx, log, candidate, payload, true)
	if err != nil || canonical.Sequence != first.Sequence {
		t.Fatalf("sorted fence did not recover the order-preserving privacy event: event=%+v err=%v", canonical, err)
	}
	if count := applicationSecretRecoveryEventCount(t, log); count != 1 {
		t.Fatalf("role-order recovery published %d physical events, want one", count)
	}

	changed := candidate
	changed.Actor = &events.Actor{
		Subject: candidate.Actor.Subject,
		Roles:   []string{"admin", placeholder, placeholder},
	}
	if _, _, err := recoverOrAppendApplicationSecretMutationEvent(ctx, log, changed, payload, true); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed retained role authority error=%v, want ErrIdempotencyConflict", err)
	}
}

func TestApplicationSecretLegacyActorlessRecoveryWithoutRetainedEventFailsClosed(t *testing.T) {
	ctx := context.Background()
	log := openApplicationSecretRecoveryLog(t)
	payload := applicationSecretRecoveryPayload("alice")
	actorless := applicationSecretRecoveryEvent(t, payload)
	actorless.Actor = nil
	if _, _, err := recoverOrAppendApplicationSecretMutationEvent(
		ctx, log, actorless, payload, true); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("actorless legacy recovery error=%v, want ErrIdempotencyConflict", err)
	}
	if count := applicationSecretRecoveryEventCount(t, log); count != 0 {
		t.Fatalf("actorless legacy recovery published %d event(s), want zero", count)
	}
}

func TestApplicationSecretAuthenticatedLiveRetryCannotManufactureLegacyActor(t *testing.T) {
	ctx := events.ContextWithActor(context.Background(), events.Actor{
		Subject: "live-alice", Roles: []string{"operator"},
	})
	log := openApplicationSecretRecoveryLog(t)
	payload := applicationSecretRecoveryPayload("live-alice")
	event := applicationSecretRecoveryEvent(t, payload)
	a := &API{secrets: &secretsService{be: SecretsBackend{EventLog: log}}}
	fence := store.ApplicationSecretMutationFence{
		TenantID: event.TenantID, Name: payload.Name, Operation: payload.Action,
		EventID: event.ID, EventType: event.Type, EventTime: event.Time,
		SchemaVersion: event.SchemaVersion, Actor: nil,
	}
	if _, _, err := a.appendAndProjectApplicationSecretMutationUnbarriered(
		ctx, event.TenantID, fence, payload, true); !errors.Is(err, errApplicationSecretLegacyActorUnavailable) ||
		!errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("authenticated actorless legacy retry error=%v, want bounded idempotency conflict", err)
	}
	if count := applicationSecretRecoveryEventCount(t, log); count != 0 {
		t.Fatalf("authenticated legacy retry published %d event(s), want zero", count)
	}
}

func TestApplicationSecretActorRoleSetIsCanonical(t *testing.T) {
	ctx := events.ContextWithActor(context.Background(), events.Actor{
		Subject: "alice", Roles: []string{"operator", "auditor", "operator", ""},
	})
	got := applicationSecretActorFromContext(ctx)
	want := &events.Actor{Subject: "alice", Roles: []string{"auditor", "operator"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("canonical application-secret actor=%+v, want %+v", got, want)
	}
	empty := applicationSecretActorFromContext(events.ContextWithActor(
		context.Background(), events.Actor{Subject: "system", Roles: []string{}}))
	if empty == nil || empty.Roles != nil {
		t.Fatalf("empty role set was not normalized to nil: %+v", empty)
	}
}

func TestApplicationSecretRecoveryActorComparisonAllowsOnlyRoleOrdering(t *testing.T) {
	placeholder := privacy.Placeholder(privacy.SubjectRef("tenant-a", "alice"))
	retained := &events.Actor{
		Subject: "release-controller",
		Roles:   []string{placeholder, "bob", placeholder},
	}
	fence := &events.Actor{
		Subject: "release-controller",
		Roles:   []string{"bob", placeholder, placeholder},
	}
	if !applicationSecretRecoveryActorsEqual(retained, fence) {
		t.Fatal("privacy-rewritten retained actor order did not converge with the sorted fence")
	}
	if !applicationSecretRecoveryActorsEqual(
		&events.Actor{Subject: "system", Roles: nil},
		&events.Actor{Subject: "system", Roles: []string{}},
	) {
		t.Fatal("equivalent empty actor-role encodings did not converge")
	}
	for name, changed := range map[string]*events.Actor{
		"subject": {Subject: "other-controller", Roles: append([]string(nil), fence.Roles...)},
		"role":    {Subject: fence.Subject, Roles: []string{"admin", placeholder, placeholder}},
		"count":   {Subject: fence.Subject, Roles: []string{"bob", placeholder}},
	} {
		t.Run(name, func(t *testing.T) {
			if applicationSecretRecoveryActorsEqual(retained, changed) {
				t.Fatalf("changed %s actor was treated as an ordering-only rewrite", name)
			}
		})
	}
}

func TestApplicationSecretAppendRecoveryRejectsRetainedEnvelopeDrift(t *testing.T) {
	tests := []struct {
		name   string
		poison func(events.Event, projections.ApplicationSecretMutation) (events.Event, projections.ApplicationSecretMutation)
	}{
		{name: "event time", poison: func(event events.Event, payload projections.ApplicationSecretMutation) (events.Event, projections.ApplicationSecretMutation) {
			event.Time = event.Time.Add(time.Second)
			return event, payload
		}},
		{name: "actor", poison: func(event events.Event, payload projections.ApplicationSecretMutation) (events.Event, projections.ApplicationSecretMutation) {
			event.Actor = &events.Actor{Subject: "mallory"}
			return event, payload
		}},
		{name: "sealed command", poison: func(event events.Event, payload projections.ApplicationSecretMutation) (events.Event, projections.ApplicationSecretMutation) {
			payload.Sealed = []byte("sealed-poison-v2")
			return event, payload
		}},
		{name: "approval capability", poison: func(event events.Event, payload projections.ApplicationSecretMutation) (events.Event, projections.ApplicationSecretMutation) {
			payload.Approval.TargetVersion = 99
			return event, payload
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			log := openApplicationSecretRecoveryLog(t)
			attemptPayload := applicationSecretRecoveryPayload("alice")
			attempt := applicationSecretRecoveryEvent(t, attemptPayload)
			attempt.Actor = &events.Actor{Subject: "alice", Roles: []string{"operator"}}
			_, poisonPayload := tc.poison(attempt, applicationSecretRecoveryPayload("alice"))
			poisonEvent := applicationSecretRecoveryEvent(t, poisonPayload)
			poisonEvent.Actor = &events.Actor{Subject: "alice", Roles: []string{"operator"}}
			if tc.name == "event time" {
				poisonEvent.Time = attempt.Time.Add(time.Second)
			}
			if tc.name == "actor" {
				poisonEvent.Actor = &events.Actor{Subject: "mallory"}
			}
			if _, err := log.Append(ctx, poisonEvent); err != nil {
				t.Fatal(err)
			}
			if _, _, err := recoverOrAppendApplicationSecretMutationEvent(ctx, log, attempt, attemptPayload, true); !errors.Is(err, store.ErrIdempotencyConflict) {
				t.Fatalf("retained drift error = %v, want ErrIdempotencyConflict", err)
			}
			if count := applicationSecretRecoveryEventCount(t, log); count != 1 {
				t.Fatalf("drift recovery changed physical event count to %d", count)
			}
		})
	}
}
