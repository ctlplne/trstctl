// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reprotect

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"trstctl.com/trstctl/ee/decommission/depstate"
	"trstctl.com/trstctl/internal/orchestrator"
)

// Guard for VDEC-claim-3.
func TestRevokeFirst_FailClosedPermitsReprotectDecrypt(t *testing.T) {
	guard := NewFailClosedKeyGuard()
	activeProtective := KeyUseRequest{TenantID: "tenant-a", KeyID: "key://tenant-a/root", Use: KeyUseEncrypt}
	if err := guard.Authorize(activeProtective); err != nil {
		t.Fatalf("active key protective use denied: %v", err)
	}
	if err := guard.MarkFailClosed(FailClosedStateChange{
		TenantID: "tenant-a",
		KeyID:    "key://tenant-a/root",
		JobID:    "job-reprotect-1",
		State:    RevocationStateFailClosed,
	}); err != nil {
		t.Fatalf("MarkFailClosed: %v", err)
	}

	for _, use := range []KeyUse{KeyUseEncrypt, KeyUseSign, KeyUseWrap} {
		err := guard.Authorize(KeyUseRequest{TenantID: "tenant-a", KeyID: "key://tenant-a/root", Use: use})
		if !errors.Is(err, ErrFailClosedProtectiveUse) {
			t.Fatalf("fail-closed %s err = %v, want ErrFailClosedProtectiveUse", use, err)
		}
	}
	err := guard.Authorize(KeyUseRequest{TenantID: "tenant-a", KeyID: "key://tenant-a/root", Use: KeyUseDecrypt})
	if !errors.Is(err, ErrReprotectJobIdentityRequired) {
		t.Fatalf("fail-closed general decrypt err = %v, want ErrReprotectJobIdentityRequired", err)
	}
	if err := guard.Authorize(KeyUseRequest{
		TenantID:       "tenant-a",
		KeyID:          "key://tenant-a/root",
		Use:            KeyUseDecrypt,
		ReprotectJobID: "job-reprotect-1",
	}); err != nil {
		t.Fatalf("re-protection decrypt denied: %v", err)
	}
}

func TestRevokeFirst_IntentsSameTxnAsStateChange(t *testing.T) {
	ctx := context.Background()
	req := revokeFirstTestRequest()
	store := newMemoryRevocationStore()
	coordinator, err := NewRevokeFirstCoordinator(store)
	if err != nil {
		t.Fatalf("NewRevokeFirstCoordinator: %v", err)
	}

	store.failBeforeCommit = errors.New("injected failure before commit")
	if _, err := coordinator.RevokeFirst(ctx, req); !errors.Is(err, store.failBeforeCommit) {
		t.Fatalf("RevokeFirst injected err = %v, want %v", err, store.failBeforeCommit)
	}
	if got := len(store.states); got != 0 {
		t.Fatalf("committed fail-closed states after failed txn = %d, want 0", got)
	}
	if got := len(store.intents); got != 0 {
		t.Fatalf("committed revocation intents after failed txn = %d, want 0", got)
	}
	if got, want := len(store.lastPendingStates), 1; got != want {
		t.Fatalf("pending state changes before injected failure = %d, want %d", got, want)
	}
	if got, want := len(store.lastPendingIntents), len(req.Destinations); got != want {
		t.Fatalf("pending intents before injected failure = %d, want %d", got, want)
	}

	store.failBeforeCommit = nil
	res, err := coordinator.RevokeFirst(ctx, req)
	if err != nil {
		t.Fatalf("RevokeFirst: %v", err)
	}
	if got := len(store.states); got != 1 {
		t.Fatalf("committed fail-closed states = %d, want 1", got)
	}
	if got, want := len(store.intents), len(req.Destinations); got != want {
		t.Fatalf("committed revocation intents = %d, want %d", got, want)
	}
	if res.StateChange.State != RevocationStateFailClosed {
		t.Fatalf("state change = %#v, want fail-closed", res.StateChange)
	}
	if got, want := len(res.Intents), len(req.Destinations); got != want {
		t.Fatalf("result intents = %d, want %d", got, want)
	}
	seenKeys := map[string]struct{}{}
	for i, intent := range res.Intents {
		if intent.TenantID != req.TenantID {
			t.Fatalf("intent %d tenant = %q, want %q", i, intent.TenantID, req.TenantID)
		}
		if intent.Destination == "" || intent.IdempotencyKey == "" || len(intent.Payload) == 0 {
			t.Fatalf("intent %d incomplete: %#v", i, intent)
		}
		if _, ok := seenKeys[intent.IdempotencyKey]; ok {
			t.Fatalf("duplicate revocation intent idempotency key: %s", intent.IdempotencyKey)
		}
		seenKeys[intent.IdempotencyKey] = struct{}{}
	}
}

func TestRevokeFirst_PerDestinationCompletionRequired(t *testing.T) {
	ctx := context.Background()
	req := revokeFirstTestRequest()
	sink := &recordingRevocationCompletionSink{}
	recorder := NewRevocationCompletionRecorder(sink)

	for i := 0; i < len(req.Destinations)-1; i++ {
		res, err := recorder.RecordDestinationCompletion(ctx, req, req.Destinations[i])
		if err != nil {
			t.Fatalf("RecordDestinationCompletion %d: %v", i, err)
		}
		if !res.Recorded {
			t.Fatalf("RecordDestinationCompletion %d did not append first delivery", i)
		}
	}
	status, err := EvaluateRevocationCompletionRequirement(req, sink.events)
	if err != nil {
		t.Fatalf("EvaluateRevocationCompletionRequirement partial: %v", err)
	}
	if status.Satisfied {
		t.Fatalf("completion requirement satisfied with missing destination: %#v", status)
	}
	if !errors.Is(status.MissingError, ErrRevocationCompletionMissing) {
		t.Fatalf("missing error = %v, want ErrRevocationCompletionMissing", status.MissingError)
	}
	if !reflect.DeepEqual(status.Missing, []string{"peer-cache"}) {
		t.Fatalf("missing destinations = %#v, want peer-cache", status.Missing)
	}
	if err := RequireRevocationCompletions(req, sink.events); !errors.Is(err, ErrRevocationCompletionMissing) {
		t.Fatalf("RequireRevocationCompletions partial err = %v, want ErrRevocationCompletionMissing", err)
	}

	res, err := recorder.RecordDestinationCompletion(ctx, req, req.Destinations[len(req.Destinations)-1])
	if err != nil {
		t.Fatalf("RecordDestinationCompletion final: %v", err)
	}
	if !res.Recorded {
		t.Fatal("final destination completion was not recorded")
	}
	status, err = EvaluateRevocationCompletionRequirement(req, sink.events)
	if err != nil {
		t.Fatalf("EvaluateRevocationCompletionRequirement final: %v", err)
	}
	if !status.Satisfied || len(status.Missing) != 0 {
		t.Fatalf("completion requirement = %#v, want satisfied", status)
	}
	if err := RequireRevocationCompletions(req, sink.events); err != nil {
		t.Fatalf("RequireRevocationCompletions final: %v", err)
	}
	redelivery, err := recorder.RecordDestinationCompletion(ctx, req, req.Destinations[0])
	if err != nil {
		t.Fatalf("RecordDestinationCompletion redelivery: %v", err)
	}
	if redelivery.Recorded {
		t.Fatal("redelivery recorded a duplicate revocation completion")
	}
	if got, want := len(sink.events), len(req.Destinations); got != want {
		t.Fatalf("completion events after redelivery = %d, want %d", got, want)
	}
}

func revokeFirstTestRequest() RevokeFirstRequest {
	return RevokeFirstRequest{
		TenantID:  "tenant-a",
		KeyID:     "key://tenant-a/root",
		JobID:     "job-revoke-first-1",
		Reason:    "verifiable decommission",
		Dependent: depstate.Dependent{Class: depstate.DependentCredential, ID: "credential:serial-99"},
		Destinations: []RevocationDestination{
			{ID: "crl", OutboxDestination: "revocation.publish.crl", Kind: "crl"},
			{ID: "ocsp", OutboxDestination: "revocation.publish.ocsp", Kind: "ocsp"},
			{ID: "peer-cache", OutboxDestination: "revocation.invalidate.peer", Kind: "cache"},
		},
	}
}

type memoryRevocationStore struct {
	failBeforeCommit   error
	states             []FailClosedStateChange
	intents            []orchestrator.Entry
	lastPendingStates  []FailClosedStateChange
	lastPendingIntents []orchestrator.Entry
}

func newMemoryRevocationStore() *memoryRevocationStore {
	return &memoryRevocationStore{}
}

func (s *memoryRevocationStore) WithinRevocationTx(ctx context.Context, tenantID string, fn func(context.Context, RevocationTransaction) error) error {
	tx := &memoryRevocationTx{}
	if err := fn(ctx, tx); err != nil {
		return err
	}
	s.lastPendingStates = append([]FailClosedStateChange(nil), tx.states...)
	s.lastPendingIntents = append([]orchestrator.Entry(nil), tx.intents...)
	if s.failBeforeCommit != nil {
		return s.failBeforeCommit
	}
	s.states = append(s.states, tx.states...)
	s.intents = append(s.intents, tx.intents...)
	return nil
}

type memoryRevocationTx struct {
	states  []FailClosedStateChange
	intents []orchestrator.Entry
}

func (tx *memoryRevocationTx) MarkKeyFailClosed(_ context.Context, change FailClosedStateChange) error {
	tx.states = append(tx.states, change)
	return nil
}

func (tx *memoryRevocationTx) EnqueueRevocationIntent(_ context.Context, entry orchestrator.Entry) error {
	tx.intents = append(tx.intents, entry)
	return nil
}

type recordingRevocationCompletionSink struct {
	events []depstate.RevocationCompletedV1
}

func (s *recordingRevocationCompletionSink) AppendRevocationCompleted(_ context.Context, event depstate.RevocationCompletedV1) error {
	s.events = append(s.events, event)
	return nil
}
