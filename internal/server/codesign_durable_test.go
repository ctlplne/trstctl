// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

func TestDurableCodeSigningCrashReplayReturnsSignerJournalResult(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		remote, err := d.Signer.Client().GenerateConstrainedKeyHandle(context.Background(),
			crypto.ECDSAP256, "codesign-crash-replay",
			[]signing.KeyPurpose{signing.PurposeCodeSign}, signing.PurposeCodeSign)
		if err != nil {
			t.Fatalf("generate signer-backed code-signing key: %v", err)
		}
		d.CodeSigning = CodeSigningConfig{
			Keys: codeSigningKeyMap{keys: map[string]crypto.DigestSigner{"release-key": remote}},
		}
	})
	startServedExternalCADispatcher(t, h)
	token := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "release-bot", []string{
		string(authz.KeysRead), string(authz.KeysWrite),
	})
	digest := crypto.SHA256Sum([]byte("crash-window artifact"))

	var (
		mu         sync.Mutex
		signatures [][]byte
	)
	h.srv.codeSign.afterSign = func(_ context.Context, response api.CodeSigningResponse) error {
		mu.Lock()
		defer mu.Unlock()
		signatures = append(signatures, append([]byte(nil), response.Signature...))
		if len(signatures) == 1 {
			return errors.New("injected crash after signer response")
		}
		return nil
	}

	request := map[string]any{
		"key_id": "release-key", "artifact_type": "oci-image", "digest": digest,
	}
	statusCode, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/code-signing/sign",
		token, "codesign-crash-replay", request)
	if statusCode != http.StatusOK {
		t.Fatalf("durable crash replay = %d, want 200; body=%s", statusCode, body)
	}
	mu.Lock()
	if len(signatures) != 2 || !bytes.Equal(signatures[0], signatures[1]) {
		t.Fatalf("signer results across crash = %x, want two byte-identical results", signatures)
	}
	mu.Unlock()

	// An identical HTTP replay returns the byte-identical persisted response.
	replayCode, replayBody := doBearer(t, h.ts, http.MethodPost, "/api/v1/code-signing/sign",
		token, "codesign-crash-replay", request)
	if replayCode != http.StatusOK || !bytes.Equal(replayBody, body) {
		t.Fatalf("HTTP replay = (%d, %s), want exact (%d, %s)", replayCode, replayBody, statusCode, body)
	}

	// The raw header key remains the recorder key. Its cached envelope binds the
	// authenticated principal and canonical command, so changed reuse is rejected
	// before either the durable state machine or signer can run again.
	changed := map[string]any{
		"key_id": "release-key", "artifact_type": "oci-image",
		"digest": crypto.SHA256Sum([]byte("different artifact")),
	}
	changedCode, changedBody := doBearer(t, h.ts, http.MethodPost, "/api/v1/code-signing/sign",
		token, "codesign-crash-replay", changed)
	if changedCode != http.StatusConflict {
		t.Fatalf("same key/different request = %d, want 409; body=%s", changedCode, changedBody)
	}
	changedKey := map[string]any{
		"key_id": "another-release-key", "artifact_type": "oci-image", "digest": digest,
	}
	changedKeyCode, changedKeyBody := doBearer(t, h.ts, http.MethodPost, "/api/v1/code-signing/sign",
		token, "codesign-crash-replay", changedKey)
	if changedKeyCode != http.StatusConflict {
		t.Fatalf("same idempotency key/different signing key = %d, want 409; body=%s", changedKeyCode, changedKeyBody)
	}

	otherToken := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "other-release-bot", []string{
		string(authz.KeysRead), string(authz.KeysWrite),
	})
	changedPrincipalCode, changedPrincipalBody := doBearer(t, h.ts, http.MethodPost, "/api/v1/code-signing/sign",
		otherToken, "codesign-crash-replay", request)
	if changedPrincipalCode != http.StatusConflict {
		t.Fatalf("same key/different principal = %d, want 409; body=%s", changedPrincipalCode, changedPrincipalBody)
	}
}

func TestDurableCodeSigningConcurrentIdenticalBindingSignsOnce(t *testing.T) {
	inner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inner.Destroy)
	signer := &countingOperationSigner{DigestSigner: inner}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.CodeSigning = CodeSigningConfig{
			Keys: codeSigningKeyMap{keys: map[string]crypto.DigestSigner{"release-key": signer}},
		}
	})
	startServedExternalCADispatcher(t, h)
	token := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "release-bot", []string{
		string(authz.KeysRead), string(authz.KeysWrite),
	})
	digest := crypto.SHA256Sum([]byte("concurrent code-signing artifact"))
	payload, err := json.Marshal(map[string]any{
		"key_id": "release-key", "artifact_type": "oci-image", "digest": digest,
	})
	if err != nil {
		t.Fatal(err)
	}

	type result struct {
		status int
		body   []byte
		err    error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			request, requestErr := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/code-signing/sign", bytes.NewReader(payload))
			if requestErr != nil {
				results <- result{err: requestErr}
				return
			}
			request.Header.Set("Authorization", "Bearer "+token)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "codesign-concurrent-bound")
			response, requestErr := h.ts.Client().Do(request)
			if requestErr != nil {
				results <- result{err: requestErr}
				return
			}
			body, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			results <- result{status: response.StatusCode, body: body, err: readErr}
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	var first []byte
	for got := range results {
		if got.err != nil || got.status != http.StatusOK {
			t.Fatalf("concurrent code-sign result status=%d err=%v body=%s", got.status, got.err, got.body)
		}
		if first == nil {
			first = got.body
		} else if !bytes.Equal(first, got.body) {
			t.Fatalf("concurrent identical replay returned different bodies: %s != %s", first, got.body)
		}
	}
	if calls := signer.calls.Load(); calls != 1 {
		t.Fatalf("concurrent identical replay invoked signer %d times, want exactly one", calls)
	}
}

func TestCodeSigningRequestDoesNotDispatchSignerOrUnrelatedRows(t *testing.T) {
	inner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate fixture signer: %v", err)
	}
	t.Cleanup(inner.Destroy)
	signer := &countingOperationSigner{DigestSigner: inner}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.CodeSigning = CodeSigningConfig{
			Keys: codeSigningKeyMap{keys: map[string]crypto.DigestSigner{"release-key": signer}},
		}
	})

	var unrelatedID int64
	if err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		var enqueueErr error
		unrelatedID, enqueueErr = h.srv.outbox.Enqueue(context.Background(), tx, orchestrator.Entry{
			TenantID: h.tenant, Destination: "notification.unrelated",
			IdempotencyKey: "unrelated-row", Payload: []byte(`{"kind":"unrelated"}`),
		})
		return enqueueErr
	}); err != nil {
		t.Fatalf("enqueue unrelated row: %v", err)
	}

	requestCtx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err = h.srv.codeSign.SignCode(requestCtx, h.tenant, "codesign-no-inline-dispatch", api.CodeSigningRequest{
		Principal: "release-bot", KeyID: "release-key", ArtifactType: "blob",
		Digest: crypto.SHA256Sum([]byte("queued only")),
	})
	if err == nil || (!strings.Contains(err.Error(), "pending") && !errors.Is(err, context.DeadlineExceeded)) {
		t.Fatalf("request without worker error = %v, want pending/deadline", err)
	}
	if got := signer.calls.Load(); got != 0 {
		t.Fatalf("request goroutine invoked signer %d times; only outbox worker may sign", got)
	}
	row, err := h.srv.outbox.Get(context.Background(), h.tenant, unrelatedID)
	if err != nil {
		t.Fatalf("load unrelated outbox row: %v", err)
	}
	if row.Status != "pending" || row.Attempts != 0 {
		t.Fatalf("request dispatched unrelated row: %+v", row)
	}
}

func TestCodeSigningRetryAfterAppendBeforeProjectionUsesCanonicalEvent(t *testing.T) {
	inner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate fixture signer: %v", err)
	}
	t.Cleanup(inner.Destroy)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.CodeSigning = CodeSigningConfig{
			Keys: codeSigningKeyMap{keys: map[string]crypto.DigestSigner{
				"release-key": &countingOperationSigner{DigestSigner: inner},
			}},
		}
	})
	const idempotencyKey = "codesign-append-project-crash"
	command := codeSigningCommand{
		Mode: "key", Principal: "release-bot", KeyID: "release-key",
		ArtifactType: "blob", Digest: crypto.SHA256Sum([]byte("append then crash")),
	}
	plain, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(plain)
	requestHash := crypto.SHA256Hex(plain)
	operationID := codeSigningOperationID(h.tenant, idempotencyKey)
	canonicalCiphertext, err := seal.Seal(h.srv.codeSign.kek, plain,
		codeSigningCommandAAD(h.tenant, operationID, command.Mode, requestHash))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(canonicalCiphertext)
	eventPayload, err := json.Marshal(projections.CodeSigningCommanded{
		OperationID: operationID, IdempotencyKey: idempotencyKey, Mode: command.Mode,
		RequestHash: requestHash, SealedCommand: canonicalCiphertext,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a process death after JetStream ACK: append succeeds, but the
	// relational projector never sees this returned event.
	if _, err := h.log.Append(context.Background(), events.Event{
		ID:   codeSigningEventID(h.tenant, projections.EventCodeSigningCommanded, operationID),
		Type: projections.EventCodeSigningCommanded, TenantID: h.tenant, Data: eventPayload,
	}); err != nil {
		t.Fatalf("append command before simulated crash: %v", err)
	}

	requestCtx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err = h.srv.codeSign.SignCode(requestCtx, h.tenant, idempotencyKey, api.CodeSigningRequest{
		Principal: command.Principal, KeyID: command.KeyID,
		ArtifactType: command.ArtifactType, Digest: command.Digest,
	})
	if err == nil {
		t.Fatal("retry without dispatcher unexpectedly completed")
	}
	op, found, err := h.store.CodeSigningOperationByIdempotency(context.Background(), h.tenant, idempotencyKey)
	if err != nil || !found {
		t.Fatalf("retry projection = found %v err %v", found, err)
	}
	if !bytes.Equal(op.SealedCommand, canonicalCiphertext) {
		t.Fatal("retry projected newly sealed ciphertext instead of canonical JetStream event")
	}
	eventCount := 0
	if err := h.log.Replay(context.Background(), 0, func(event events.Event) error {
		if event.ID == codeSigningEventID(h.tenant, projections.EventCodeSigningCommanded, operationID) {
			eventCount++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if eventCount != 1 {
		t.Fatalf("durable command events = %d, want one deduplicated canonical event", eventCount)
	}
}

func TestCodeSigningWorkerHoldsNoDatabaseTransactionAroundSigner(t *testing.T) {
	inner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate fixture signer: %v", err)
	}
	t.Cleanup(inner.Destroy)
	probe := &databaseProbeOperationSigner{DigestSigner: inner, tenantID: servedTestTenant}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		probe.store = d.Store
		d.CodeSigning = CodeSigningConfig{
			Keys: codeSigningKeyMap{keys: map[string]crypto.DigestSigner{"release-key": probe}},
		}
	})
	token := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "release-bot", []string{
		string(authz.KeysRead), string(authz.KeysWrite),
	})

	// Reserve every pool connection except one. If the dispatcher kept its claim
	// or projection tx open while invoking the signer, the signer's independent
	// tenant query could not acquire a connection and would time out.
	maxConns := int(h.store.SystemPool().Config().MaxConns)
	if maxConns < 2 {
		t.Skip("PostgreSQL pool has fewer than two connections")
	}
	reserved := make([]interface{ Release() }, 0, maxConns-1)
	for i := 0; i < maxConns-1; i++ {
		conn, err := h.store.SystemPool().Acquire(context.Background())
		if err != nil {
			t.Fatalf("reserve pool connection %d: %v", i, err)
		}
		reserved = append(reserved, conn)
	}
	defer func() {
		for _, conn := range reserved {
			conn.Release()
		}
	}()
	startServedExternalCADispatcher(t, h)

	statusCode, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/code-signing/sign",
		token, "codesign-no-db-tx", map[string]any{
			"key_id": "release-key", "artifact_type": "blob",
			"digest": crypto.SHA256Sum([]byte("database transaction probe")),
		})
	if statusCode != http.StatusOK {
		t.Fatalf("code-signing DB transaction probe = %d, want 200; body=%s probe_error=%v", statusCode, body, probe.Err())
	}
	if err := probe.Err(); err != nil {
		t.Fatalf("signer could not run independent tenant query: %v", err)
	}
}

func TestCodeSigningTransientSignerFailureStaysQueuedThenSucceeds(t *testing.T) {
	inner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inner.Destroy)
	flaky := &failOnceOperationSigner{DigestSigner: inner}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.CodeSigning = CodeSigningConfig{
			Keys: codeSigningKeyMap{keys: map[string]crypto.DigestSigner{"release-key": flaky}},
		}
	})
	const idempotencyKey = "codesign-transient-signer-retry"
	requestCtx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	_, err = h.srv.codeSign.SignCode(requestCtx, h.tenant, idempotencyKey, api.CodeSigningRequest{
		Principal: "release-bot", KeyID: "release-key", ArtifactType: "blob",
		Digest: crypto.SHA256Sum([]byte("retryable signer artifact")),
	})
	if err == nil {
		t.Fatal("queued signing request unexpectedly completed without a dispatcher")
	}
	op, found, err := h.store.CodeSigningOperationByIdempotency(context.Background(), h.tenant, idempotencyKey)
	if err != nil || !found {
		t.Fatalf("load queued signing operation = found %v err %v", found, err)
	}
	command := loadCodeSigningOutboxMessage(t, h.store, h.tenant, op.CommandOutboxID)
	firstErr := h.srv.obHandler.Deliver(context.Background(), command)
	if status.Code(firstErr) != codes.Unavailable {
		t.Fatalf("first transient signer delivery = %v (code %s), want Unavailable", firstErr, status.Code(firstErr))
	}
	op, found, err = h.store.CodeSigningOperationByID(context.Background(), h.tenant, op.OperationID)
	if err != nil || !found || op.Status != "queued" || op.LastError != "" {
		t.Fatalf("transient signer failure changed durable operation = found %v err %v op %+v", found, err, op)
	}
	if err := h.srv.obHandler.Deliver(context.Background(), command); err != nil {
		t.Fatalf("retry after transient signer recovery: %v", err)
	}
	op, found, err = h.store.CodeSigningOperationByID(context.Background(), h.tenant, op.OperationID)
	if err != nil || !found || op.Status != "completed" || len(op.Response) == 0 {
		t.Fatalf("recovered signer operation = found %v err %v op %+v", found, err, op)
	}
	if calls := flaky.calls.Load(); calls != 2 {
		t.Fatalf("transient signer calls = %d, want failed attempt plus successful retry", calls)
	}
}

func TestCodeSigningTransientKeyResolverFailureStaysQueuedThenSucceeds(t *testing.T) {
	inner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inner.Destroy)
	signer := &countingOperationSigner{DigestSigner: inner}
	resolver := &failOnceCodeSigningKeyResolver{signer: signer}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.CodeSigning = CodeSigningConfig{Keys: resolver}
	})
	const idempotencyKey = "codesign-transient-key-resolver-retry"
	requestCtx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	_, err = h.srv.codeSign.SignCode(requestCtx, h.tenant, idempotencyKey, api.CodeSigningRequest{
		Principal: "release-bot", KeyID: "release-key", ArtifactType: "blob",
		Digest: crypto.SHA256Sum([]byte("retryable resolver artifact")),
	})
	if err == nil {
		t.Fatal("queued signing request unexpectedly completed without a dispatcher")
	}
	op, found, err := h.store.CodeSigningOperationByIdempotency(context.Background(), h.tenant, idempotencyKey)
	if err != nil || !found {
		t.Fatalf("load queued resolver operation = found %v err %v", found, err)
	}
	command := loadCodeSigningOutboxMessage(t, h.store, h.tenant, op.CommandOutboxID)
	firstErr := h.srv.obHandler.Deliver(context.Background(), command)
	if status.Code(firstErr) != codes.Unavailable {
		t.Fatalf("first transient key resolution = %v (code %s), want Unavailable", firstErr, status.Code(firstErr))
	}
	op, found, err = h.store.CodeSigningOperationByID(context.Background(), h.tenant, op.OperationID)
	if err != nil || !found || op.Status != "queued" || op.LastError != "" {
		t.Fatalf("transient key resolution changed durable operation = found %v err %v op %+v", found, err, op)
	}
	if err := h.srv.obHandler.Deliver(context.Background(), command); err != nil {
		t.Fatalf("retry after key resolver recovery: %v", err)
	}
	op, found, err = h.store.CodeSigningOperationByID(context.Background(), h.tenant, op.OperationID)
	if err != nil || !found || op.Status != "completed" || len(op.Response) == 0 {
		t.Fatalf("recovered key resolver operation = found %v err %v op %+v", found, err, op)
	}
	if calls := resolver.calls.Load(); calls != 2 {
		t.Fatalf("key resolver calls = %d, want failed attempt plus successful retry", calls)
	}
	if calls := signer.calls.Load(); calls != 1 {
		t.Fatalf("signer calls = %d, want only the successful resolved attempt", calls)
	}
}

func TestCodeSigningPolicyFailureProjectsTerminalWithoutRetry(t *testing.T) {
	inner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inner.Destroy)
	signer := &countingOperationSigner{DigestSigner: inner}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.CodeSigning = CodeSigningConfig{
			Keys: codeSigningKeyMap{keys: map[string]crypto.DigestSigner{"release-key": signer}},
			Gate: codeSigningGateFunc(func(context.Context, string, string, string, string) (bool, string) {
				return false, "explicit policy denial"
			}),
		}
	})
	const idempotencyKey = "codesign-terminal-policy-denial"
	requestCtx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	_, err = h.srv.codeSign.SignCode(requestCtx, h.tenant, idempotencyKey, api.CodeSigningRequest{
		Principal: "release-bot", KeyID: "release-key", ArtifactType: "blob",
		Digest: crypto.SHA256Sum([]byte("policy-denied artifact")),
	})
	if err == nil {
		t.Fatal("queued policy-denied request unexpectedly completed without a dispatcher")
	}
	op, found, err := h.store.CodeSigningOperationByIdempotency(context.Background(), h.tenant, idempotencyKey)
	if err != nil || !found {
		t.Fatalf("load policy-denied operation = found %v err %v", found, err)
	}
	command := loadCodeSigningOutboxMessage(t, h.store, h.tenant, op.CommandOutboxID)
	if err := h.srv.obHandler.Deliver(context.Background(), command); err != nil {
		t.Fatalf("terminal policy delivery should be acknowledged after projection: %v", err)
	}
	op, found, err = h.store.CodeSigningOperationByID(context.Background(), h.tenant, op.OperationID)
	if err != nil || !found || op.Status != "failed" || op.LastError != "policy_denied" {
		t.Fatalf("terminal policy operation = found %v err %v op %+v", found, err, op)
	}
	if calls := signer.calls.Load(); calls != 0 {
		t.Fatalf("policy-denied request reached signer %d time(s)", calls)
	}
}

func TestCodeSigningFailureCodeNeverPersistsAttestorInput(t *testing.T) {
	secretInput := "identity-token-that-must-not-enter-events"
	got := codeSigningFailureCode(fmt.Errorf("attest rejected payload %s", secretInput))
	if got != "identity_attestation_failed" || strings.Contains(got, secretInput) {
		t.Fatalf("sanitized failure = %q", got)
	}
}

func TestCodeSigningFailureCodeCarriesOnlyValidatedApprovalResource(t *testing.T) {
	resource := "codesign:" + strings.Repeat("a", 64)
	got := codeSigningFailureCode(fmt.Errorf("not permitted (approval resource %s, action sign)", resource))
	if got != "approval_required:"+resource {
		t.Fatalf("approval failure code = %q", got)
	}
	for _, hostile := range []string{
		"codesign:short", "codesign:" + strings.Repeat("z", 64),
		"codesign:" + strings.Repeat("a", 64) + "secret",
	} {
		got = codeSigningFailureCode(fmt.Errorf("not permitted (approval resource %s, action sign)", hostile))
		if got != "policy_denied" {
			t.Fatalf("hostile approval resource %q persisted as %q", hostile, got)
		}
	}
}

func TestCodeSigningBusinessEventIDsAreDeterministicPerOperation(t *testing.T) {
	first := codeSigningEventID(servedTestTenant, "codesign.completed", "operation-1")
	if again := codeSigningEventID(servedTestTenant, "codesign.completed", "operation-1"); again != first {
		t.Fatalf("same business event IDs differ: %q != %q", first, again)
	}
	for _, different := range []string{
		codeSigningEventID(servedTestTenant, "codesign.failed", "operation-1"),
		codeSigningEventID(servedTestTenant, "codesign.completed", "operation-2"),
		codeSigningEventID("22222222-2222-2222-2222-222222222222", "codesign.completed", "operation-1"),
	} {
		if different == first {
			t.Fatalf("different business event collided with %q", first)
		}
	}
}

func TestProductionCodeSigningGateUsesLivePolicyAndPostgresApproval(t *testing.T) {
	inner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inner.Destroy)
	digest := crypto.SHA256Sum([]byte("policy-and-approval-bound artifact"))
	digestHex := fmt.Sprintf("%x", digest)
	policyModule := fmt.Sprintf(`package trstctl.policy

default allow := false
default reason := "code-signing tuple is not authorized"

allow if {
	input.action == "code_sign"
	input.actor == "release-bot"
	input.subject == "release-key"
	input.attrs.digest_sha256 == %q
}
`, digestHex)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnablePolicyGate = true
		d.PolicyModule = policyModule
		d.RequireApproval = true
		d.RequiredApprovals = 1
		d.CodeSigning = CodeSigningConfig{
			Keys: codeSigningKeyMap{keys: map[string]crypto.DigestSigner{
				"release-key": testOperationDigestSigner{DigestSigner: inner},
			}},
		}
	})
	gate := h.srv.codeSign.cfg.Gate
	if gate == nil {
		t.Fatal("production Build left the code-signing gate unwired")
	}
	allowed, reason := gate.MaySign(context.Background(), h.tenant, "release-bot", "release-key", digestHex)
	if allowed || !strings.Contains(reason, "approval resource") {
		t.Fatalf("unapproved production gate = allowed %v reason %q", allowed, reason)
	}
	resource := codeSigningApprovalResource("release-bot", "release-key", digestHex)
	approval, err := h.store.GetIssuanceApproval(context.Background(), h.tenant, resource, codeSigningApprovalAction)
	if err != nil {
		t.Fatalf("load code-signing approval request: %v", err)
	}
	if approval.Requester != "release-bot" || approval.Required != 1 {
		t.Fatalf("approval binding = %+v", approval)
	}
	requesterToken := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "release-bot", []string{
		string(authz.KeysRead), string(authz.KeysWrite),
	})
	approverToken := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "security-approver", []string{
		string(authz.CertsIssue),
	})
	startServedExternalCADispatcher(t, h)
	request := map[string]any{"key_id": "release-key", "artifact_type": "oci-image", "digest": digest}
	statusCode, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/code-signing/sign",
		requesterToken, "codesign-policy-approval-denied", request)
	if statusCode != http.StatusForbidden || !bytes.Contains(body, []byte(resource)) {
		t.Fatalf("served approval denial = %d body=%s, want 403 with resource %s", statusCode, body, resource)
	}
	statusCode, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/identities/"+resource+"/approvals",
		approverToken, "codesign-policy-approval-grant", map[string]string{"action": codeSigningApprovalAction})
	if statusCode != http.StatusOK {
		t.Fatalf("served code-signing approval = %d body=%s", statusCode, body)
	}
	statusCode, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/code-signing/sign",
		requesterToken, "codesign-policy-approval-allowed", request)
	if statusCode != http.StatusOK {
		t.Fatalf("served approved code-signing = %d body=%s", statusCode, body)
	}
	if allowed, reason = gate.MaySign(context.Background(), h.tenant, "release-bot", "release-key", digestHex); !allowed {
		t.Fatalf("policy-approved, distinctly approved tuple denied: %s", reason)
	}
	if allowed, _ = gate.MaySign(context.Background(), h.tenant, "release-bot", "release-key", fmt.Sprintf("%x", crypto.SHA256Sum([]byte("different")))); allowed {
		t.Fatal("production policy gate allowed a different artifact digest")
	}
}

func TestCodeSigningDeadLetterProjectsFailureAndCleansLostKeylessHandle(t *testing.T) {
	var (
		mu        sync.Mutex
		created   = map[string]*crypto.LockedSigner{}
		destroyed []string
	)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.CodeSigning = CodeSigningConfig{
			Keys:      codeSigningKeyMap{keys: map[string]crypto.DigestSigner{}},
			Attestors: []attest.Attestor{fulcioFixtureAttestor{subject: "repo:acme/release", issuer: "https://issuer.example"}},
			NewEphemeralSigner: func(_ context.Context, operationID string, algorithm crypto.Algorithm) (crypto.DigestSigner, string, error) {
				handle := codeSigningEphemeralHandle(operationID)
				key, err := crypto.GenerateLockedKey(algorithm)
				if err != nil {
					return nil, "", err
				}
				mu.Lock()
				created[handle] = key
				mu.Unlock()
				return testOperationDigestSigner{DigestSigner: key}, handle, nil
			},
			DestroyEphemeralSigner: func(_ context.Context, handle string) error {
				mu.Lock()
				defer mu.Unlock()
				if key := created[handle]; key != nil {
					key.Destroy()
					delete(created, handle)
				}
				destroyed = append(destroyed, handle)
				return nil
			},
		}
	})
	const idempotencyKey = "codesign-keyless-lost-handle"
	requestCtx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	_, err := h.srv.codeSign.SignKeylessCode(requestCtx, h.tenant, idempotencyKey, api.CodeSigningKeylessRequest{
		Principal: "release-bot", ArtifactType: "oci-image",
		Digest:         crypto.SHA256Sum([]byte("keyless crash artifact")),
		IdentityMethod: "fulcio_fixture", IdentityPayload: []byte("short-lived-proof"),
	})
	if err == nil {
		t.Fatal("queued keyless request unexpectedly completed without a dispatcher")
	}
	op, found, err := h.store.CodeSigningOperationByIdempotency(context.Background(), h.tenant, idempotencyKey)
	if err != nil || !found {
		t.Fatalf("load queued keyless operation = found %v err %v", found, err)
	}
	// Simulate the real crash window: the deterministic signer key was created, but
	// the process died before codesign.completed persisted its handle.
	_, lostHandle, err := h.srv.codeSign.cfg.NewEphemeralSigner(context.Background(), op.OperationID, crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("create pre-crash keyless handle: %v", err)
	}
	if op.EphemeralHandle != "" {
		t.Fatalf("queued operation unexpectedly persisted pre-crash handle %q", op.EphemeralHandle)
	}
	command := loadCodeSigningOutboxMessage(t, h.store, h.tenant, op.CommandOutboxID)
	if command.EffectLane != store.CodeSigningCommandDestination+":"+op.OperationID {
		t.Fatalf("command effect lane = %q", command.EffectLane)
	}
	terminal, ok := h.srv.obHandler.(orchestrator.TerminalFailureHandler)
	if !ok {
		t.Fatal("production outbox handler has no terminal-failure callback")
	}
	if err := terminal.DeliverTerminalFailure(context.Background(), command, errors.New("signer retry budget exhausted")); err != nil {
		t.Fatalf("project code-signing terminal failure: %v", err)
	}
	op, found, err = h.store.CodeSigningOperationByID(context.Background(), h.tenant, op.OperationID)
	if err != nil || !found {
		t.Fatalf("reload terminal keyless operation = found %v err %v", found, err)
	}
	if op.Status != "failed" || op.CleanupStatus != "pending" || op.EphemeralHandle != lostHandle || op.CleanupOutboxID == 0 {
		t.Fatalf("terminal keyless operation did not retain crash-safe cleanup identity: %+v lost=%q", op, lostHandle)
	}
	cleanup := loadCodeSigningOutboxMessage(t, h.store, h.tenant, op.CleanupOutboxID)
	if cleanup.EffectLane != store.CodeSigningCleanupDestination+":"+op.OperationID {
		t.Fatalf("cleanup effect lane = %q", cleanup.EffectLane)
	}
	if err := h.srv.obHandler.Deliver(context.Background(), cleanup); err != nil {
		t.Fatalf("deliver crash-safe keyless cleanup: %v", err)
	}
	op, _, err = h.store.CodeSigningOperationByID(context.Background(), h.tenant, op.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if op.CleanupStatus != "completed" || len(destroyed) != 1 || destroyed[0] != lostHandle || len(created) != 0 {
		t.Fatalf("cleanup convergence = status %q destroyed %v remaining %d", op.CleanupStatus, destroyed, len(created))
	}
}

func loadCodeSigningOutboxMessage(t *testing.T, st *store.Store, tenantID string, id int64) orchestrator.Message {
	t.Helper()
	var message orchestrator.Message
	err := st.WithTenant(context.Background(), tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(),
			`SELECT id, tenant_id::text, destination, payload, idempotency_key, attempts,
			        COALESCE(NULLIF(effect_lane, ''), destination)
			   FROM outbox WHERE tenant_id = $1 AND id = $2`, tenantID, id).Scan(
			&message.ID, &message.TenantID, &message.Destination, &message.Payload,
			&message.IdempotencyKey, &message.Attempts, &message.EffectLane)
	})
	if err != nil {
		t.Fatalf("load code-signing outbox row %d: %v", id, err)
	}
	return message
}

type countingOperationSigner struct {
	crypto.DigestSigner
	calls atomic.Int32
}

type failOnceOperationSigner struct {
	crypto.DigestSigner
	calls atomic.Int32
}

type failOnceCodeSigningKeyResolver struct {
	signer crypto.DigestSigner
	calls  atomic.Int32
}

func (r *failOnceCodeSigningKeyResolver) Signer(_, _ string) (crypto.DigestSigner, error) {
	if r.calls.Add(1) == 1 {
		return nil, status.Error(codes.Unavailable, "temporary key resolver outage")
	}
	return r.signer, nil
}

func (s *failOnceOperationSigner) SignDigestForOperation(_ string, digest []byte, opts crypto.SignOptions) ([]byte, error) {
	if s.calls.Add(1) == 1 {
		return nil, status.Error(codes.Unavailable, "temporary signer outage")
	}
	return s.SignDigest(digest, opts)
}

type codeSigningGateFunc func(context.Context, string, string, string, string) (bool, string)

func (f codeSigningGateFunc) MaySign(ctx context.Context, tenantID, principal, keyID, digestHex string) (bool, string) {
	return f(ctx, tenantID, principal, keyID, digestHex)
}

func (s *countingOperationSigner) SignDigestForOperation(_ string, digest []byte, opts crypto.SignOptions) ([]byte, error) {
	s.calls.Add(1)
	return s.SignDigest(digest, opts)
}

type databaseProbeOperationSigner struct {
	crypto.DigestSigner
	store    *store.Store
	tenantID string
	mu       sync.Mutex
	err      error
}

func (s *databaseProbeOperationSigner) SignDigestForOperation(_ string, digest []byte, opts crypto.SignOptions) ([]byte, error) {
	probeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := s.store.WithTenant(probeCtx, s.tenantID, func(tx pgx.Tx) error {
		var count int
		return tx.QueryRow(probeCtx,
			`SELECT count(*) FROM outbox WHERE tenant_id = $1`, s.tenantID).Scan(&count)
	})
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("database probe while signing: %w", err)
	}
	return s.SignDigest(digest, opts)
}

func (s *databaseProbeOperationSigner) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}
