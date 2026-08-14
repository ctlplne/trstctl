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
	"slices"
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
	"trstctl.com/trstctl/internal/privacy"
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
	operationID := projections.LegacyCodeSigningOperationID(h.tenant, idempotencyKey)
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

	// The retry must project the canonical event before it waits for the absent
	// dispatcher. Do not use a tiny request timeout as a synchronization barrier:
	// under the race detector it can cancel the projection that this test is
	// trying to observe.
	requestCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	retryDone := make(chan error, 1)
	go func() {
		_, retryErr := h.srv.codeSign.SignCode(requestCtx, h.tenant, idempotencyKey, api.CodeSigningRequest{
			Principal: command.Principal, KeyID: command.KeyID,
			ArtifactType: command.ArtifactType, Digest: command.Digest,
		})
		retryDone <- retryErr
	}()

	projectionCtx, stopProjectionWait := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopProjectionWait()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var (
		op    store.CodeSigningOperation
		found bool
	)
	for !found {
		op, found, err = h.store.CodeSigningOperationByIdempotency(projectionCtx, h.tenant, idempotencyKey)
		if err != nil {
			t.Fatalf("retry projection: %v", err)
		}
		if found {
			break
		}
		select {
		case retryErr := <-retryDone:
			t.Fatalf("retry returned before projecting the canonical event: %v", retryErr)
		case <-projectionCtx.Done():
			t.Fatalf("retry projection: %v", projectionCtx.Err())
		case <-ticker.C:
		}
	}
	cancel()
	select {
	case retryErr := <-retryDone:
		if retryErr == nil {
			t.Fatal("retry without dispatcher unexpectedly completed")
		}
	case <-time.After(time.Second):
		t.Fatal("retry did not stop after request cancellation")
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

func TestPrivacySafeCodeSigningRetryAfterAppendACKAndSQLFailureReprojectsCanonicalEvent(t *testing.T) {
	inner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inner.Destroy)
	signer := &countingOperationSigner{DigestSigner: inner}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.CodeSigning = CodeSigningConfig{Keys: codeSigningKeyMap{keys: map[string]crypto.DigestSigner{
			"release-key": signer,
		}}}
	})
	const idempotencyKey = "codesign-v3-append-ack-sql-failure"
	request := api.CodeSigningRequest{
		Principal: "release-bot", KeyID: "release-key", ArtifactType: "blob",
		Digest: crypto.SHA256Sum([]byte("v3 append ACK then SQL failure")),
	}
	untruncated := time.Date(2031, time.January, 2, 3, 4, 5, 987654321, time.FixedZone("test", -5*60*60))
	h.srv.codeSign.now = func() time.Time { return untruncated }
	crash := errors.New("simulated process death after command append ACK")
	var appended events.Event
	h.srv.codeSign.afterCommandAppend = func(event events.Event) error {
		appended = event
		return crash
	}
	if _, err := h.srv.codeSign.SignCode(context.Background(), h.tenant, idempotencyKey, request); !errors.Is(err, crash) {
		t.Fatalf("first command error=%v, want append-ACK crash", err)
	}
	if appended.ID == "" || appended.SchemaVersion != projections.CodeSigningPrivacySafeEventSchemaVersion ||
		!appended.Time.Equal(untruncated.UTC().Truncate(time.Microsecond)) ||
		!appended.Time.Equal(appended.Time.UTC().Truncate(time.Microsecond)) {
		t.Fatalf("canonical v3 envelope time/schema = %+v", appended)
	}
	if _, found, err := h.store.CodeSigningOperationByIdempotency(
		context.Background(), h.tenant, idempotencyKey,
	); err != nil || found {
		t.Fatalf("simulated SQL failure left operation = found %t err=%v", found, err)
	}

	h.srv.codeSign.afterCommandAppend = nil
	op := submitQueuedCodeSigning(t, h, idempotencyKey, func(ctx context.Context) error {
		_, err := h.srv.codeSign.SignCode(ctx, h.tenant, idempotencyKey, request)
		return err
	})
	var canonical projections.CodeSigningCommanded
	if err := json.Unmarshal(appended.Data, &canonical); err != nil {
		t.Fatal(err)
	}
	if op.OperationID != codeSigningOperationID(h.tenant, idempotencyKey) ||
		op.IdempotencyKey != store.CodeSigningIdempotencyKeyRef(idempotencyKey) ||
		!bytes.Equal(op.SealedCommand, canonical.SealedCommand) || signer.calls.Load() != 0 {
		t.Fatalf("reprojected v3 command/provider calls differ: op=%+v calls=%d", op, signer.calls.Load())
	}
	var operationRows, outboxRows int
	if err := h.store.SystemPool().QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM code_signing_operations WHERE tenant_id = $1 AND operation_id = $2),
		(SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key = $3)`,
		h.tenant, op.OperationID, "codesign.command:"+op.OperationID).Scan(&operationRows, &outboxRows); err != nil {
		t.Fatal(err)
	}
	eventCount := 0
	if err := h.log.Replay(context.Background(), 0, func(event events.Event) error {
		if event.ID == appended.ID {
			eventCount++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if operationRows != 1 || outboxRows != 1 || eventCount != 1 {
		t.Fatalf("canonical convergence operations/outbox/events=%d/%d/%d, want 1/1/1",
			operationRows, outboxRows, eventCount)
	}
}

func TestCodeSigningRetryRejectsRetainedV3AndLegacyCommandDisagreement(t *testing.T) {
	inner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inner.Destroy)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.CodeSigning = CodeSigningConfig{Keys: codeSigningKeyMap{keys: map[string]crypto.DigestSigner{
			"release-key": testOperationDigestSigner{DigestSigner: inner},
		}}}
	})
	const idempotencyKey = "retained-current-and-legacy-disagree"
	command := codeSigningCommand{
		Mode: "key", Principal: "release-bot", KeyID: "release-key",
		ArtifactType: "blob", Digest: crypto.SHA256Sum([]byte("two retained identities")),
	}
	requestHash, err := codeSigningCommandHash(command)
	if err != nil {
		t.Fatal(err)
	}
	v3Operation := codeSigningOperationID(h.tenant, idempotencyKey)
	legacyOperation := projections.LegacyCodeSigningOperationID(h.tenant, idempotencyKey)
	v3Payload, err := json.Marshal(projections.CodeSigningCommanded{
		OperationID:       v3Operation,
		IdempotencyKeyRef: store.CodeSigningIdempotencyKeyRef(idempotencyKey),
		RequestBinding:    projections.CodeSigningRequestBinding(requestHash, idempotencyKey),
		Mode:              command.Mode, RequestHash: requestHash, SealedCommand: []byte("v3-ciphertext"),
	})
	if err != nil {
		t.Fatal(err)
	}
	legacyPayload, err := json.Marshal(projections.CodeSigningCommanded{
		OperationID: legacyOperation, IdempotencyKey: idempotencyKey,
		Mode: command.Mode, RequestHash: requestHash, SealedCommand: []byte("legacy-ciphertext"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []events.Event{
		{
			ID:   codeSigningEventID(h.tenant, projections.EventCodeSigningCommanded, v3Operation),
			Type: projections.EventCodeSigningCommanded, TenantID: h.tenant,
			Time:          time.Now().UTC().Truncate(time.Microsecond),
			SchemaVersion: projections.CodeSigningPrivacySafeEventSchemaVersion, Data: v3Payload,
		},
		{
			ID:   codeSigningEventID(h.tenant, projections.EventCodeSigningCommanded, legacyOperation),
			Type: projections.EventCodeSigningCommanded, TenantID: h.tenant,
			SchemaVersion: 1, Data: legacyPayload,
		},
	} {
		if _, err := h.log.Append(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}
	_, err = h.srv.codeSign.SignCode(context.Background(), h.tenant, idempotencyKey, api.CodeSigningRequest{
		Principal: command.Principal, KeyID: command.KeyID,
		ArtifactType: command.ArtifactType, Digest: command.Digest,
	})
	if !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("dual retained identity retry error=%v, want ErrIdempotencyConflict", err)
	}
	if _, found, err := h.store.CodeSigningOperationByIdempotency(
		context.Background(), h.tenant, idempotencyKey,
	); err != nil || found {
		t.Fatalf("dual retained disagreement projected work = found %t err=%v", found, err)
	}
}

func TestApprovedCodeSigningRetryAfterAppendAndSQLRollbackUsesDurableFirstCommand(t *testing.T) {
	inner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inner.Destroy)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.RequireApproval = true
		d.RequiredApprovals = 1
		d.CodeSigning = CodeSigningConfig{
			Keys: codeSigningKeyMap{keys: map[string]crypto.DigestSigner{
				"release-key": testOperationDigestSigner{DigestSigner: inner},
			}},
		}
	})
	registerServedTenant(t, h, "approved code-signing rollback tenant")
	ctx := context.Background()
	const (
		keySubject     = "alice.codesign@example.com"
		idempotencyKey = "approved-codesign/" + keySubject + "/append-sql-rollback"
	)
	command := codeSigningCommand{
		Mode: "key", Principal: "release-bot", KeyID: "release-key",
		ArtifactType: "oci-image", Digest: crypto.SHA256Sum([]byte("approved first command")),
	}
	requesterToken := seedServedAPIToken(t, ctx, h.store, h.tenant, command.Principal, []string{
		string(authz.KeysRead), string(authz.KeysWrite),
	})
	approverToken := seedServedAPIToken(t, ctx, h.store, h.tenant, "security-approver", []string{
		string(authz.CertsIssue),
	})
	request := map[string]any{"key_id": command.KeyID, "artifact_type": command.ArtifactType, "digest": command.Digest}
	statusCode, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/code-signing/sign",
		requesterToken, idempotencyKey, request)
	if statusCode != http.StatusForbidden || !bytes.Contains(body, []byte("approval_required:codesign:")) {
		t.Fatalf("create exact approval = %d body=%s", statusCode, body)
	}
	pending, err := h.store.ListOperationApprovals(ctx, h.tenant, store.ApprovalStatusPending, 10)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending exact approval = %+v err=%v", pending, err)
	}
	approval := pending[0]
	statusCode, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/approval-requests/"+approval.ID+"/approvals",
		approverToken, "approve-durable-first-command", map[string]string{"intent_digest": approval.IntentDigest})
	if statusCode != http.StatusOK {
		t.Fatalf("approve exact command = %d body=%s", statusCode, body)
	}
	approval, err = h.store.GetOperationApproval(ctx, h.tenant, approval.ID)
	if err != nil {
		t.Fatal(err)
	}
	use, err := store.OperationApprovalUseFromRequest(approval)
	if err != nil {
		t.Fatal(err)
	}
	requestHash, err := codeSigningCommandHash(command)
	if err != nil {
		t.Fatal(err)
	}
	operationID := codeSigningOperationID(h.tenant, idempotencyKey)
	keyRef := store.CodeSigningIdempotencyKeyRef(idempotencyKey)
	requestBinding := projections.CodeSigningRequestBinding(requestHash, idempotencyKey)
	untruncated := approval.ExpiresAt.Add(-time.Minute + 789*time.Nanosecond).
		In(time.FixedZone("approval-test", 9*60*60))
	h.srv.codeSign.now = func() time.Time { return untruncated }
	rollback := errors.New("simulated crash after append ACK")
	var event events.Event
	h.srv.codeSign.afterCommandAppend = func(appended events.Event) error {
		event = appended
		return rollback
	}
	_, err = h.srv.codeSign.SignCode(ctx, h.tenant, idempotencyKey, api.CodeSigningRequest{
		Principal: command.Principal, KeyID: command.KeyID,
		ArtifactType: command.ArtifactType, Digest: command.Digest,
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("normal approved append crash = %v", err)
	}
	h.srv.codeSign.afterCommandAppend = nil
	if event.ID != codeSigningApprovedEventID(h.tenant, operationID) ||
		!event.Time.Equal(untruncated.UTC().Truncate(time.Microsecond)) ||
		!event.Time.Equal(event.Time.UTC().Truncate(time.Microsecond)) {
		t.Fatalf("normal approved event did not use PostgreSQL-exact time: %+v", event)
	}
	var commanded projections.CodeSigningCommanded
	if err := json.Unmarshal(event.Data, &commanded); err != nil {
		t.Fatal(err)
	}
	raw := event.Data
	sealed := commanded.SealedCommand
	rawBearing := commanded
	rawBearing.IdempotencyKey = idempotencyKey
	if _, err := projections.CodeSigningCommandSemanticDigest(event, rawBearing); err == nil {
		t.Fatal("schema-v3 command accepted a raw idempotency key before append")
	}
	if commanded.OperationID != operationID || commanded.IdempotencyKeyRef != keyRef ||
		commanded.RequestBinding != requestBinding || commanded.Approval == nil ||
		commanded.Approval.RequestID != use.RequestID {
		t.Fatalf("normal approved command identity = %+v", commanded)
	}
	fence, err := h.store.GetApprovedTargetFence(
		ctx, h.tenant, store.ApprovedTargetCodeSigningCommand, operationID,
	)
	if err != nil {
		t.Fatalf("load durable first command after crash: %v", err)
	}
	if bytes.Contains(raw, []byte(keySubject)) || bytes.Contains(fence.Payload, []byte(keySubject)) ||
		bytes.Contains(raw, []byte(`"idempotency_key":`)) ||
		bytes.Contains(fence.Payload, []byte(`"idempotency_key":`)) {
		t.Fatalf("privacy-safe prepared command persisted raw idempotency subject %q: event=%s fence=%s",
			keySubject, raw, fence.Payload)
	}
	if _, found, err := h.store.CodeSigningOperationByID(ctx, h.tenant, operationID); err != nil || found {
		t.Fatalf("rolled-back command projection = found %t err=%v", found, err)
	}
	if _, err := h.store.GetApprovedTargetFence(ctx, h.tenant, fence.TargetKind, fence.CommandKey); err != nil {
		t.Fatalf("rollback lost durable command fence: %v", err)
	}
	consumed, err := h.store.GetOperationApproval(ctx, h.tenant, approval.ID)
	if err != nil || consumed.Status != store.ApprovalStatusConsumed || consumed.ConsumedEventID != event.ID {
		t.Fatalf("post-crash terminal authority = %+v err=%v", consumed, err)
	}
	if _, err := h.store.SystemPool().Exec(ctx, `UPDATE approved_target_event_fences
		SET created_at = created_at - interval '25 hours', updated_at = updated_at - interval '25 hours'
		WHERE tenant_id = $1 AND target_kind = $2 AND command_key = $3`,
		h.tenant, fence.TargetKind, fence.CommandKey); err != nil {
		t.Fatal(err)
	}

	changed := api.CodeSigningRequest{
		Principal: command.Principal, KeyID: command.KeyID, ArtifactType: command.ArtifactType,
		Digest: crypto.SHA256Sum([]byte("changed request body")),
	}
	if _, err := h.srv.codeSign.SignCode(ctx, h.tenant, idempotencyKey, changed); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed-body retry = %v, want ErrIdempotencyConflict", err)
	}
	// A real process restart runs catch-up before serving and must heal the
	// append-ACK/SQL-rollback fence even though code signing is not re-enabled in
	// the replacement configuration. Recovery is authorization already granted,
	// not a fresh feature-gate decision.
	if _, err := Build(ctx, Deps{
		Store: h.store, Log: h.log, Signer: h.signer,
		SignAuthorizer: h.authz, CACertFile: h.caFile,
	}); err != nil {
		t.Fatalf("startup reconciliation of approved code-signing fence: %v", err)
	}

	retryCtx, cancel := context.WithCancel(ctx)
	retryDone := make(chan error, 1)
	go func() {
		_, retryErr := h.srv.codeSign.SignCode(retryCtx, h.tenant, idempotencyKey, api.CodeSigningRequest{
			Principal: command.Principal, KeyID: command.KeyID,
			ArtifactType: command.ArtifactType, Digest: command.Digest,
		})
		retryDone <- retryErr
	}()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var op store.CodeSigningOperation
	for {
		var found bool
		op, found, err = h.store.CodeSigningOperationByID(ctx, h.tenant, operationID)
		if err != nil {
			t.Fatal(err)
		}
		if found {
			break
		}
		select {
		case retryErr := <-retryDone:
			t.Fatalf("retry returned before recovery projection: %v", retryErr)
		case <-deadline.C:
			t.Fatal("timed out waiting for recovery projection")
		case <-ticker.C:
		}
	}
	cancel()
	select {
	case <-retryDone:
	case <-time.After(time.Second):
		t.Fatal("recovered request did not stop after cancellation")
	}
	if !bytes.Equal(op.SealedCommand, sealed) || op.SourceEventID != event.ID ||
		op.ApprovalRequestID != approval.ID || op.ApprovalIntentDigest != approval.IntentDigest ||
		op.IdempotencyKey != keyRef {
		t.Fatalf("recovered operation differs from durable first command: %+v", op)
	}
	commandOutbox := loadCodeSigningOutboxMessage(t, h.store, h.tenant, op.CommandOutboxID)
	if bytes.Contains(commandOutbox.Payload, []byte(keySubject)) ||
		strings.Contains(commandOutbox.IdempotencyKey, keySubject) ||
		strings.Contains(commandOutbox.EffectLane, keySubject) {
		t.Fatalf("privacy-safe command outbox retained raw idempotency subject: %+v", commandOutbox)
	}
	if _, err := h.store.GetApprovedTargetFence(ctx, h.tenant, fence.TargetKind, fence.CommandKey); !store.IsNotFound(err) {
		t.Fatalf("completed target fence remains: %v", err)
	}
	eventCount := 0
	if err := h.log.Replay(ctx, 0, func(got events.Event) error {
		if got.ID == event.ID {
			eventCount++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if eventCount != 1 {
		t.Fatalf("canonical approved command events = %d, want 1", eventCount)
	}
	if err := projections.New(h.store).Rebuild(ctx, h.log); err != nil {
		t.Fatalf("cold rebuild after recovery: %v", err)
	}
	rebuilt, found, err := h.store.CodeSigningOperationByID(ctx, h.tenant, operationID)
	if err != nil || !found || !bytes.Equal(rebuilt.SealedCommand, sealed) ||
		rebuilt.SourceEventID != event.ID || rebuilt.IdempotencyKey != keyRef {
		t.Fatalf("cold-rebuilt command = found %t op=%+v err=%v", found, rebuilt, err)
	}
}

func TestLegacyApprovedCodeSigningRetainedNanosecondsRecoverAcrossPostgresFencePrecision(t *testing.T) {
	inner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inner.Destroy)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.CodeSigning = CodeSigningConfig{Keys: codeSigningKeyMap{keys: map[string]crypto.DigestSigner{
			"release-key": testOperationDigestSigner{DigestSigner: inner},
		}}}
	})
	ctx := context.Background()
	const (
		idempotencyKey = "legacy-approved-nanosecond-command"
		requestID      = "77961000-0000-4000-8000-000000000001"
		decisionID     = "77961000-0000-4000-8000-000000000002"
		requestHash    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	operationID := projections.LegacyCodeSigningOperationID(h.tenant, idempotencyKey)
	resourceID := store.CodeSigningApprovalResourceID(requestHash, idempotencyKey)
	base := time.Now().UTC().Truncate(time.Microsecond)
	request := store.OperationApprovalRequest{
		ID: requestID, TenantID: h.tenant, IntentDigest: "sha256:" + strings.Repeat("c", 64),
		ResourceKind: "code_signing", ResourceID: resourceID, ResourceName: "release-key",
		Action: "sign", Requester: "release-bot", RequiredApprovals: 1,
		CreatedAt: base, ExpiresAt: base.Add(time.Hour), UpdatedAt: base,
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		if err := h.store.ApplyOperationApprovalRequestedTx(ctx, tx, request); err != nil {
			return err
		}
		return h.store.ApplyOperationApprovalDecisionTx(ctx, tx, store.OperationApprovalDecision{
			TenantID: h.tenant, RequestID: request.ID, IntentDigest: request.IntentDigest,
			Approver: "security-approver", Decision: store.ApprovalDecisionApprove,
			EventID: decisionID, DecidedAt: base.Add(time.Minute),
		})
	}); err != nil {
		t.Fatal(err)
	}
	approved, err := h.store.GetOperationApproval(ctx, h.tenant, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	use, err := store.OperationApprovalUseFromRequest(approved)
	if err != nil {
		t.Fatal(err)
	}
	payload := projections.CodeSigningCommanded{
		OperationID: operationID, IdempotencyKey: idempotencyKey, Mode: "key",
		RequestHash: requestHash, SealedCommand: []byte("legacy-tenant-sealed-command"), Approval: &use,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	untruncated := base.Add(2*time.Minute + 789*time.Nanosecond)
	event := events.Event{
		ID:   codeSigningApprovedEventID(h.tenant, operationID),
		Type: projections.EventCodeSigningCommanded, TenantID: h.tenant,
		Time: untruncated, SchemaVersion: projections.CodeSigningApprovalEventSchemaVersion, Data: raw,
	}
	semantic, err := projections.LegacyCodeSigningHistoricalSemanticDigest(event, payload)
	if err != nil {
		t.Fatal(err)
	}
	fence, created, err := h.store.ClaimApprovedTargetFence(ctx, store.ApprovedTargetFence{
		TenantID: h.tenant, TargetKind: store.ApprovedTargetCodeSigningCommand,
		CommandKey: operationID, RequestBinding: projections.CodeSigningRequestBinding(requestHash, idempotencyKey),
		EventID: event.ID, EventType: event.Type, SchemaVersion: event.SchemaVersion,
		EventTime: event.Time, Payload: event.Data, SemanticDigest: semantic,
	}, use)
	if err != nil || !created {
		t.Fatalf("claim legacy nanosecond fence = created %t err=%v", created, err)
	}
	if fence.EventTime.Equal(untruncated) ||
		!fence.EventTime.Equal(untruncated.UTC().Truncate(time.Microsecond)) {
		t.Fatalf("PostgreSQL fence time=%s, want rounded form of retained %s", fence.EventTime, untruncated)
	}
	retained, err := h.log.Append(ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	if !retained.Time.Equal(untruncated) {
		t.Fatalf("retained legacy timestamp=%s, want %s", retained.Time, untruncated)
	}
	if err := h.srv.codeSign.projectCodeSigningFence(ctx, h.tenant, fence); err != nil {
		t.Fatalf("recover retained legacy nanosecond event: %v", err)
	}
	op, found, err := h.store.CodeSigningOperationByID(ctx, h.tenant, operationID)
	if err != nil || !found || op.SourceEventID != event.ID ||
		op.IdempotencyKey != store.LegacyCodeSigningStorageKey(operationID, idempotencyKey) {
		t.Fatalf("legacy nanosecond recovery = found %t op=%+v err=%v", found, op, err)
	}
	if _, err := h.store.GetApprovedTargetFence(ctx, h.tenant, fence.TargetKind, fence.CommandKey); !store.IsNotFound(err) {
		t.Fatalf("legacy nanosecond recovery left fence: %v", err)
	}
}

func TestPrivacyRewrittenLegacyApprovedFenceWithoutRetainedEventRecoversExactNanosecondsOnRestart(t *testing.T) {
	inner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inner.Destroy)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.CodeSigning = CodeSigningConfig{Keys: codeSigningKeyMap{keys: map[string]crypto.DigestSigner{
			"release-key": testOperationDigestSigner{DigestSigner: inner},
		}}}
	})
	ctx := context.Background()
	const (
		subject        = "legacy-fence-owner@example.com"
		idempotencyKey = "release/legacy-fence-owner@example.com/fence-before-append"
		requestID      = "77961000-0000-4000-8000-000000000011"
		decisionID     = "77961000-0000-4000-8000-000000000012"
		requestHash    = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	)
	operationID := projections.LegacyCodeSigningOperationID(h.tenant, idempotencyKey)
	resourceID := store.CodeSigningApprovalResourceID(requestHash, idempotencyKey)
	base := time.Now().UTC().Truncate(time.Microsecond)
	request := store.OperationApprovalRequest{
		ID: requestID, TenantID: h.tenant, IntentDigest: "sha256:" + strings.Repeat("d", 64),
		ResourceKind: "code_signing", ResourceID: resourceID, ResourceName: "release-key",
		Action: "sign", Requester: subject, RequiredApprovals: 1,
		Reason: "release requested by " + subject, EvidenceRefs: []string{"ticket:" + subject},
		CreatedAt: base, ExpiresAt: base.Add(time.Hour), UpdatedAt: base,
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		if err := h.store.ApplyOperationApprovalRequestedTx(ctx, tx, request); err != nil {
			return err
		}
		return h.store.ApplyOperationApprovalDecisionTx(ctx, tx, store.OperationApprovalDecision{
			TenantID: h.tenant, RequestID: request.ID, IntentDigest: request.IntentDigest,
			Approver: "security-approver", Decision: store.ApprovalDecisionApprove,
			EventID: decisionID, DecidedAt: base.Add(time.Minute),
		})
	}); err != nil {
		t.Fatal(err)
	}
	approved, err := h.store.GetOperationApproval(ctx, h.tenant, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	use, err := store.OperationApprovalUseFromRequest(approved)
	if err != nil {
		t.Fatal(err)
	}
	payload := projections.CodeSigningCommanded{
		OperationID: operationID, IdempotencyKey: idempotencyKey, Mode: "key",
		RequestHash: requestHash, SealedCommand: []byte("legacy-fence-before-append"), Approval: &use,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	originalTime := base.Add(2*time.Minute + 613*time.Nanosecond)
	event := events.Event{
		ID:   codeSigningApprovedEventID(h.tenant, operationID),
		Type: projections.EventCodeSigningCommanded, TenantID: h.tenant,
		Time: originalTime, SchemaVersion: projections.CodeSigningApprovalEventSchemaVersion, Data: raw,
		Actor: &events.Actor{Subject: subject, Roles: []string{"release"}},
	}
	historical, err := projections.LegacyCodeSigningHistoricalSemanticDigest(event, payload)
	if err != nil {
		t.Fatal(err)
	}
	fence, created, err := h.store.ClaimApprovedTargetFence(ctx, store.ApprovedTargetFence{
		TenantID: h.tenant, TargetKind: store.ApprovedTargetCodeSigningCommand,
		CommandKey: operationID, RequestBinding: projections.CodeSigningRequestBinding(requestHash, idempotencyKey),
		EventID: event.ID, EventType: event.Type, SchemaVersion: event.SchemaVersion,
		EventTime: event.Time, Actor: event.Actor, Payload: event.Data, SemanticDigest: historical,
	}, use)
	if err != nil || !created {
		t.Fatalf("claim legacy fence-before-append = created %t err=%v", created, err)
	}
	if fence.EventTime.Equal(originalTime) ||
		!fence.EventTime.Equal(originalTime.UTC().Truncate(time.Microsecond)) {
		t.Fatalf("stored fence time=%s, want rounded form of %s", fence.EventTime, originalTime)
	}
	if _, found, err := h.log.EventByID(ctx, event.ID); err != nil || found {
		t.Fatalf("pre-restart retained event = found %t err=%v", found, err)
	}
	if changed, err := h.store.PseudonymizeApprovedTargetFences(ctx, h.tenant, subject); err != nil || changed != 1 {
		t.Fatalf("pseudonymize legacy fence-before-append = changed %d err=%v", changed, err)
	}
	placeholder := privacy.Placeholder(privacy.SubjectRef(h.tenant, subject))
	if _, err := h.store.SystemPool().Exec(ctx, `UPDATE operation_approval_requests
		SET requester = $3, reason = '', evidence_refs = '[]'::jsonb
		WHERE tenant_id = $1 AND id = $2`, h.tenant, request.ID, placeholder); err != nil {
		t.Fatal(err)
	}
	rewrittenFence, err := h.store.GetApprovedTargetFence(
		ctx, h.tenant, store.ApprovedTargetCodeSigningCommand, operationID,
	)
	if err != nil || bytes.Contains(rewrittenFence.Payload, []byte(subject)) ||
		rewrittenFence.SemanticDigest == historical {
		t.Fatalf("privacy-rewritten legacy fence=%+v err=%v", rewrittenFence, err)
	}
	var rewrittenPayload projections.CodeSigningCommanded
	if err := json.Unmarshal(rewrittenFence.Payload, &rewrittenPayload); err != nil {
		t.Fatal(err)
	}
	rewrittenProof := event
	rewrittenProof.Time = originalTime
	rewrittenProof.Actor = rewrittenFence.Actor
	rewrittenProof.Data = rewrittenFence.Payload
	rewrittenHistorical, err := projections.LegacyCodeSigningHistoricalSemanticDigest(
		rewrittenProof, rewrittenPayload,
	)
	if err != nil || rewrittenFence.SemanticDigest != rewrittenHistorical {
		t.Fatalf("rewritten exact-time historical semantic=%q err=%v, want %q",
			rewrittenFence.SemanticDigest, err, rewrittenHistorical)
	}

	if _, err := Build(ctx, Deps{
		Store: h.store, Log: h.log, Signer: h.signer,
		SignAuthorizer: h.authz, CACertFile: h.caFile,
	}); err != nil {
		t.Fatalf("restart reconciliation of legacy fence-before-append: %v", err)
	}
	retained, found, err := h.log.EventByID(ctx, event.ID)
	if err != nil || !found || !retained.Time.Equal(originalTime) ||
		bytes.Contains(retained.Data, []byte(subject)) || retained.Actor == nil ||
		retained.Actor.Subject != placeholder {
		t.Fatalf("recovered exact legacy event = found %t event=%+v err=%v", found, retained, err)
	}
	var retainedPayload projections.CodeSigningCommanded
	if err := json.Unmarshal(retained.Data, &retainedPayload); err != nil {
		t.Fatal(err)
	}
	if retainedPayload.IdempotencyKey != store.LegacyCodeSigningStorageKey(operationID, idempotencyKey) {
		t.Fatalf("recovered legacy key=%q", retainedPayload.IdempotencyKey)
	}
	canonical, err := projections.CodeSigningCommandSemanticDigest(retained, retainedPayload)
	if err != nil {
		t.Fatal(err)
	}
	op, found, err := h.store.CodeSigningOperationByID(ctx, h.tenant, operationID)
	if err != nil || !found || op.SourceEventID != event.ID || op.SemanticDigest != canonical ||
		op.IdempotencyKey != store.LegacyCodeSigningStorageKey(operationID, idempotencyKey) {
		t.Fatalf("restart-recovered legacy operation = found %t op=%+v err=%v", found, op, err)
	}
	if _, err := h.store.GetApprovedTargetFence(ctx, h.tenant,
		store.ApprovedTargetCodeSigningCommand, operationID); !store.IsNotFound(err) {
		t.Fatalf("restart recovery left legacy fence: %v", err)
	}
}

func TestLegacyApprovedCodeSigningFenceWithoutRetainedEventRejectsSemanticDrift(t *testing.T) {
	inner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inner.Destroy)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.CodeSigning = CodeSigningConfig{Keys: codeSigningKeyMap{keys: map[string]crypto.DigestSigner{
			"release-key": testOperationDigestSigner{DigestSigner: inner},
		}}}
	})
	ctx := context.Background()
	const (
		idempotencyKey = "legacy-approved-corrupt-fence-before-append"
		requestID      = "77961000-0000-4000-8000-000000000021"
		decisionID     = "77961000-0000-4000-8000-000000000022"
		requestHash    = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	)
	operationID := projections.LegacyCodeSigningOperationID(h.tenant, idempotencyKey)
	base := time.Now().UTC().Truncate(time.Microsecond)
	request := store.OperationApprovalRequest{
		ID: requestID, TenantID: h.tenant, IntentDigest: "sha256:" + strings.Repeat("e", 64),
		ResourceKind: "code_signing",
		ResourceID:   store.CodeSigningApprovalResourceID(requestHash, idempotencyKey),
		ResourceName: "release-key", Action: "sign", Requester: "release-bot",
		RequiredApprovals: 1, CreatedAt: base, ExpiresAt: base.Add(time.Hour), UpdatedAt: base,
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		if err := h.store.ApplyOperationApprovalRequestedTx(ctx, tx, request); err != nil {
			return err
		}
		return h.store.ApplyOperationApprovalDecisionTx(ctx, tx, store.OperationApprovalDecision{
			TenantID: h.tenant, RequestID: request.ID, IntentDigest: request.IntentDigest,
			Approver: "security-approver", Decision: store.ApprovalDecisionApprove,
			EventID: decisionID, DecidedAt: base.Add(time.Minute),
		})
	}); err != nil {
		t.Fatal(err)
	}
	approved, err := h.store.GetOperationApproval(ctx, h.tenant, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	use, err := store.OperationApprovalUseFromRequest(approved)
	if err != nil {
		t.Fatal(err)
	}
	payload := projections.CodeSigningCommanded{
		OperationID: operationID, IdempotencyKey: idempotencyKey, Mode: "key",
		RequestHash: requestHash, SealedCommand: []byte("legacy-corrupt-fence"), Approval: &use,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{
		ID:   codeSigningApprovedEventID(h.tenant, operationID),
		Type: projections.EventCodeSigningCommanded, TenantID: h.tenant,
		Time:          base.Add(2*time.Minute + 457*time.Nanosecond),
		SchemaVersion: projections.CodeSigningApprovalEventSchemaVersion, Data: raw,
	}
	historical, err := projections.LegacyCodeSigningHistoricalSemanticDigest(event, payload)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := []byte(historical)
	if corrupt[0] == '0' {
		corrupt[0] = '1'
	} else {
		corrupt[0] = '0'
	}
	if _, created, err := h.store.ClaimApprovedTargetFence(ctx, store.ApprovedTargetFence{
		TenantID: h.tenant, TargetKind: store.ApprovedTargetCodeSigningCommand,
		CommandKey: operationID, RequestBinding: projections.CodeSigningRequestBinding(requestHash, idempotencyKey),
		EventID: event.ID, EventType: event.Type, SchemaVersion: event.SchemaVersion,
		EventTime: event.Time, Payload: event.Data, SemanticDigest: string(corrupt),
	}, use); err != nil || !created {
		t.Fatalf("claim corrupt legacy fence = created %t err=%v", created, err)
	}

	if _, err := Build(ctx, Deps{
		Store: h.store, Log: h.log, Signer: h.signer,
		SignAuthorizer: h.authz, CACertFile: h.caFile,
	}); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("restart with corrupt legacy semantic = %v, want ErrIdempotencyConflict", err)
	}
	if _, found, err := h.log.EventByID(ctx, event.ID); err != nil || found {
		t.Fatalf("corrupt legacy fence appended event = found %t err=%v", found, err)
	}
	if _, found, err := h.store.CodeSigningOperationByID(ctx, h.tenant, operationID); err != nil || found {
		t.Fatalf("corrupt legacy fence projected operation = found %t err=%v", found, err)
	}
	if _, err := h.store.GetApprovedTargetFence(ctx, h.tenant,
		store.ApprovedTargetCodeSigningCommand, operationID); err != nil {
		t.Fatalf("corrupt legacy fence was not preserved for inspection: %v", err)
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
	op := submitQueuedCodeSigning(t, h, idempotencyKey, func(ctx context.Context) error {
		_, submitErr := h.srv.codeSign.SignCode(ctx, h.tenant, idempotencyKey, api.CodeSigningRequest{
			Principal: "release-bot", KeyID: "release-key", ArtifactType: "blob",
			Digest: crypto.SHA256Sum([]byte("retryable signer artifact")),
		})
		return submitErr
	})
	command := loadCodeSigningOutboxMessage(t, h.store, h.tenant, op.CommandOutboxID)
	firstErr := h.srv.obHandler.Deliver(context.Background(), command)
	if status.Code(firstErr) != codes.Unavailable {
		t.Fatalf("first transient signer delivery = %v (code %s), want Unavailable", firstErr, status.Code(firstErr))
	}
	op, found, err := h.store.CodeSigningOperationByID(context.Background(), h.tenant, op.OperationID)
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
	op := submitQueuedCodeSigning(t, h, idempotencyKey, func(ctx context.Context) error {
		_, submitErr := h.srv.codeSign.SignCode(ctx, h.tenant, idempotencyKey, api.CodeSigningRequest{
			Principal: "release-bot", KeyID: "release-key", ArtifactType: "blob",
			Digest: crypto.SHA256Sum([]byte("retryable resolver artifact")),
		})
		return submitErr
	})
	command := loadCodeSigningOutboxMessage(t, h.store, h.tenant, op.CommandOutboxID)
	firstErr := h.srv.obHandler.Deliver(context.Background(), command)
	if status.Code(firstErr) != codes.Unavailable {
		t.Fatalf("first transient key resolution = %v (code %s), want Unavailable", firstErr, status.Code(firstErr))
	}
	op, found, err := h.store.CodeSigningOperationByID(context.Background(), h.tenant, op.OperationID)
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
	op := submitQueuedCodeSigning(t, h, idempotencyKey, func(ctx context.Context) error {
		_, submitErr := h.srv.codeSign.SignCode(ctx, h.tenant, idempotencyKey, api.CodeSigningRequest{
			Principal: "release-bot", KeyID: "release-key", ArtifactType: "blob",
			Digest: crypto.SHA256Sum([]byte("policy-denied artifact")),
		})
		return submitErr
	})
	command := loadCodeSigningOutboxMessage(t, h.store, h.tenant, op.CommandOutboxID)
	if err := h.srv.obHandler.Deliver(context.Background(), command); err != nil {
		t.Fatalf("terminal policy delivery should be acknowledged after projection: %v", err)
	}
	op, found, err := h.store.CodeSigningOperationByID(context.Background(), h.tenant, op.OperationID)
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
	registerServedTenant(t, h, "code-signing policy approval tenant")
	gate := h.srv.codeSign.cfg.Gate
	if gate == nil {
		t.Fatal("production Build left the code-signing gate unwired")
	}
	allowed, reason := gate.MaySign(context.Background(), h.tenant, "release-bot", "release-key", digestHex)
	if !allowed {
		t.Fatalf("production policy gate denied the policy-authorized tuple before approval orchestration: %s", reason)
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
	if statusCode != http.StatusForbidden || !bytes.Contains(body, []byte("approval_required:codesign:")) {
		t.Fatalf("served approval denial = %d body=%s, want exact approval request", statusCode, body)
	}
	pending, err := h.store.ListOperationApprovals(context.Background(), h.tenant, store.ApprovalStatusPending, 10)
	if err != nil {
		t.Fatalf("list code-signing approval requests: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending code-signing approvals = %d, want 1: %+v", len(pending), pending)
	}
	approval := pending[0]
	requestHash, err := codeSigningCommandHash(codeSigningCommand{
		Mode: "key", Principal: "release-bot", KeyID: "release-key",
		ArtifactType: "oci-image", Digest: digest,
	})
	if err != nil {
		t.Fatal(err)
	}
	resource := store.CodeSigningApprovalResourceID(requestHash, "codesign-policy-approval-denied")
	idempotencyDigest := store.CodeSigningIdempotencyKeyDigest("codesign-policy-approval-denied")
	if approval.ResourceKind != "code_signing" || approval.ResourceID != resource ||
		approval.Action != codeSigningApprovalAction || approval.Requester != "release-bot" ||
		approval.TargetVersion != 0 || approval.RequiredApprovals != 1 ||
		!slices.Contains(approval.EvidenceRefs, "request-sha256:"+requestHash) ||
		!slices.Contains(approval.EvidenceRefs, "idempotency-key-sha256:"+idempotencyDigest) ||
		!slices.Contains(approval.EvidenceRefs, "artifact-sha256:"+digestHex) {
		t.Fatalf("exact code-signing approval binding = %+v, want resource %s", approval, resource)
	}
	var operationRows, commandRows int
	if err := h.store.SystemPool().QueryRow(context.Background(),
		`SELECT count(*) FROM code_signing_operations WHERE tenant_id = $1`, h.tenant).Scan(&operationRows); err != nil {
		t.Fatal(err)
	}
	if err := h.store.SystemPool().QueryRow(context.Background(),
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2`,
		h.tenant, store.CodeSigningCommandDestination).Scan(&commandRows); err != nil {
		t.Fatal(err)
	}
	if operationRows != 0 || commandRows != 0 {
		t.Fatalf("unapproved request persisted operation/outbox = %d/%d, want 0/0", operationRows, commandRows)
	}

	statusCode, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/approval-requests/"+approval.ID+"/approvals",
		approverToken, "codesign-policy-approval-grant", map[string]string{"intent_digest": approval.IntentDigest})
	if statusCode != http.StatusOK {
		t.Fatalf("served code-signing approval = %d body=%s", statusCode, body)
	}
	statusCode, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/code-signing/sign",
		requesterToken, "codesign-policy-approval-denied", request)
	if statusCode != http.StatusOK {
		_, directErr := h.srv.codeSign.SignCode(context.Background(), h.tenant,
			"codesign-policy-approval-denied", api.CodeSigningRequest{
				Principal: "release-bot", KeyID: "release-key", ArtifactType: "oci-image", Digest: digest,
			})
		t.Fatalf("served approved code-signing = %d body=%s direct retry error=%v", statusCode, body, directErr)
	}
	consumed, err := h.store.GetOperationApproval(context.Background(), h.tenant, approval.ID)
	if err != nil {
		t.Fatal(err)
	}
	if consumed.Status != store.ApprovalStatusConsumed || consumed.ConsumedEventID == "" || consumed.ConsumedAt == nil {
		t.Fatalf("executed code-signing authority was not consumed atomically: %+v", consumed)
	}
	if replayCode, replayBody := doBearer(t, h.ts, http.MethodPost, "/api/v1/code-signing/sign",
		requesterToken, "codesign-policy-approval-denied", request); replayCode != http.StatusOK || !bytes.Equal(replayBody, body) {
		t.Fatalf("approved code-signing replay = %d body=%s, want exact 200 body=%s", replayCode, replayBody, body)
	}
	secondKey := "codesign-policy-approval-second-use"
	secondResource := store.CodeSigningApprovalResourceID(requestHash, secondKey)
	if statusCode, secondBody := doBearer(t, h.ts, http.MethodPost, "/api/v1/code-signing/sign",
		requesterToken, secondKey, request); statusCode != http.StatusForbidden ||
		!bytes.Contains(secondBody, []byte("approval_required:"+secondResource)) {
		t.Fatalf("fresh-key approval request = %d body=%s, want 403 for new %s", statusCode, secondBody, secondResource)
	}
	second, err := h.store.ListOperationApprovals(context.Background(), h.tenant, store.ApprovalStatusPending, 10)
	if err != nil || len(second) != 1 || second[0].ResourceID != secondResource || second[0].ID == approval.ID {
		t.Fatalf("fresh idempotency key did not create distinct exact approval: rows=%+v err=%v", second, err)
	}
	if err := h.store.SystemPool().QueryRow(context.Background(),
		`SELECT count(*) FROM code_signing_operations WHERE tenant_id = $1`, h.tenant).Scan(&operationRows); err != nil {
		t.Fatal(err)
	}
	if err := h.store.SystemPool().QueryRow(context.Background(),
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2`,
		h.tenant, store.CodeSigningCommandDestination).Scan(&commandRows); err != nil {
		t.Fatal(err)
	}
	if operationRows != 1 || commandRows != 1 {
		t.Fatalf("single-use approval persisted operation/outbox = %d/%d, want 1/1", operationRows, commandRows)
	}
	if allowed, _ = gate.MaySign(context.Background(), h.tenant, "release-bot", "release-key", fmt.Sprintf("%x", crypto.SHA256Sum([]byte("different")))); allowed {
		t.Fatal("production policy gate allowed a different artifact digest")
	}
}

func TestRequiredCodeSigningApprovalRefusesLegacyUnapprovedQueuedCommand(t *testing.T) {
	inner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inner.Destroy)
	signer := &countingOperationSigner{DigestSigner: inner}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.RequireApproval = true
		d.RequiredApprovals = 1
		d.CodeSigning = CodeSigningConfig{
			Keys: codeSigningKeyMap{keys: map[string]crypto.DigestSigner{"release-key": signer}},
		}
	})
	const idempotencyKey = "codesign-legacy-unapproved-command"
	command := codeSigningCommand{
		Mode: "key", Principal: "release-bot", KeyID: "release-key",
		ArtifactType: "oci-image", Digest: crypto.SHA256Sum([]byte("legacy queued artifact")),
	}
	plain, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(plain)
	requestHash := crypto.SHA256Hex(plain)
	operationID := projections.LegacyCodeSigningOperationID(h.tenant, idempotencyKey)
	sealed, err := sealTenantValue(context.Background(), h.srv.codeSign.crypto, h.srv.codeSign.kek,
		h.tenant, plain, codeSigningCommandAAD(h.tenant, operationID, command.Mode, requestHash))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(sealed)
	if err := h.srv.codeSign.appendAndProject(context.Background(), h.tenant,
		projections.EventCodeSigningCommanded, operationID, projections.CodeSigningCommanded{
			OperationID: operationID, IdempotencyKey: idempotencyKey,
			Mode: command.Mode, RequestHash: requestHash, SealedCommand: sealed,
		}); err != nil {
		t.Fatalf("project legacy unapproved command: %v", err)
	}
	op, found, err := h.store.CodeSigningOperationByID(context.Background(), h.tenant, operationID)
	if err != nil || !found {
		t.Fatalf("load legacy queued command = found %v err %v", found, err)
	}
	message := loadCodeSigningOutboxMessage(t, h.store, h.tenant, op.CommandOutboxID)
	if err := h.srv.codeSign.deliverCommand(context.Background(), message); err != nil {
		t.Fatalf("deliver legacy unapproved command: %v", err)
	}
	op, found, err = h.store.CodeSigningOperationByID(context.Background(), h.tenant, operationID)
	if err != nil || !found {
		t.Fatalf("reload legacy queued command = found %v err %v", found, err)
	}
	if op.Status != "failed" || op.LastError != "policy_denied" || signer.calls.Load() != 0 {
		t.Fatalf("legacy unapproved command = status %q error %q signer calls %d, want failed/policy_denied/0",
			op.Status, op.LastError, signer.calls.Load())
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
	op := submitQueuedCodeSigning(t, h, idempotencyKey, func(ctx context.Context) error {
		_, submitErr := h.srv.codeSign.SignKeylessCode(ctx, h.tenant, idempotencyKey, api.CodeSigningKeylessRequest{
			Principal: "release-bot", ArtifactType: "oci-image",
			Digest:         crypto.SHA256Sum([]byte("keyless crash artifact")),
			IdentityMethod: "fulcio_fixture", IdentityPayload: []byte("short-lived-proof"),
		})
		return submitErr
	})
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
	op, found, err := h.store.CodeSigningOperationByID(context.Background(), h.tenant, op.OperationID)
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

// submitQueuedCodeSigning gives command append/projection its own bounded setup
// phase, then cancels only after the durable row is observable. A tiny request
// deadline makes these tests race the database under -race/-cover; merely making
// that deadline larger would keep the same timing bug.
func submitQueuedCodeSigning(
	t *testing.T,
	h *servedHarness,
	idempotencyKey string,
	submit func(context.Context) error,
) store.CodeSigningOperation {
	t.Helper()

	submitCtx, cancelSubmit := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelSubmit()
	result := make(chan error, 1)
	go func() { result <- submit(submitCtx) }()

	projectionCtx, cancelProjection := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelProjection()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		op, found, err := h.store.CodeSigningOperationByIdempotency(projectionCtx, h.tenant, idempotencyKey)
		if err != nil {
			t.Fatalf("load queued code-signing operation: %v", err)
		}
		if found {
			if op.Status != "queued" {
				t.Fatalf("code-signing operation reached %q without a dispatcher", op.Status)
			}
			cancelSubmit()
			returnCtx, cancelReturn := context.WithTimeout(context.Background(), time.Second)
			defer cancelReturn()
			select {
			case submitErr := <-result:
				if submitErr == nil {
					t.Fatal("queued code-signing request unexpectedly completed without a dispatcher")
				}
				if !errors.Is(submitErr, context.Canceled) {
					t.Fatalf("cancel queued code-signing wait: %v", submitErr)
				}
			case <-returnCtx.Done():
				t.Fatalf("queued code-signing request did not return after cancellation: %v", returnCtx.Err())
			}
			return op
		}

		select {
		case submitErr := <-result:
			if submitErr == nil {
				t.Fatal("code-signing request completed before its durable command was observable")
			}
			t.Fatalf("code-signing submission ended before command projection: %v", submitErr)
		case <-projectionCtx.Done():
			t.Fatalf("wait for queued code-signing projection: %v", projectionCtx.Err())
		case <-ticker.C:
		}
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
