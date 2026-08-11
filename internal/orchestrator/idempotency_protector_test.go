// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// recordingResultProtector is a test double, not cryptography. It binds its
// reversible envelope to the same tenant/key/request tuple that a real
// internal/crypto implementation must authenticate, so a row copied to another
// tenant cannot be opened.
type recordingResultProtector struct {
	mu       sync.Mutex
	protects int
	opens    int
}

type ownershipResultProtector struct {
	mu sync.Mutex

	protectCodec string
	protectErr   error
	openErr      error
	openValue    []byte
	protects     int
	opens        int

	lastProtectedOutput []byte
	lastOpenInput       []byte
	lastOpenOutput      []byte
}

func (p *ownershipResultProtector) Protect(_ context.Context, _, _, _ string, plaintext []byte) (string, []byte, error) {
	output := append([]byte("owned-protected\x00"), plaintext...)
	p.mu.Lock()
	p.protects++
	p.lastProtectedOutput = output
	codec := p.protectCodec
	err := p.protectErr
	p.mu.Unlock()
	if codec == "" {
		codec = orchestrator.ResultCodecSealedRowV1
	}
	return codec, output, err
}

func (p *ownershipResultProtector) Open(_ context.Context, _, _, _, _ string, protected []byte) ([]byte, error) {
	p.mu.Lock()
	p.opens++
	output := append([]byte(nil), p.openValue...)
	p.lastOpenInput = protected
	p.lastOpenOutput = output
	err := p.openErr
	p.mu.Unlock()
	return output, err
}

func (p *ownershipResultProtector) buffers() (protectedOutput, openInput, openOutput []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastProtectedOutput, p.lastOpenInput, p.lastOpenOutput
}

func (p *ownershipResultProtector) counts() (protects, opens int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.protects, p.opens
}

func requireWiped(t *testing.T, name string, value []byte) {
	t.Helper()
	if !bytes.Equal(value, make([]byte, len(value))) {
		t.Fatalf("%s retained bytes: %x", name, value)
	}
}

func TestPreparedDurableCompletedClaimVerifiesOpenedTerminalResultAUD113(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	protector := &recordingResultProtector{}
	idem := orchestrator.NewIdempotency(st, orchestrator.WithResultProtector(protector))
	const (
		key     = "aud113-completed-verify"
		binding = "sha256:aud113-completed-verify"
	)
	plaintext := []byte(`{"s":503,"b":{"system_error":"owned"},"h":"sha256:aud113-completed-verify"}`)
	codec, protected, err := protector.Protect(ctx, tenantA, key, binding, plaintext)
	if err != nil {
		t.Fatalf("protect completed prepared result: %v", err)
	}
	wantErr := errors.New("terminal receiver rejected restored bytes")
	verifyCalls := 0
	result, err := idem.DoPreparedDurableEffectBound(
		ctx, tenantA, key, binding,
		func(context.Context, pgx.Tx) (orchestrator.PreparedDurableEffectClaim, error) {
			return orchestrator.PreparedDurableEffectClaim{
				Completed: true, ResultCodec: codec,
				CompletedResult: append([]byte(nil), protected...),
			}, nil
		},
		func(_ context.Context, tx pgx.Tx, got []byte) error {
			verifyCalls++
			if tx == nil || !bytes.Equal(got, plaintext) {
				t.Fatalf("completed verifier tx=%v plaintext=%q, want transaction and %q", tx, got, plaintext)
			}
			return wantErr
		},
		func(context.Context) ([]byte, error) {
			t.Fatal("completed prepared replay executed effect callback")
			return nil, nil
		},
	)
	if !errors.Is(err, wantErr) || len(result) != 0 || verifyCalls != 1 {
		t.Fatalf("completed prepared replay result=%q err=%v verify_calls=%d, want empty/%v/1",
			result, err, verifyCalls, wantErr)
	}
}

func TestSchedulerPrivacyOuterResolverRekeysAndReprotectsInCallerTransaction(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	protector := &recordingResultProtector{}
	idem := orchestrator.NewIdempotency(st, orchestrator.WithResultProtector(protector))
	const (
		rawKey     = "scheduler:alice:outer"
		binding    = "sha256:scheduler-privacy-binding"
		statusCode = 200
	)
	authorityRef := strings.Repeat("a", 64)
	replacementKey := "privacy-scheduler:" + authorityRef
	originalBody := json.RawMessage(`{"ran":1,"result":"unchanged"}`)
	plaintext, err := json.Marshal(struct {
		Status  int             `json:"s"`
		Body    json.RawMessage `json:"b"`
		Binding string          `json:"h,omitempty"`
	}{Status: statusCode, Body: originalBody, Binding: binding})
	if err != nil {
		t.Fatal(err)
	}
	codec, protected, err := protector.Protect(ctx, tenantA, rawKey, binding, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO idempotency_keys
			        (tenant_id, key, status, request_binding, result_codec, result, completed_at)
			 VALUES ($1, $2, 'completed', $3, $4, $5, clock_timestamp())`,
			tenantA, rawKey, binding, codec, protected)
		return err
	}); err != nil {
		t.Fatalf("seed protected scheduler outer: %v", err)
	}

	requirement := store.SecretRotationSchedulePrivacyOuterRequirement{
		AuthorityRef: authorityRef, RequestBinding: binding, Status: "completed",
		ResultCodec: codec, ReplacementIdempotencyKey: replacementKey,
		RawKeyTokenMatch: true, TerminalBodyMatch: false,
		TerminalHTTPStatus: statusCode, OriginalTerminalBody: originalBody,
	}
	rollback := errors.New("simulate crash before privacy preparation commit")
	err = st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		ack, err := idem.ResolveSecretRotationSchedulePrivacyOuter(
			ctx, tx, tenantA, rawKey, requirement)
		if err != nil {
			return err
		}
		if ack.ResolvedIdempotencyKey != replacementKey ||
			ack.ResolvedResultCodec != orchestrator.ResultCodecSealedRowV1 ||
			len(ack.ProtectedResult) == 0 {
			t.Fatalf("same-tx scheduler privacy acknowledgement = %+v", ack)
		}
		var oldExists, newExists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM idempotency_keys WHERE tenant_id = $1 AND key = $2),
			        EXISTS (SELECT 1 FROM idempotency_keys WHERE tenant_id = $1 AND key = $3)`,
			tenantA, rawKey, replacementKey).Scan(&oldExists, &newExists); err != nil {
			return err
		}
		if oldExists || !newExists {
			t.Fatalf("same-tx rekey visibility old=%t new=%t", oldExists, newExists)
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("rollback simulation error = %v", err)
	}
	var oldExists, newExists bool
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM idempotency_keys WHERE tenant_id = $1 AND key = $2),
			        EXISTS (SELECT 1 FROM idempotency_keys WHERE tenant_id = $1 AND key = $3)`,
			tenantA, rawKey, replacementKey).Scan(&oldExists, &newExists)
	}); err != nil {
		t.Fatal(err)
	}
	if !oldExists || newExists {
		t.Fatalf("rolled-back scheduler rekey old=%t new=%t", oldExists, newExists)
	}

	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := idem.ResolveSecretRotationSchedulePrivacyOuter(
			ctx, tx, tenantA, rawKey, requirement)
		return err
	}); err != nil {
		t.Fatalf("commit scheduler privacy outer rekey: %v", err)
	}
	var resolvedCodec string
	var resolvedProtected []byte
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT result_codec, result FROM idempotency_keys
			  WHERE tenant_id = $1 AND key = $2`, tenantA, replacementKey).Scan(
			&resolvedCodec, &resolvedProtected)
	}); err != nil {
		t.Fatalf("load committed scheduler privacy outer: %v", err)
	}
	resolved, err := protector.Open(
		ctx, tenantA, replacementKey, binding, resolvedCodec, resolvedProtected)
	if err != nil {
		t.Fatalf("open rekeyed scheduler result: %v", err)
	}
	var cached struct {
		Status  int             `json:"s"`
		Body    json.RawMessage `json:"b"`
		Binding string          `json:"h,omitempty"`
	}
	if err := json.Unmarshal(resolved, &cached); err != nil {
		t.Fatal(err)
	}
	if cached.Status != statusCode || cached.Binding != binding ||
		!bytes.Equal(cached.Body, originalBody) {
		t.Fatalf("re-protected scheduler response = %+v", cached)
	}
}

func TestSchedulerPrivacyOuterResolverRekeysBoundReceiverWithoutInventingResult(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	idem := orchestrator.NewIdempotency(st, orchestrator.WithResultProtector(&recordingResultProtector{}))
	const (
		rawKey         = "scheduler:alice:bound-outer"
		binding        = "sha256:scheduler-bound-privacy-binding"
		authorityRef   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		replacementKey = "privacy-scheduler:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO idempotency_keys
			        (tenant_id, key, status, request_binding, result_codec)
			 VALUES ($1, $2, 'bound', $3, $4)`,
			tenantA, rawKey, binding, orchestrator.ResultCodecSealedRowV1)
		return err
	}); err != nil {
		t.Fatalf("seed bound scheduler outer: %v", err)
	}

	var acknowledgement store.SecretRotationSchedulePrivacyOuterAcknowledgement
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		var err error
		acknowledgement, err = idem.ResolveSecretRotationSchedulePrivacyOuter(
			ctx, tx, tenantA, rawKey, store.SecretRotationSchedulePrivacyOuterRequirement{
				AuthorityRef: authorityRef, RequestBinding: binding, Status: "bound",
				ResultCodec:               orchestrator.ResultCodecSealedRowV1,
				ReplacementIdempotencyKey: replacementKey, RawKeyTokenMatch: true,
			})
		return err
	}); err != nil {
		t.Fatalf("rekey bound scheduler privacy outer: %v", err)
	}
	if acknowledgement.ResolvedIdempotencyKey != replacementKey ||
		acknowledgement.ResolvedResultCodec != orchestrator.ResultCodecSealedRowV1 ||
		len(acknowledgement.ProtectedResult) != 0 {
		t.Fatalf("bound scheduler privacy acknowledgement = %+v", acknowledgement)
	}
	var oldExists, newExists bool
	var status, codec string
	var result []byte
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS (
			          SELECT 1 FROM idempotency_keys WHERE tenant_id = $1 AND key = $2
			        ), status, result_codec, result
			   FROM idempotency_keys
			  WHERE tenant_id = $1 AND key = $3`,
			tenantA, rawKey, replacementKey).Scan(&oldExists, &status, &codec, &result)
	}); err != nil {
		t.Fatalf("load rekeyed bound scheduler outer: %v", err)
	}
	newExists = status != ""
	if oldExists || !newExists || status != "bound" ||
		codec != orchestrator.ResultCodecSealedRowV1 || len(result) != 0 {
		t.Fatalf("bound scheduler privacy row old=%t new=%t status=%q codec=%q result=%x",
			oldExists, newExists, status, codec, result)
	}
}

func (p *recordingResultProtector) Protect(_ context.Context, tenantID, key, binding string, plaintext []byte) (string, []byte, error) {
	p.mu.Lock()
	p.protects++
	p.mu.Unlock()

	prefix := []byte("test-envelope-v1\x00" + tenantID + "\x00" + key + "\x00" + binding + "\x00")
	protected := make([]byte, len(prefix)+len(plaintext))
	copy(protected, prefix)
	for index := range plaintext {
		protected[len(prefix)+index] = plaintext[index] ^ 0xa5
	}
	return orchestrator.ResultCodecSealedRowV1, protected, nil
}

func (p *recordingResultProtector) Open(_ context.Context, tenantID, key, binding, codec string, protected []byte) ([]byte, error) {
	p.mu.Lock()
	p.opens++
	p.mu.Unlock()

	if codec != orchestrator.ResultCodecSealedRowV1 {
		return nil, fmt.Errorf("test protector: codec %q is not sealed-row-v1", codec)
	}
	prefix := []byte("test-envelope-v1\x00" + tenantID + "\x00" + key + "\x00" + binding + "\x00")
	if !bytes.HasPrefix(protected, prefix) {
		return nil, errors.New("test protector: authenticated tenant/key/binding context mismatch")
	}
	plaintext := make([]byte, len(protected)-len(prefix))
	for index := range plaintext {
		plaintext[index] = protected[len(prefix)+index] ^ 0xa5
	}
	return plaintext, nil
}

func (p *recordingResultProtector) counts() (protects, opens int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.protects, p.opens
}

func TestIdempotencyResultProtectorCoversEveryWriterAndReader(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	protector := &recordingResultProtector{}
	idem := orchestrator.NewIdempotency(s, orchestrator.WithResultProtector(protector))

	type idempotencyCase struct {
		name    string
		key     string
		binding string
		write   func(func(context.Context) ([]byte, error)) ([]byte, error)
		replay  func(func(context.Context) ([]byte, error)) ([]byte, error)
		read    func() ([]byte, error)
	}
	cases := []idempotencyCase{
		{
			name: "Do", key: "protected-do",
			write: func(fn func(context.Context) ([]byte, error)) ([]byte, error) {
				return idem.Do(ctx, tenantA, "protected-do", fn)
			},
			replay: func(fn func(context.Context) ([]byte, error)) ([]byte, error) {
				return idem.Do(ctx, tenantA, "protected-do", fn)
			},
			read: func() ([]byte, error) { return idem.Result(ctx, tenantA, "protected-do") },
		},
		{
			name: "DoBound", key: "protected-do-bound", binding: "sha256:do-bound-command",
			write: func(fn func(context.Context) ([]byte, error)) ([]byte, error) {
				return idem.DoBound(ctx, tenantA, "protected-do-bound", "sha256:do-bound-command", fn)
			},
			replay: func(fn func(context.Context) ([]byte, error)) ([]byte, error) {
				return idem.DoBound(ctx, tenantA, "protected-do-bound", "sha256:do-bound-command", fn)
			},
			read: func() ([]byte, error) {
				return idem.BoundResult(ctx, tenantA, "protected-do-bound", "sha256:do-bound-command")
			},
		},
		{
			name: "DoDurableEffect", key: "protected-durable",
			write: func(fn func(context.Context) ([]byte, error)) ([]byte, error) {
				return idem.DoDurableEffect(ctx, tenantA, "protected-durable", fn)
			},
			replay: func(fn func(context.Context) ([]byte, error)) ([]byte, error) {
				return idem.DoDurableEffect(ctx, tenantA, "protected-durable", fn)
			},
			read: func() ([]byte, error) { return idem.Result(ctx, tenantA, "protected-durable") },
		},
		{
			name: "DoDurableEffectBound", key: "protected-durable-bound", binding: "sha256:durable-bound-command",
			write: func(fn func(context.Context) ([]byte, error)) ([]byte, error) {
				return idem.DoDurableEffectBound(ctx, tenantA, "protected-durable-bound", "sha256:durable-bound-command", fn)
			},
			replay: func(fn func(context.Context) ([]byte, error)) ([]byte, error) {
				return idem.DoDurableEffectBound(ctx, tenantA, "protected-durable-bound", "sha256:durable-bound-command", fn)
			},
			read: func() ([]byte, error) {
				return idem.BoundResult(ctx, tenantA, "protected-durable-bound", "sha256:durable-bound-command")
			},
		},
		{
			name: "DoAtMostOnceEffect", key: "protected-at-most-once",
			write: func(fn func(context.Context) ([]byte, error)) ([]byte, error) {
				return idem.DoAtMostOnceEffect(ctx, tenantA, "protected-at-most-once", fn)
			},
			replay: func(fn func(context.Context) ([]byte, error)) ([]byte, error) {
				return idem.DoAtMostOnceEffect(ctx, tenantA, "protected-at-most-once", fn)
			},
			read: func() ([]byte, error) { return idem.Result(ctx, tenantA, "protected-at-most-once") },
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			plaintext := []byte("credential-bearing-result-" + test.name)
			first, err := test.write(func(context.Context) ([]byte, error) {
				return append([]byte(nil), plaintext...), nil
			})
			if err != nil || !bytes.Equal(first, plaintext) {
				t.Fatalf("first result=%q err=%v, want plaintext result", first, err)
			}

			var codec string
			var stored []byte
			if err := s.SystemPool().QueryRow(ctx, `
				SELECT result_codec, result
				  FROM idempotency_keys
				 WHERE tenant_id = $1 AND key = $2`,
				tenantA, test.key).Scan(&codec, &stored); err != nil {
				t.Fatalf("inspect protected row: %v", err)
			}
			if codec != orchestrator.ResultCodecSealedRowV1 {
				t.Fatalf("result_codec=%q, want %q", codec, orchestrator.ResultCodecSealedRowV1)
			}
			if bytes.Equal(stored, plaintext) || bytes.Contains(stored, plaintext) {
				t.Fatalf("database result contains plaintext: stored=%q plaintext=%q", stored, plaintext)
			}

			replayed, err := test.replay(func(context.Context) ([]byte, error) {
				t.Fatal("completed replay executed callback")
				return nil, nil
			})
			if err != nil || !bytes.Equal(replayed, plaintext) {
				t.Fatalf("replay result=%q err=%v, want opened plaintext", replayed, err)
			}
			read, err := test.read()
			if err != nil || !bytes.Equal(read, plaintext) {
				t.Fatalf("explicit read result=%q err=%v, want opened plaintext", read, err)
			}
		})
	}

	protects, opens := protector.counts()
	if protects != len(cases) {
		t.Fatalf("Protect calls=%d, want one for each of %d result writers", protects, len(cases))
	}
	if opens != 2*len(cases) {
		t.Fatalf("Open calls=%d, want replay + explicit read for each of %d methods", opens, len(cases))
	}
}

// TestBoundResultCompletedChecksTheWallWithoutOpeningResultBytes pins the seal
// worker prerequisite. The worker needs to know that the accepted response is
// durable, but it must not decrypt that response or borrow tenant key material
// merely to check a status bit.
func TestBoundResultCompletedChecksTheWallWithoutOpeningResultBytes(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	protector := &ownershipResultProtector{
		openErr: errors.New("result bytes must not be opened by completion check"),
	}
	idem := orchestrator.NewIdempotency(s, orchestrator.WithResultProtector(protector))
	const key = "seal-result-wall"
	const binding = "sha256:seal-result-wall"
	if _, err := idem.DoDurableEffectBound(ctx, tenantA, key, binding, func(context.Context) ([]byte, error) {
		return []byte(`{"accepted":true}`), nil
	}); err != nil {
		t.Fatalf("write completed bound result: %v", err)
	}

	completed, err := idem.BoundResultCompleted(ctx, tenantA, key, binding)
	if err != nil || !completed {
		t.Fatalf("BoundResultCompleted = %v/%v, want true/nil", completed, err)
	}
	if _, opens := protector.counts(); opens != 0 {
		t.Fatalf("completion check opened protected result %d times", opens)
	}
	if _, err := idem.BoundResultCompleted(ctx, tenantA, key, binding+"-other"); !errors.Is(err, orchestrator.ErrIdempotencyConflict) {
		t.Fatalf("mismatched binding error = %v, want conflict", err)
	}
}

func TestBoundResultChecksBindingBeforeOpeningProtectedBytes(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	protector := &recordingResultProtector{}
	idem := orchestrator.NewIdempotency(s, orchestrator.WithResultProtector(protector))

	const (
		key          = "binding-before-open"
		binding      = "sha256:authenticated-command"
		otherBinding = "sha256:other-authenticated-command"
	)
	if _, err := idem.DoBound(ctx, tenantA, key, binding, func(context.Context) ([]byte, error) {
		return []byte("credential-sentinel"), nil
	}); err != nil {
		t.Fatal(err)
	}
	_, opensBefore := protector.counts()

	if result, err := idem.BoundResult(ctx, tenantA, key, otherBinding); !errors.Is(err, orchestrator.ErrIdempotencyConflict) || len(result) != 0 {
		t.Fatalf("mismatched BoundResult result=%q err=%v, want empty conflict", result, err)
	}
	if result, err := idem.DoBound(ctx, tenantA, key, otherBinding, func(context.Context) ([]byte, error) {
		t.Fatal("mismatched DoBound executed callback")
		return nil, nil
	}); !errors.Is(err, orchestrator.ErrIdempotencyConflict) || len(result) != 0 {
		t.Fatalf("mismatched DoBound result=%q err=%v, want empty conflict", result, err)
	}
	_, opensAfter := protector.counts()
	if opensAfter != opensBefore {
		t.Fatalf("mismatched binding called Open %d times; binding must be checked before protected bytes are read/opened", opensAfter-opensBefore)
	}
}

func TestProtectedIdempotencyResultRejectsCrossTenantRowSwap(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	protector := &recordingResultProtector{}
	idem := orchestrator.NewIdempotency(s, orchestrator.WithResultProtector(protector))
	const key = "same-key-in-both-tenants"

	for tenantID, plaintext := range map[string]string{
		tenantA: "tenant-a-credential",
		tenantB: "tenant-b-credential",
	} {
		if _, err := idem.Do(ctx, tenantID, key, func(context.Context) ([]byte, error) {
			return []byte(plaintext), nil
		}); err != nil {
			t.Fatalf("write %s: %v", tenantID, err)
		}
	}

	var resultA, resultB []byte
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT result FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`,
		tenantA, key).Scan(&resultA); err != nil {
		t.Fatal(err)
	}
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT result FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`,
		tenantB, key).Scan(&resultB); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE idempotency_keys
		    SET result = CASE tenant_id WHEN $1::uuid THEN $3::bytea ELSE $4::bytea END
		  WHERE key = $2 AND tenant_id IN ($1::uuid, $5::uuid)`,
		tenantA, key, resultB, resultA, tenantB); err != nil {
		t.Fatalf("swap protected rows: %v", err)
	}

	for _, tenantID := range []string{tenantA, tenantB} {
		result, err := idem.Result(ctx, tenantID, key)
		if err == nil || len(result) != 0 {
			t.Fatalf("cross-tenant swapped result for %s=%q err=%v, want fail-closed open error", tenantID, result, err)
		}
	}
}

func TestNoProtectorKeepsHistoricalDynamicLeaseEnvelopeOpaque(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	idem := orchestrator.NewIdempotency(s)
	const (
		key     = "historical-dynamic-envelope"
		binding = "sha256:historical-dynamic-command"
	)
	envelope := append([]byte{'C', 'S', 'L', '1', 1}, []byte("already-sealed-by-dynamic-api")...)
	if _, err := s.SystemPool().Exec(ctx, `
		INSERT INTO idempotency_keys
		       (tenant_id, key, status, request_binding, result_codec, result, completed_at)
		VALUES ($1, $2, 'completed', $3, $4, $5, now())`,
		tenantA, key, binding, orchestrator.ResultCodecSealedDynamicLeaseV1, envelope); err != nil {
		t.Fatalf("seed historical dynamic envelope: %v", err)
	}

	got, err := idem.BoundResult(ctx, tenantA, key, binding)
	if err != nil {
		t.Fatalf("read historical dynamic envelope: %v", err)
	}
	if !bytes.Equal(got, envelope) {
		t.Fatalf("historical dynamic envelope changed: got=%x want=%x", got, envelope)
	}
}

func TestNoProtectorLabelsIntermediateWritesRawV0(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	idem := orchestrator.NewIdempotency(s)
	const key = "explicit-raw-compatibility"

	if _, err := idem.Do(ctx, tenantA, key, func(context.Context) ([]byte, error) {
		return []byte("compatibility-result"), nil
	}); err != nil {
		t.Fatalf("write compatibility result: %v", err)
	}
	var codec string
	if err := s.SystemPool().QueryRow(ctx, `
		SELECT result_codec
		  FROM idempotency_keys
		 WHERE tenant_id = $1 AND key = $2`,
		tenantA, key).Scan(&codec); err != nil {
		t.Fatalf("read compatibility codec: %v", err)
	}
	if codec != orchestrator.ResultCodecRawV0 {
		t.Fatalf("no-protector result_codec=%q, want explicit raw-v0", codec)
	}
}

func TestMemoryResultProtectorCopiesThenWipesTransferredBuffers(t *testing.T) {
	want := []byte("credential-bearing-memory-result")
	protector := &ownershipResultProtector{openValue: want}
	idem := orchestrator.NewMemoryIdempotency(orchestrator.WithResultProtector(protector))
	callbackResult := append([]byte(nil), want...)

	first, err := idem.Do(context.Background(), "tenant-a", "owned-buffer", func(context.Context) ([]byte, error) {
		return callbackResult, nil
	})
	if err != nil || !bytes.Equal(first, want) {
		t.Fatalf("first result=%q err=%v, want copied plaintext", first, err)
	}
	requireWiped(t, "callback-owned plaintext", callbackResult)
	protectedOutput, _, _ := protector.buffers()
	requireWiped(t, "protector-owned protected output", protectedOutput)

	replayed, err := idem.Do(context.Background(), "tenant-a", "owned-buffer", func(context.Context) ([]byte, error) {
		t.Fatal("completed memory replay executed callback")
		return nil, nil
	})
	if err != nil || !bytes.Equal(replayed, want) {
		t.Fatalf("replay result=%q err=%v, want opened plaintext", replayed, err)
	}
	_, openInput, openOutput := protector.buffers()
	requireWiped(t, "owned protected replay input", openInput)
	requireWiped(t, "protector-owned opened plaintext", openOutput)
}

func TestProtectorFailureWipesPartialOutputsAndCallbackResult(t *testing.T) {
	injected := errors.New("injected protector failure")
	protector := &ownershipResultProtector{
		protectErr: injected,
		openValue:  []byte("partial-open-plaintext"),
	}
	idem := orchestrator.NewMemoryIdempotency(orchestrator.WithResultProtector(protector))
	callbackResult := []byte("credential-bearing-failed-result")

	result, err := idem.Do(context.Background(), "tenant-a", "protect-failure", func(context.Context) ([]byte, error) {
		return callbackResult, nil
	})
	if !errors.Is(err, injected) || len(result) != 0 {
		t.Fatalf("protect failure result=%q err=%v, want empty wrapped failure", result, err)
	}
	requireWiped(t, "failed callback-owned plaintext", callbackResult)
	protectedOutput, _, _ := protector.buffers()
	requireWiped(t, "partial protected error output", protectedOutput)
}

func TestTransactionalProtectFailureLeavesIndeterminateWallInMemoryAndPostgres(t *testing.T) {
	injected := errors.New("injected protector failure")
	type operation struct {
		name    string
		binding string
		call    func(*orchestrator.Idempotency, context.Context, string, func(context.Context) ([]byte, error)) ([]byte, error)
		read    func(*orchestrator.Idempotency, context.Context, string) ([]byte, error)
	}
	operations := []operation{
		{
			name: "Do",
			call: func(idem *orchestrator.Idempotency, ctx context.Context, key string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
				return idem.Do(ctx, tenantA, key, fn)
			},
			read: func(idem *orchestrator.Idempotency, ctx context.Context, key string) ([]byte, error) {
				return idem.Result(ctx, tenantA, key)
			},
		},
		{
			name:    "DoBound",
			binding: "sha256:protected-failure-command",
			call: func(idem *orchestrator.Idempotency, ctx context.Context, key string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
				return idem.DoBound(ctx, tenantA, key, "sha256:protected-failure-command", fn)
			},
			read: func(idem *orchestrator.Idempotency, ctx context.Context, key string) ([]byte, error) {
				return idem.BoundResult(ctx, tenantA, key, "sha256:protected-failure-command")
			},
		},
	}
	backends := []struct {
		name string
		new  func(*testing.T, *ownershipResultProtector) *orchestrator.Idempotency
	}{
		{
			name: "memory",
			new: func(_ *testing.T, protector *ownershipResultProtector) *orchestrator.Idempotency {
				return orchestrator.NewMemoryIdempotency(orchestrator.WithResultProtector(protector))
			},
		},
		{
			name: "postgres",
			new: func(t *testing.T, protector *ownershipResultProtector) *orchestrator.Idempotency {
				return orchestrator.NewIdempotency(newStore(t), orchestrator.WithResultProtector(protector))
			},
		},
	}

	for _, backend := range backends {
		t.Run(backend.name, func(t *testing.T) {
			for _, op := range operations {
				t.Run(op.name, func(t *testing.T) {
					protector := &ownershipResultProtector{protectErr: injected}
					idem := backend.new(t, protector)
					key := "protected-post-success-failure-" + backend.name + "-" + op.name
					calls := 0
					callback := func(context.Context) ([]byte, error) {
						calls++
						return []byte("effect-already-succeeded"), nil
					}

					result, err := op.call(idem, context.Background(), key, callback)
					if !errors.Is(err, orchestrator.ErrEffectIndeterminate) || !errors.Is(err, injected) || len(result) != 0 {
						t.Fatalf("first result=%q err=%v, want empty ErrEffectIndeterminate wrapping Protect failure", result, err)
					}
					result, err = op.call(idem, context.Background(), key, callback)
					if !errors.Is(err, orchestrator.ErrEffectIndeterminate) || len(result) != 0 {
						t.Fatalf("retry result=%q err=%v, want empty ErrEffectIndeterminate", result, err)
					}
					if calls != 1 {
						t.Fatalf("callback calls=%d, want exactly one after successful effect + Protect failure", calls)
					}
					if result, err = op.read(idem, context.Background(), key); !errors.Is(err, orchestrator.ErrEffectIndeterminate) || len(result) != 0 {
						t.Fatalf("explicit read result=%q err=%v, want empty ErrEffectIndeterminate", result, err)
					}

					if op.binding != "" {
						changedCalled := false
						result, err = idem.DoBound(context.Background(), tenantA, key, "sha256:different-command", func(context.Context) ([]byte, error) {
							changedCalled = true
							return []byte("must-not-run"), nil
						})
						if !errors.Is(err, orchestrator.ErrIdempotencyConflict) || changedCalled || len(result) != 0 {
							t.Fatalf("changed binding result=%q err=%v callback=%v, want conflict before callback/bytes", result, err, changedCalled)
						}
					}
					if protects, opens := protector.counts(); protects != 1 || opens != 0 {
						t.Fatalf("protector calls Protect/Open=%d/%d, want 1/0 after failed write and blocked retries", protects, opens)
					}
				})
			}
		})
	}
}

func TestConfiguredProtectorKeepsCallbackErrorsRetryable(t *testing.T) {
	backends := []struct {
		name string
		new  func(*testing.T, *recordingResultProtector) *orchestrator.Idempotency
	}{
		{
			name: "memory",
			new: func(_ *testing.T, protector *recordingResultProtector) *orchestrator.Idempotency {
				return orchestrator.NewMemoryIdempotency(orchestrator.WithResultProtector(protector))
			},
		},
		{
			name: "postgres",
			new: func(t *testing.T, protector *recordingResultProtector) *orchestrator.Idempotency {
				return orchestrator.NewIdempotency(newStore(t), orchestrator.WithResultProtector(protector))
			},
		},
	}
	for _, backend := range backends {
		t.Run(backend.name, func(t *testing.T) {
			protector := &recordingResultProtector{}
			idem := backend.new(t, protector)
			key := "protected-callback-retry-" + backend.name
			calls := 0
			callback := func(context.Context) ([]byte, error) {
				calls++
				if calls == 1 {
					return []byte("partial-callback-output"), errors.New("transient callback failure")
				}
				return []byte("successful-retry"), nil
			}
			if result, err := idem.DoBound(context.Background(), tenantA, key, "sha256:retryable-command", callback); err == nil || len(result) != 0 {
				t.Fatalf("first callback failure result=%q err=%v, want empty error", result, err)
			}
			result, err := idem.DoBound(context.Background(), tenantA, key, "sha256:retryable-command", callback)
			if err != nil || string(result) != "successful-retry" {
				t.Fatalf("retry result=%q err=%v, want successful-retry", result, err)
			}
			replay, err := idem.DoBound(context.Background(), tenantA, key, "sha256:retryable-command", func(context.Context) ([]byte, error) {
				t.Fatal("completed replay executed callback")
				return nil, nil
			})
			if err != nil || string(replay) != "successful-retry" || calls != 2 {
				t.Fatalf("replay=%q err=%v callback calls=%d, want cached result and two total attempts", replay, err, calls)
			}
		})
	}
}

func TestMemoryDurableBoundReceiverConflictReleasesFreshClaim(t *testing.T) {
	idem := orchestrator.NewMemoryIdempotency()
	ctx := context.Background()
	const (
		tenantID        = "11111111-1111-1111-1111-111111111111"
		key             = "privacy-erasure-after-generic-cache-gc"
		changedBinding  = "sha256:changed-command"
		originalBinding = "sha256:canonical-command"
	)

	if result, err := idem.DoDurableEffectBound(
		ctx, tenantID, key, changedBinding,
		func(context.Context) ([]byte, error) {
			return nil, orchestrator.ErrIdempotencyConflict
		},
	); !errors.Is(err, orchestrator.ErrIdempotencyConflict) || len(result) != 0 {
		t.Fatalf("changed receiver result=%q err=%v, want empty ErrIdempotencyConflict", result, err)
	}

	calls := 0
	result, err := idem.DoDurableEffectBound(
		ctx, tenantID, key, originalBinding,
		func(context.Context) ([]byte, error) {
			calls++
			return []byte("canonical-response"), nil
		},
	)
	if err != nil {
		t.Fatalf("canonical recovery after receiver conflict: %v", err)
	}
	if string(result) != "canonical-response" || calls != 1 {
		t.Fatalf("canonical recovery result=%q calls=%d, want canonical-response/1", result, calls)
	}
}

// TestProtectedPreclaimExecutionGapBarrierNeverExecutesOrPromotes seeds the
// exact durable state visible while an owner is between its committed preclaim
// and execution-row lock. This is a deterministic barrier proof: an observer
// cannot infer owner death, run the callback, or promote the row.
func TestProtectedPreclaimExecutionGapBarrierNeverExecutesOrPromotes(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	const (
		key     = "protected-preclaim-execution-gap"
		binding = "sha256:gap-command"
	)
	if _, err := s.SystemPool().Exec(ctx, `
		INSERT INTO idempotency_keys (tenant_id, key, status, request_binding)
		VALUES ($1, $2, 'pending', $3)`,
		tenantA, key, binding); err != nil {
		t.Fatalf("seed committed preclaim: %v", err)
	}
	protector := &recordingResultProtector{}
	idem := orchestrator.NewIdempotency(s, orchestrator.WithResultProtector(protector))
	called := false
	result, err := idem.DoBound(ctx, tenantA, key, binding, func(context.Context) ([]byte, error) {
		called = true
		return []byte("must-not-run"), nil
	})
	if !errors.Is(err, orchestrator.ErrInProgress) || called || len(result) != 0 {
		t.Fatalf("pending-gap result=%q err=%v callback=%v, want unchanged ErrInProgress wall", result, err, called)
	}
	var status string
	if err := s.SystemPool().QueryRow(ctx,
		`SELECT status FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`,
		tenantA, key).Scan(&status); err != nil {
		t.Fatalf("read gap status: %v", err)
	}
	if status != "pending" {
		t.Fatalf("gap status=%q, want pending; observer must not infer owner death", status)
	}
	if protects, opens := protector.counts(); protects != 0 || opens != 0 {
		t.Fatalf("pending gap called Protect/Open=%d/%d, want 0/0", protects, opens)
	}
}

func TestProtectedCompletionStoreFailureLeavesIndeterminateWall(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	const (
		triggerName  = "test_fail_protected_idempotency_completion"
		functionName = "test_fail_protected_idempotency_completion_fn"
		keyPrefix    = "test-protected-completion-failure-"
	)
	dropFailureTrigger := func() {
		_, _ = s.SystemPool().Exec(context.Background(), "DROP TRIGGER IF EXISTS "+triggerName+" ON idempotency_keys")
		_, _ = s.SystemPool().Exec(context.Background(), "DROP FUNCTION IF EXISTS "+functionName+"()")
	}
	dropFailureTrigger()
	t.Cleanup(dropFailureTrigger)
	if _, err := s.SystemPool().Exec(ctx, `
		CREATE FUNCTION `+functionName+`() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.status = 'completed' AND NEW.key LIKE '`+keyPrefix+`%' THEN
				RAISE EXCEPTION 'injected protected result completion failure';
			END IF;
			RETURN NEW;
		END
		$$`); err != nil {
		t.Fatalf("create completion failure function: %v", err)
	}
	if _, err := s.SystemPool().Exec(ctx,
		"CREATE TRIGGER "+triggerName+" BEFORE UPDATE ON idempotency_keys FOR EACH ROW EXECUTE FUNCTION "+functionName+"()"); err != nil {
		t.Fatalf("create completion failure trigger: %v", err)
	}

	type operation struct {
		name    string
		binding string
		call    func(*orchestrator.Idempotency, string, func(context.Context) ([]byte, error)) ([]byte, error)
		read    func(*orchestrator.Idempotency, string) ([]byte, error)
	}
	operations := []operation{
		{
			name: "Do",
			call: func(idem *orchestrator.Idempotency, key string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
				return idem.Do(context.Background(), tenantA, key, fn)
			},
			read: func(idem *orchestrator.Idempotency, key string) ([]byte, error) {
				return idem.Result(context.Background(), tenantA, key)
			},
		},
		{
			name:    "DoBound",
			binding: "sha256:completion-failure-command",
			call: func(idem *orchestrator.Idempotency, key string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
				return idem.DoBound(context.Background(), tenantA, key, "sha256:completion-failure-command", fn)
			},
			read: func(idem *orchestrator.Idempotency, key string) ([]byte, error) {
				return idem.BoundResult(context.Background(), tenantA, key, "sha256:completion-failure-command")
			},
		},
	}
	protector := &recordingResultProtector{}
	idem := orchestrator.NewIdempotency(s, orchestrator.WithResultProtector(protector))
	for _, op := range operations {
		t.Run(op.name, func(t *testing.T) {
			key := keyPrefix + op.name
			calls := 0
			callback := func(context.Context) ([]byte, error) {
				calls++
				return []byte("effect-committed-before-result-store"), nil
			}
			result, err := op.call(idem, key, callback)
			if !errors.Is(err, orchestrator.ErrEffectIndeterminate) || len(result) != 0 {
				t.Fatalf("completion failure result=%q err=%v, want ErrEffectIndeterminate", result, err)
			}
			var status string
			if err := s.SystemPool().QueryRow(ctx,
				`SELECT status FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`,
				tenantA, key).Scan(&status); err != nil {
				t.Fatalf("read completion failure status: %v", err)
			}
			if status != "indeterminate" {
				t.Fatalf("completion failure status=%q, want indeterminate", status)
			}
			if result, err = op.call(idem, key, callback); !errors.Is(err, orchestrator.ErrEffectIndeterminate) || len(result) != 0 {
				t.Fatalf("completion failure retry result=%q err=%v, want ErrEffectIndeterminate", result, err)
			}
			if calls != 1 {
				t.Fatalf("callback calls=%d, want one across failed completion + retry", calls)
			}
			if result, err = op.read(idem, key); !errors.Is(err, orchestrator.ErrEffectIndeterminate) || len(result) != 0 {
				t.Fatalf("completion failure read result=%q err=%v, want ErrEffectIndeterminate", result, err)
			}
			if op.binding != "" {
				changedCalled := false
				result, err = idem.DoBound(context.Background(), tenantA, key, "sha256:different-completion-command", func(context.Context) ([]byte, error) {
					changedCalled = true
					return []byte("must-not-run"), nil
				})
				if !errors.Is(err, orchestrator.ErrIdempotencyConflict) || changedCalled || len(result) != 0 {
					t.Fatalf("completion failure binding collision result=%q err=%v callback=%v", result, err, changedCalled)
				}
			}
		})
	}
	if protects, opens := protector.counts(); protects != len(operations) || opens != 0 {
		t.Fatalf("completion failures Protect/Open=%d/%d, want %d/0", protects, opens, len(operations))
	}
}

func TestProtectedDoBoundConcurrentSameBindingStillWaitsAndReplays(t *testing.T) {
	backends := []struct {
		name string
		new  func(*testing.T, *recordingResultProtector) *orchestrator.Idempotency
	}{
		{
			name: "memory",
			new: func(_ *testing.T, protector *recordingResultProtector) *orchestrator.Idempotency {
				return orchestrator.NewMemoryIdempotency(orchestrator.WithResultProtector(protector))
			},
		},
		{
			name: "postgres",
			new: func(t *testing.T, protector *recordingResultProtector) *orchestrator.Idempotency {
				return orchestrator.NewIdempotency(newStore(t), orchestrator.WithResultProtector(protector))
			},
		},
	}
	type outcome struct {
		result []byte
		err    error
	}
	for _, backend := range backends {
		t.Run(backend.name, func(t *testing.T) {
			protector := &recordingResultProtector{}
			idem := backend.new(t, protector)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var calls atomic.Int32
			entered := make(chan struct{})
			release := make(chan struct{})
			callback := func(context.Context) ([]byte, error) {
				if calls.Add(1) == 1 {
					close(entered)
					<-release
				}
				return []byte("protected-single-flight-result"), nil
			}
			firstDone := make(chan outcome, 1)
			go func() {
				result, err := idem.DoBound(ctx, tenantA, "protected-single-flight-"+backend.name, "sha256:same-command", callback)
				firstDone <- outcome{result: result, err: err}
			}()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatalf("protected owner did not enter callback: %v", ctx.Err())
			}
			secondDone := make(chan outcome, 1)
			go func() {
				result, err := idem.DoBound(ctx, tenantA, "protected-single-flight-"+backend.name, "sha256:same-command", callback)
				secondDone <- outcome{result: result, err: err}
			}()
			select {
			case early := <-secondDone:
				close(release)
				t.Fatalf("concurrent retry returned before owner completed: result=%q err=%v", early.result, early.err)
			case <-time.After(100 * time.Millisecond):
			}
			close(release)
			first := <-firstDone
			second := <-secondDone
			if first.err != nil || second.err != nil ||
				string(first.result) != "protected-single-flight-result" ||
				string(second.result) != "protected-single-flight-result" {
				t.Fatalf("single-flight first=%q/%v second=%q/%v", first.result, first.err, second.result, second.err)
			}
			if calls.Load() != 1 {
				t.Fatalf("protected concurrent callback calls=%d, want 1", calls.Load())
			}
		})
	}
}

func TestOpenFailureWipesProtectedInputAndPartialPlaintext(t *testing.T) {
	injected := errors.New("injected open failure")
	protector := &ownershipResultProtector{
		openValue: []byte("partial-open-plaintext"),
	}
	idem := orchestrator.NewMemoryIdempotency(orchestrator.WithResultProtector(protector))
	if _, err := idem.Do(context.Background(), "tenant-a", "open-failure", func(context.Context) ([]byte, error) {
		return []byte("original-result"), nil
	}); err != nil {
		t.Fatalf("seed protected result: %v", err)
	}
	protector.mu.Lock()
	protector.openErr = injected
	protector.mu.Unlock()

	result, err := idem.Result(context.Background(), "tenant-a", "open-failure")
	if !errors.Is(err, injected) || len(result) != 0 {
		t.Fatalf("open failure result=%q err=%v, want empty wrapped failure", result, err)
	}
	_, openInput, openOutput := protector.buffers()
	requireWiped(t, "protected input on open error", openInput)
	requireWiped(t, "partial plaintext on open error", openOutput)
}

func TestConfiguredProtectorCannotWriteMigrationOnlyCodec(t *testing.T) {
	for _, codec := range []string{
		orchestrator.ResultCodecRawV0,
		orchestrator.ResultCodecSealedDynamicLeaseV1,
	} {
		t.Run(codec, func(t *testing.T) {
			protector := &ownershipResultProtector{protectCodec: codec}
			idem := orchestrator.NewMemoryIdempotency(orchestrator.WithResultProtector(protector))
			callbackResult := []byte("must-not-be-retained-under-migration-codec")
			result, err := idem.Do(context.Background(), "tenant-a", "migration-codec-"+codec, func(context.Context) ([]byte, error) {
				return callbackResult, nil
			})
			if err == nil || len(result) != 0 {
				t.Fatalf("codec %q write result=%q err=%v, want fail-closed", codec, result, err)
			}
			requireWiped(t, "migration-codec callback result", callbackResult)
			protectedOutput, _, _ := protector.buffers()
			requireWiped(t, "migration-codec protector output", protectedOutput)
		})
	}
}

func TestAtMostOnceProtectFailureStaysIndeterminateInMemoryAndPostgres(t *testing.T) {
	tests := []struct {
		name string
		new  func(*ownershipResultProtector) *orchestrator.Idempotency
	}{
		{
			name: "memory",
			new: func(protector *ownershipResultProtector) *orchestrator.Idempotency {
				return orchestrator.NewMemoryIdempotency(orchestrator.WithResultProtector(protector))
			},
		},
		{
			name: "postgres",
			new: func(protector *ownershipResultProtector) *orchestrator.Idempotency {
				return orchestrator.NewIdempotency(newStore(t), orchestrator.WithResultProtector(protector))
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			protector := &ownershipResultProtector{protectErr: errors.New("injected seal failure")}
			idem := test.new(protector)
			calls := 0
			var callbackResult []byte
			call := func(context.Context) ([]byte, error) {
				calls++
				callbackResult = []byte("non-replay-safe-external-result")
				return callbackResult, nil
			}
			if result, err := idem.DoAtMostOnceEffect(context.Background(), tenantA, "protect-failed-at-most-once", call); !errors.Is(err, orchestrator.ErrEffectIndeterminate) || len(result) != 0 {
				t.Fatalf("first result=%q err=%v, want ErrEffectIndeterminate", result, err)
			}
			requireWiped(t, "at-most-once callback result", callbackResult)
			if result, err := idem.DoAtMostOnceEffect(context.Background(), tenantA, "protect-failed-at-most-once", call); !errors.Is(err, orchestrator.ErrEffectIndeterminate) || len(result) != 0 {
				t.Fatalf("replay result=%q err=%v, want ErrEffectIndeterminate", result, err)
			}
			if calls != 1 {
				t.Fatalf("external callback calls=%d, want exactly one after protection failure", calls)
			}
		})
	}
}
