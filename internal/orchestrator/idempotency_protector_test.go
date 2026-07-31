// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/orchestrator"
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

	lastProtectedOutput []byte
	lastOpenInput       []byte
	lastOpenOutput      []byte
}

func (p *ownershipResultProtector) Protect(_ context.Context, _, _, _ string, plaintext []byte) (string, []byte, error) {
	output := append([]byte("owned-protected\x00"), plaintext...)
	p.mu.Lock()
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

func requireWiped(t *testing.T, name string, value []byte) {
	t.Helper()
	if !bytes.Equal(value, make([]byte, len(value))) {
		t.Fatalf("%s retained bytes: %x", name, value)
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
