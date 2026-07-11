// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
)

const mutationBindingSecretSentinel = "credential-sentinel-must-never-cross-binding"

func mutationBindingRequest(subject, method, path string) *http.Request {
	const tenantID = "11111111-1111-1111-1111-111111111111"
	req := httptest.NewRequest(method, path, nil)
	principal := authz.Principal{TenantID: tenantID, Subject: subject}
	return req.WithContext(context.WithValue(req.Context(), principalCtxKey, principal))
}

func TestMutateFallbackBindingPreventsCrossRouteAndPrincipalReplay(t *testing.T) {
	for _, tc := range []struct {
		name    string
		durable bool
	}{
		{name: "transactional"},
		{name: "durable-fallback", durable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil, orchestrator.NewMemoryIdempotency(), nil)
			key := "shared-sensitive-key-" + tc.name
			calls := 0
			invoke := func(subject, method, path string, fn func(context.Context, string) (int, any, error)) *httptest.ResponseRecorder {
				t.Helper()
				recorder := httptest.NewRecorder()
				req := mutationBindingRequest(subject, method, path)
				if tc.durable {
					a.mutateDurable(recorder, req, key, fn)
				} else {
					a.mutate(recorder, req, key, fn)
				}
				return recorder
			}
			original := func(context.Context, string) (int, any, error) {
				calls++
				return http.StatusCreated, map[string]string{"credential": mutationBindingSecretSentinel}, nil
			}

			const escapedRoute = "/test/mutations/secret%2Fexport"
			first := invoke("issuer-a", http.MethodPost, escapedRoute, original)
			if first.Code != http.StatusCreated || !strings.Contains(first.Body.String(), mutationBindingSecretSentinel) {
				t.Fatalf("first response status=%d body=%s", first.Code, first.Body.String())
			}
			replayRan := false
			replay := invoke("issuer-a", http.MethodPost, escapedRoute, func(context.Context, string) (int, any, error) {
				replayRan = true
				return http.StatusCreated, map[string]string{"credential": "wrong"}, nil
			})
			if replay.Code != first.Code || replay.Body.String() != first.Body.String() || replayRan || calls != 1 {
				t.Fatalf("exact replay status=%d body=%s ran=%v calls=%d; first=%s", replay.Code, replay.Body.String(), replayRan, calls, first.Body.String())
			}

			for label, conflict := range map[string]*httptest.ResponseRecorder{
				"route": invoke("issuer-a", http.MethodPost, "/test/mutations/secret/export", func(context.Context, string) (int, any, error) {
					t.Fatal("cross-route collision reached callback")
					return 0, nil, nil
				}),
				"principal": invoke("issuer-b", http.MethodPost, escapedRoute, func(context.Context, string) (int, any, error) {
					t.Fatal("cross-principal collision reached callback")
					return 0, nil, nil
				}),
				"method": invoke("issuer-a", http.MethodPut, escapedRoute, func(context.Context, string) (int, any, error) {
					t.Fatal("cross-method collision reached callback")
					return 0, nil, nil
				}),
			} {
				if conflict.Code != http.StatusConflict {
					t.Fatalf("%s collision status=%d body=%s, want 409", label, conflict.Code, conflict.Body.String())
				}
				if strings.Contains(conflict.Body.String(), mutationBindingSecretSentinel) {
					t.Fatalf("%s conflict disclosed cached credential: %s", label, conflict.Body.String())
				}
			}
		})
	}
}

func TestMutateFallbackBindingRequiresAuthenticatedPrincipal(t *testing.T) {
	a := New(nil, orchestrator.NewMemoryIdempotency(), nil)
	req := httptest.NewRequest(http.MethodPost, "/test/mutations/direct", nil)
	req.Header.Set("X-Tenant-ID", "11111111-1111-1111-1111-111111111111")
	recorder := httptest.NewRecorder()
	called := false
	a.mutate(recorder, req, "direct-unauthenticated", func(context.Context, string) (int, any, error) {
		called = true
		return http.StatusCreated, nil, nil
	})
	if recorder.Code != http.StatusUnauthorized || called {
		t.Fatalf("direct unauthenticated mutation status=%d called=%v body=%s, want credential-free 401", recorder.Code, called, recorder.Body.String())
	}
}

func TestMutateFallbackBindingRejectsLegacyUnboundCredentialCache(t *testing.T) {
	const key = "legacy-unbound-sensitive-cache"
	idem := orchestrator.NewMemoryIdempotency()
	if _, err := idem.Do(context.Background(), "11111111-1111-1111-1111-111111111111", key, func(context.Context) ([]byte, error) {
		return []byte(`{"s":201,"b":{"credential":"` + mutationBindingSecretSentinel + `"}}`), nil
	}); err != nil {
		t.Fatal(err)
	}
	a := New(nil, idem, nil)
	recorder := httptest.NewRecorder()
	called := false
	a.mutate(recorder, mutationBindingRequest("issuer-b", http.MethodPost, "/test/mutations/legacy-collision"), key, func(context.Context, string) (int, any, error) {
		called = true
		return http.StatusCreated, nil, nil
	})
	if recorder.Code != http.StatusConflict || called {
		t.Fatalf("legacy cache collision status=%d called=%v body=%s, want 409 before callback", recorder.Code, called, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), mutationBindingSecretSentinel) {
		t.Fatalf("legacy cache conflict disclosed cached credential: %s", recorder.Body.String())
	}
}

func TestMutateFallbackBindingMemorySingleFlight(t *testing.T) {
	a := New(nil, orchestrator.NewMemoryIdempotency(), nil)
	const (
		key  = "memory-bound-concurrent"
		path = "/test/mutations/concurrent"
	)
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		recorder := httptest.NewRecorder()
		a.mutate(recorder, mutationBindingRequest("issuer-a", http.MethodPost, path), key, func(context.Context, string) (int, any, error) {
			calls.Add(1)
			close(entered)
			<-release
			return http.StatusCreated, map[string]string{"credential": mutationBindingSecretSentinel}, nil
		})
		firstDone <- recorder
	}()
	<-entered

	secondStarted := make(chan struct{})
	secondCallback := make(chan struct{}, 1)
	secondDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		close(secondStarted)
		recorder := httptest.NewRecorder()
		a.mutate(recorder, mutationBindingRequest("issuer-a", http.MethodPost, path), key, func(context.Context, string) (int, any, error) {
			calls.Add(1)
			secondCallback <- struct{}{}
			return http.StatusCreated, map[string]string{"credential": "wrong-second-effect"}, nil
		})
		secondDone <- recorder
	}()
	<-secondStarted
	secondRanWhileFirstActive := false
	select {
	case <-secondCallback:
		secondRanWhileFirstActive = true
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	first, second := <-firstDone, <-secondDone
	if secondRanWhileFirstActive || calls.Load() != 1 {
		t.Fatalf("concurrent callbacks ran=%d second-active=%v, want one callback", calls.Load(), secondRanWhileFirstActive)
	}
	if first.Code != http.StatusCreated || second.Code != http.StatusCreated || first.Body.String() != second.Body.String() {
		t.Fatalf("single-flight responses first=%d/%s second=%d/%s", first.Code, first.Body.String(), second.Code, second.Body.String())
	}
}

func TestMemoryBoundDifferentBindingWaitsWithoutDeadlock(t *testing.T) {
	idem := orchestrator.NewMemoryIdempotency()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	entered := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		_, err := idem.DoBound(ctx, "tenant-a", "shared", "binding-a", func(context.Context) ([]byte, error) {
			close(entered)
			<-release
			return []byte("binding-a-result"), nil
		})
		firstDone <- err
	}()
	<-entered

	secondStarted := make(chan struct{})
	secondDone := make(chan error, 1)
	secondCalled := atomic.Bool{}
	go func() {
		close(secondStarted)
		_, err := idem.DoBound(ctx, "tenant-a", "shared", "binding-b", func(context.Context) ([]byte, error) {
			secondCalled.Store(true)
			return []byte("must-not-run"), nil
		})
		secondDone <- err
	}()
	<-secondStarted
	select {
	case err := <-secondDone:
		close(release)
		t.Fatalf("different binding returned before transactional owner committed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("first binding: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("first binding deadlocked")
	}
	select {
	case err := <-secondDone:
		if !errors.Is(err, orchestrator.ErrIdempotencyConflict) || secondCalled.Load() {
			t.Fatalf("different binding err=%v callback=%v, want conflict without callback", err, secondCalled.Load())
		}
	case <-ctx.Done():
		t.Fatal("different binding deadlocked after owner commit")
	}
}

func TestMemoryBoundCredentialCacheIsOpaqueToLegacyReaders(t *testing.T) {
	idem := orchestrator.NewMemoryIdempotency()
	const sentinel = "memory-bound-secret-must-not-open"
	tests := []struct {
		name string
		call func(context.Context, string, func(context.Context) ([]byte, error)) ([]byte, error)
	}{
		{name: "Do", call: func(ctx context.Context, key string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
			return idem.Do(ctx, "tenant-a", key, fn)
		}},
		{name: "DoDurableEffect", call: func(ctx context.Context, key string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
			return idem.DoDurableEffect(ctx, "tenant-a", key, fn)
		}},
		{name: "DoAtMostOnceEffect", call: func(ctx context.Context, key string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
			return idem.DoAtMostOnceEffect(ctx, "tenant-a", key, fn)
		}},
		{name: "Result", call: func(ctx context.Context, key string, _ func(context.Context) ([]byte, error)) ([]byte, error) {
			return idem.Result(ctx, "tenant-a", key)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key := "bound-to-legacy-" + test.name
			if _, err := idem.DoBound(context.Background(), "tenant-a", key, "authenticated-command", func(context.Context) ([]byte, error) {
				return []byte(sentinel), nil
			}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			called := atomic.Bool{}
			type outcome struct {
				result []byte
				err    error
			}
			done := make(chan outcome, 1)
			go func() {
				result, err := test.call(ctx, key, func(context.Context) ([]byte, error) {
					called.Store(true)
					return []byte("legacy-effect-must-not-run"), nil
				})
				done <- outcome{result: result, err: err}
			}()
			select {
			case got := <-done:
				if !errors.Is(got.err, orchestrator.ErrIdempotencyConflict) || called.Load() || len(got.result) != 0 {
					t.Fatalf("bound->legacy result=%q err=%v callback=%v, want empty conflict", got.result, got.err, called.Load())
				}
				if strings.Contains(string(got.result), sentinel) || strings.Contains(got.err.Error(), sentinel) {
					t.Fatalf("bound->legacy conflict disclosed credential result=%q err=%v", got.result, got.err)
				}
			case <-ctx.Done():
				t.Fatalf("bound->legacy %s deadlocked", test.name)
			}
		})
	}
}
