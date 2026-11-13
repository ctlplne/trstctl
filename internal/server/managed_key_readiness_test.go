// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/observ"
	"trstctl.com/trstctl/internal/signing"
)

// A169-L2 Done-when (served readiness): /readyz asks the signer how each
// workload-identity managed-key provider's token exchange went since the
// signer started. While Entra refuses one, readiness still answers 200 —
// CA signing and every other provider keep working — with
// managed_key_providers degraded, naming the provider and the closed reason;
// once the signer's retry succeeds the check reads ok. An unreachable signer
// is the signer check's to report, never this one's.
func TestServedReadinessNamesAManagedKeyProviderThatCannotAuthenticateA169L2(t *testing.T) {
	var refuse atomic.Int32
	refuse.Store(1 << 30)
	srv := signing.NewServer(signing.WithManagedKeyReadinessBackoff(10*time.Millisecond, 20*time.Millisecond),
		signing.WithManagedKeyReadinessProbes(map[string]signing.ManagedKeyReadinessProbe{
			"azure-key-vault": func(context.Context) error {
				if refuse.Load() > 0 {
					return &signing.ManagedKeyReadinessError{Code: signing.ReadinessExchangeRefused}
				}
				return nil
			},
		}))
	t.Cleanup(srv.Shutdown)
	client := serveReadinessSigner(t, srv)
	readiness := observ.NewReadiness(nil, managedKeyProvidersCheck(signing.StaticProvider{C: client}))
	ts := httptest.NewServer(readiness.Handler())
	t.Cleanup(ts.Close)
	ready := func() (int, string) {
		t.Helper()
		resp, err := ts.Client().Get(ts.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		checks, _ := body["checks"].(map[string]any)
		if checks == nil {
			checks = body
		}
		verdict, _ := checks["managed_key_providers"].(string)
		return resp.StatusCode, verdict
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, verdict := ready()
		if strings.Contains(verdict, "token_exchange_refused") {
			if code != http.StatusOK || !strings.HasPrefix(verdict, "degraded") || !strings.Contains(verdict, "azure-key-vault (token_exchange_refused)") {
				t.Fatalf("while Entra refuses: %d %q", code, verdict)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("readiness never named the refused provider: %d %q", code, verdict)
		}
		time.Sleep(10 * time.Millisecond)
	}
	refuse.Store(0)
	deadline = time.Now().Add(5 * time.Second)
	for {
		code, verdict := ready()
		if verdict == "ok" && code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("readiness did not recover: %d %q", code, verdict)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// No signer client, or one that cannot be reached, is not this check's to fail.
	if err := managedKeyProvidersCheck(nil).Probe(context.Background()); err != nil {
		t.Fatalf("no signer = %v", err)
	}
}

func serveReadinessSigner(t *testing.T, srv *signing.Server) *signing.Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "a169l2")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- signing.ServeServerWithOptions(ctx, socket, srv, signing.ServeOptions{AllowInsecureDevNonLinux: runtime.GOOS != "linux"})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("signer server did not stop")
		}
	})
	client, err := signing.DialReady(ctx, socket, 10*time.Second)
	if err != nil {
		t.Fatalf("dial the signer: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}
