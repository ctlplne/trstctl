// SPDX-License-Identifier: LicenseRef-trstctl-EE

package signerwiring

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// A169-L2: a signer whose Azure managed-key provider authenticates with a
// workload identity exchanges the federated token as it starts and reports
// the outcome in Health: refused while Entra refuses (retrying until it
// accepts, then ready), unreadable when the federated token file is missing,
// unreachable when the token endpoint cannot be reached — closed codes only.
func TestWorkloadIdentityProviderReportsItsStartupExchangeA169L2(t *testing.T) {
	var exchanges, refuse atomic.Int32
	refuse.Store(2)
	entra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		if refuse.Add(-1) >= 0 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"AADSTS700016: words the signer must not repeat"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "kv-token", "token_type": "Bearer", "expires_in": 3600})
	}))
	t.Cleanup(entra.Close)
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "azure-identity-token")
	if err := os.WriteFile(tokenFile, []byte("projected-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	build := func(authority, federated string) *signing.Server {
		t.Helper()
		path := filepath.Join(t.TempDir(), "provider.json")
		body := `{"enabled":true,"provider":"azure-key-vault","azure":{"vault_url":"` + entra.URL + `","allow_insecure_loopback":true,` +
			`"workload_identity":{"tenant_id":"11111111-2222-4333-8444-555555555555","client_id":"66666666-7777-4888-9999-000000000000",` +
			`"federated_token_file":"` + federated + `","authority_host":"` + authority + `","scope":"https://vault.azure.net/.default"}}}`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		option, err := ProviderOption(path, t.TempDir())
		if err != nil {
			t.Fatalf("provider option: %v", err)
		}
		server := signing.NewServer(option, signing.WithManagedKeyReadinessBackoff(10*time.Millisecond, 40*time.Millisecond))
		t.Cleanup(server.Shutdown)
		return server
	}
	readiness := func(server *signing.Server) *signerpb.ManagedKeyProviderReadiness {
		t.Helper()
		resp, err := server.Health(context.Background(), &signerpb.HealthRequest{})
		if err != nil || len(resp.GetManagedKeyProviders()) != 1 {
			t.Fatalf("health = %v %v", resp, err)
		}
		return resp.GetManagedKeyProviders()[0]
	}
	wait := func(server *signing.Server, done func(*signerpb.ManagedKeyProviderReadiness) bool) *signerpb.ManagedKeyProviderReadiness {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			got := readiness(server)
			if done(got) {
				return got
			}
			if time.Now().After(deadline) {
				t.Fatalf("readiness stayed %+v", got)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	server := build(entra.URL, tokenFile)
	refused := wait(server, func(p *signerpb.ManagedKeyProviderReadiness) bool {
		return p.GetReason() == signing.ReadinessExchangeRefused
	})
	if refused.GetProvider() != "azure-key-vault" || refused.GetReady() {
		t.Fatalf("while Entra refuses = %+v", refused)
	}
	ready := wait(server, func(p *signerpb.ManagedKeyProviderReadiness) bool { return p.GetReady() })
	if ready.GetReason() != "" || exchanges.Load() != 3 {
		t.Fatalf("after Entra accepts = %+v after %d exchanges; want ready on the third", ready, exchanges.Load())
	}

	missing := build(entra.URL, filepath.Join(dir, "missing"))
	if got := wait(missing, func(p *signerpb.ManagedKeyProviderReadiness) bool { return p.GetReason() != signing.ReadinessPending }); got.GetReason() != signing.ReadinessTokenUnreadable {
		t.Fatalf("a missing federated token file = %+v", got)
	}
	closed := httptest.NewServer(http.NotFoundHandler())
	unreachable := closed.URL
	closed.Close()
	down := build(unreachable, tokenFile)
	if got := wait(down, func(p *signerpb.ManagedKeyProviderReadiness) bool { return p.GetReason() != signing.ReadinessPending }); got.GetReason() != signing.ReadinessExchangeUnreachable {
		t.Fatalf("an unreachable token endpoint = %+v", got)
	}
}
