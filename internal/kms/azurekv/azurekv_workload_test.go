// SPDX-License-Identifier: BUSL-1.1

package azurekv_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"trstctl.com/trstctl/internal/cloudauth"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/kms/azurekv"
)

// A169 Done-when: workload identity replaces the static bearer token. With no
// bearer token configured, the managed-key backend exchanges the platform's
// projected federated token for an Entra access token and authenticates every
// Key Vault request with it — key generation, public-key reads and signatures
// all pass the conformance suite against the Key Vault double, which accepts
// only the token Entra issued — and the exchange happens once for all of them.
func TestWorkloadIdentityReplacesTheStaticBearer(t *testing.T) {
	const tenant, client = "11111111-2222-4333-8444-555555555555", "66666666-7777-4888-9999-000000000000"
	f := newFakeKV(t)
	var exchanges atomic.Int32
	entra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.URL.Path != "/"+tenant+"/oauth2/v2.0/token" || r.PostForm.Get("client_id") != client ||
			r.PostForm.Get("client_assertion") != "projected-service-account-jwt" {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		exchanges.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": testToken, "token_type": "Bearer", "expires_in": 3600})
	}))
	t.Cleanup(entra.Close)
	tokenFile := filepath.Join(t.TempDir(), "azure-identity-token")
	if err := os.WriteFile(tokenFile, []byte("projected-service-account-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := cloudauth.NewAzureFederatedTokenSource(cloudauth.AzureFederatedTokenSourceConfig{
		TenantID: tenant, ClientID: client, FederatedTokenFile: tokenFile, AuthorityHost: entra.URL,
		Scope: "https://vault.azure.net/.default", Doer: entra.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(source.Close)
	b, err := azurekv.NewSecure(testVault, azurekv.Credentials{TokenSource: source},
		azurekv.WithEndpoint(f.srv.URL), azurekv.WithHTTPClient(f.srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Destroy)
	if err := crypto.ConformBackend(b, []crypto.Algorithm{crypto.RSA2048, crypto.ECDSAP256}); err != nil {
		t.Fatalf("Key Vault backend on workload identity failed conformance: %v", err)
	}
	if got := exchanges.Load(); got != 1 {
		t.Fatalf("Entra exchanges = %d, want one cached token for every Key Vault request", got)
	}

	// A token Entra refuses never reaches Key Vault.
	if err := os.WriteFile(tokenFile, []byte("someone-elses-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	refused, err := cloudauth.NewAzureFederatedTokenSource(cloudauth.AzureFederatedTokenSourceConfig{
		TenantID: tenant, ClientID: client, FederatedTokenFile: tokenFile, AuthorityHost: entra.URL,
		Scope: "https://vault.azure.net/.default", Doer: entra.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(refused.Close)
	denied, err := azurekv.NewSecure(testVault, azurekv.Credentials{TokenSource: refused},
		azurekv.WithEndpoint(f.srv.URL), azurekv.WithHTTPClient(f.srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(denied.Destroy)
	if _, err := denied.GenerateKeyContext(context.Background(), crypto.ECDSAP256); err == nil {
		t.Fatal("a key was generated with a federated token Entra refused")
	}

	for name, creds := range map[string]azurekv.Credentials{
		"both":    {BearerToken: []byte(testToken), TokenSource: source},
		"neither": {},
	} {
		if _, err := azurekv.NewSecure(testVault, creds); err == nil {
			t.Errorf("%s credentials accepted", name)
		}
	}
}

// A169-L3: once the platform rotates the federated token file, the next Key
// Vault request exchanges the rotated token before it is sent — the access
// token minted from the old file is not ridden until it nears expiry: a
// rotated token Entra accepts is exchanged once more and Key Vault keeps
// answering; a rotated token Entra refuses stops the next request at the
// exchange, before Key Vault is called.
func TestRotatedFederatedTokenIsExchangedBeforeTheNextKeyVaultRequestA169L3(t *testing.T) {
	const tenant, client = "11111111-2222-4333-8444-555555555555", "66666666-7777-4888-9999-000000000000"
	f := newFakeKV(t)
	var exchanges atomic.Int32
	accepted := map[string]bool{"projected-jwt-1": true, "projected-jwt-2": true}
	entra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		exchanges.Add(1)
		if r.URL.Path != "/"+tenant+"/oauth2/v2.0/token" || !accepted[r.PostForm.Get("client_assertion")] {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": testToken, "token_type": "Bearer", "expires_in": 3600})
	}))
	t.Cleanup(entra.Close)
	tokenFile := filepath.Join(t.TempDir(), "azure-identity-token")
	write := func(value string) {
		t.Helper()
		if err := os.WriteFile(tokenFile, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("projected-jwt-1")
	source, err := cloudauth.NewAzureFederatedTokenSource(cloudauth.AzureFederatedTokenSourceConfig{
		TenantID: tenant, ClientID: client, FederatedTokenFile: tokenFile, AuthorityHost: entra.URL,
		Scope: "https://vault.azure.net/.default", Doer: entra.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(source.Close)
	b, err := azurekv.NewSecure(testVault, azurekv.Credentials{TokenSource: source},
		azurekv.WithEndpoint(f.srv.URL), azurekv.WithHTTPClient(f.srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Destroy)
	ctx := context.Background()
	if _, err := b.GenerateKeyContext(ctx, crypto.ECDSAP256); err != nil {
		t.Fatal(err)
	}
	if _, err := b.GenerateKeyContext(ctx, crypto.ECDSAP256); err != nil || exchanges.Load() != 1 {
		t.Fatalf("an unchanged token file: %v after %d exchanges", err, exchanges.Load())
	}
	write("projected-jwt-2")
	if _, err := b.GenerateKeyContext(ctx, crypto.ECDSAP256); err != nil || exchanges.Load() != 2 {
		t.Fatalf("after rotation: %v after %d exchanges; want the rotated token exchanged once", err, exchanges.Load())
	}
	write("projected-jwt-revoked")
	if _, err := b.GenerateKeyContext(ctx, crypto.ECDSAP256); err == nil || exchanges.Load() != 3 {
		t.Fatalf("a rotated token Entra refuses: %v after %d exchanges; want the request stopped at the exchange", err, exchanges.Load())
	}
}
