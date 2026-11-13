// SPDX-License-Identifier: BUSL-1.1

package cloudauth

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A169-L3: a cached access token stays in use while the projected platform
// token is unchanged, and the request after the platform rotates the file
// exchanges the new token at once — for the Azure federated credential and
// the GCP workload identity alike — instead of riding the old one until it
// nears expiry. A file that disappears is not a rotation: the cached token
// keeps serving.
func TestRotatedPlatformTokenIsExchangedAtTheNextRequestA169L3(t *testing.T) {
	tokenOf := func(t *testing.T, source interface {
		Token(context.Context) ([]byte, func(), error)
	}) string {
		t.Helper()
		token, wipe, err := source.Token(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer wipe()
		return string(token)
	}
	write := func(t *testing.T, path, value string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	entra := newEntraStandIn(t, a169Tenant, 3600)
	azureFile := filepath.Join(t.TempDir(), "azure-identity-token")
	write(t, azureFile, "projected-jwt-1\n")
	azure, err := NewAzureFederatedTokenSource(AzureFederatedTokenSourceConfig{TenantID: a169Tenant, ClientID: a169Client,
		FederatedTokenFile: azureFile, AuthorityHost: entra.srv.URL, Scope: "https://vault.azure.net/.default", Doer: entra.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(azure.Close)
	if got := tokenOf(t, azure); got != "kv-token-for-projected-jwt-1" || entra.count() != 1 {
		t.Fatalf("first token = %q after %d exchanges", got, entra.count())
	}
	if got := tokenOf(t, azure); got != "kv-token-for-projected-jwt-1" || entra.count() != 1 {
		t.Fatalf("an unchanged file re-exchanged: %q after %d exchanges", got, entra.count())
	}
	write(t, azureFile, "projected-jwt-2\n")
	if got := tokenOf(t, azure); got != "kv-token-for-projected-jwt-2" || entra.count() != 2 {
		t.Fatalf("after rotation = %q after %d exchanges; want the rotated token exchanged at once", got, entra.count())
	}
	if err := os.Remove(azureFile); err != nil {
		t.Fatal(err)
	}
	if got := tokenOf(t, azure); got != "kv-token-for-projected-jwt-2" || entra.count() != 2 {
		t.Fatalf("a removed file dropped the cached token: %q after %d exchanges", got, entra.count())
	}

	sts := newGCPSTSStandIn(t, 3600)
	gcpFile := filepath.Join(t.TempDir(), "gcp-subject-token")
	write(t, gcpFile, "oidc-1")
	gcp, err := NewGCPWorkloadIdentityTokenSource(GCPWorkloadIdentityTokenSourceConfig{
		Audience: a169l1Audience, SubjectTokenFile: gcpFile, STSEndpoint: sts.srv.URL + "/v1/token", Doer: sts.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gcp.Close)
	if got := tokenOf(t, gcp); got != "federated-for-oidc-1" || sts.count() != 1 {
		t.Fatalf("first GCP token = %q after %d exchanges", got, sts.count())
	}
	write(t, gcpFile, "oidc-2")
	if got := tokenOf(t, gcp); got != "federated-for-oidc-2" || sts.count() != 2 {
		t.Fatalf("GCP after rotation = %q after %d exchanges", got, sts.count())
	}
}
